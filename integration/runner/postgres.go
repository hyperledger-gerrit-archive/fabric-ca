/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" //Driver passed to the sqlx package
	"github.com/pkg/errors"
	"github.com/tedsuo/ifrit"
)

//PostgresDBDefaultImage is used if none is specified
const PostgresDBDefaultImage = "postgres:9.6"

//PostgresDB defines an SQL Object of Type Postgres
type PostgresDB struct {
	Client        *docker.Client
	Image         string
	HostIP        string
	HostPort      int
	ContainerPort nat.Port
	Name          string
	StartTimeout  time.Duration

	ErrorStream  io.Writer
	OutputStream io.Writer

	containerID      string
	hostAddress      string
	containerAddress string
	address          string

	mutex   sync.Mutex
	stopped bool
	ctxt    context.Context
}

//Run is called by the ifrit runner to start a process
func (c *PostgresDB) Run(sigCh <-chan os.Signal, ready chan<- struct{}) error {
	c.ctxt = context.Background()

	if c.Image == "" {
		c.Image = PostgresDBDefaultImage
	}

	if c.Name == "" {
		c.Name = DefaultNamer()
	}

	if c.HostIP == "" {
		c.HostIP = "127.0.0.1"
	}

	if c.ContainerPort == nat.Port("") {
		c.ContainerPort = nat.Port("5432/tcp")
	}

	if c.StartTimeout == 0 {
		c.StartTimeout = DefaultStartTimeout
	}

	if c.Client == nil {
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		if err != nil {
			return err
		}
		client.NegotiateAPIVersion(c.ctxt)
		c.Client = client
	}

	ioReader, err := c.Client.ImagePull(c.ctxt, c.Image, types.ImagePullOptions{})
	if err != nil {
		return err
	}

	io.Copy(ioutil.Discard, ioReader)
	if err != nil {
		return err
	}

	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			"5432/tcp": []nat.PortBinding{
				{
					HostIP:   c.HostIP,
					HostPort: strconv.Itoa(c.HostPort),
				},
			},
		},
	}

	containerConfig := &container.Config{
		Image: c.Image,
	}

	containerResp, err := c.Client.ContainerCreate(c.ctxt, containerConfig, hostConfig, nil, c.Name)
	if err != nil {
		return err
	}
	c.containerID = containerResp.ID

	err = c.Client.ContainerStart(c.ctxt, c.containerID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}
	defer c.Stop()

	response, err := c.Client.ContainerInspect(c.ctxt, c.containerID)
	if err != nil {
		return err
	}

	if c.HostPort == 0 {
		port, err := strconv.Atoi(response.NetworkSettings.Ports[c.ContainerPort][0].HostPort)
		if err != nil {
			return err
		}
		c.HostPort = port
	}

	c.hostAddress = net.JoinHostPort(
		response.NetworkSettings.Ports[c.ContainerPort][0].HostIP,
		response.NetworkSettings.Ports[c.ContainerPort][0].HostPort,
	)
	c.containerAddress = net.JoinHostPort(
		response.NetworkSettings.IPAddress,
		c.ContainerPort.Port(),
	)

	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	go c.streamLogs(streamCtx)

	containerExit := c.wait()
	ctx, cancel := context.WithTimeout(context.Background(), c.StartTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "database in container %s did not start", c.containerID)
	case <-containerExit:
		return errors.New("container exited before ready")
	case <-c.ready(ctx, c.hostAddress):
		c.address = c.hostAddress
	case <-c.ready(ctx, c.containerAddress):
		c.address = c.containerAddress
	}

	cancel()
	close(ready)

	for {
		select {
		case err := <-containerExit:
			return err
		case <-sigCh:
			err := c.Stop()
			if err != nil {
				return err
			}
			return nil
		}
	}
}

func (c *PostgresDB) endpointReady(addr string) bool {

	dataSource := fmt.Sprintf("host=%s port=%d user=postgres dbname=postgres sslmode=disable", c.HostIP, c.HostPort)
	db, err := sqlx.Open("postgres", dataSource)
	if err != nil {
		return false
	}

	_, err = db.Conn(context.Background())
	if err != nil {
		return false
	}

	db.Close()
	return true
}

func (c *PostgresDB) ready(ctx context.Context, addr string) <-chan struct{} {
	readyCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if c.endpointReady(addr) {
				close(readyCh)
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	return readyCh
}

func (c *PostgresDB) wait() <-chan error {
	exitCh := make(chan error)
	go func() {
		exitCode, errCh := c.Client.ContainerWait(context.Background(), c.containerID, container.WaitConditionNotRunning)
		err := <-errCh
		if err == nil {
			err = fmt.Errorf("postgres: process exited with %d", (<-exitCode).StatusCode)
		}
		exitCh <- err
	}()

	return exitCh
}

func (c *PostgresDB) streamLogs(ctx context.Context) {
	if c.ErrorStream == nil && c.OutputStream == nil {
		return
	}

	logOptions := types.ContainerLogsOptions{
		Follow:     true,
		ShowStderr: c.ErrorStream != nil,
		ShowStdout: c.OutputStream != nil,
	}

	out, err := c.Client.ContainerLogs(ctx, c.containerID, logOptions)
	if err != nil {
		fmt.Fprintf(c.ErrorStream, "log stream ended with error: %s", out)
	} else {
		io.Copy(c.OutputStream, out)
	}
}

// Address returns the address successfully used by the readiness check.
func (c *PostgresDB) Address() string {
	return c.address
}

// HostAddress returns the host address where this PostgresDB instance is available.
func (c *PostgresDB) HostAddress() string {
	return c.hostAddress
}

// ContainerAddress returns the container address where this PostgresDB instance
// is available.
func (c *PostgresDB) ContainerAddress() string {
	return c.containerAddress
}

// ContainerID returns the container ID of this PostgresDB
func (c *PostgresDB) ContainerID() string {
	return c.containerID
}

// Start starts the PostgresDB container using an ifrit runner
func (c *PostgresDB) Start() error {
	p := ifrit.Invoke(c)

	select {
	case <-p.Ready():
		return nil
	case err := <-p.Wait():
		return err
	}
}

// Stop stops and removes the PostgresDB container
func (c *PostgresDB) Stop() error {
	c.mutex.Lock()
	if c.stopped {
		c.mutex.Unlock()
		return errors.Errorf("container %s already stopped", c.containerID)
	}
	c.stopped = true
	c.mutex.Unlock()

	resp, err := c.Client.ContainerInspect(c.ctxt, c.containerID)
	if err != nil {
		return err
	}

	if resp.State.Status == "running" {
		err = c.Client.ContainerKill(c.ctxt, c.containerID, "9")
		if err != nil {
			return err
		}
	}

	err = c.Client.ContainerRemove(c.ctxt, c.containerID, types.ContainerRemoveOptions{})
	if err != nil {
		return err
	}

	return nil
}
