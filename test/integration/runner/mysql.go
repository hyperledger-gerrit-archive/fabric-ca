/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"database/sql"
	dockerTypes "github.com/docker/docker/api/types"
	dcontainer "github.com/docker/docker/api/types/container"
	dnetwork "github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	//"github.com/docker/docker/client"
	docker "github.com/docker/docker/client"
	//docker "github.com/fsouza/go-dockerclient"
	"github.com/pkg/errors"
	"github.com/tedsuo/ifrit"
)

const MySQLDBDefaultImage = "mysql:latest"

type TLSClient struct {
	CertFile string
	KeyFile  string
}

type TLSInfo struct {
	Enabled    bool
	CACertFile string
	Client     *TLSClient
}

// MySQL manages the execution of an instance of a dockerized MySQL
// for tests.
type MySQL struct {
	Client        *docker.Client
	Image         string
	HostIP        string
	HostPort      int
	ContainerPort nat.Port
	Name          string
	StartTimeout  time.Duration

	User       string
	Passwd     string
	DBName     string
	TLSInfo    *TLSInfo
	Connection *sql.DB
	DataSource string
	ExecStmnt  string

	ErrorStream  io.Writer
	OutputStream io.Writer

	containerID      string
	hostAddress      string
	containerAddress string
	address          string

	mutex   sync.Mutex
	stopped bool
}

// Run runs a MySQL container. It implements the ifrit.Runner interface
func (m *MySQL) Run(sigCh <-chan os.Signal, ready chan<- struct{}) error {
	var (
		err    error
		client *docker.Client
	)

	if m.Image == "" {
		m.Image = MySQLDBDefaultImage
	}

	if m.Name == "" {
		m.Name = DefaultNamer()
	}

	if m.HostIP == "" {
		m.HostIP = "127.0.0.1"
	}

	if m.Passwd == "" {
		m.Passwd = "mysql"
	}

	if m.ContainerPort == nat.Port("") {
		m.ContainerPort = nat.Port("33060/tcp")
	}

	if m.StartTimeout == 0 {
		m.StartTimeout = DefaultStartTimeout
	}

	if m.Client == nil {
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		if m.TLSInfo.Enabled == true {
			err = docker.WithTLSClientConfig(m.TLSInfo.CACertFile,
				m.TLSInfo.Client.CertFile,
				m.TLSInfo.Client.KeyFile)
		}
		//		} else {
		//			client, err = docker.NewClientWithOpts(docker.FromEnv)
		//		}
		if err != nil {
			return err
		}
		m.Client = client
	}

	// Pull Image if it is not present
	reader, err := m.Client.ImagePull(context.Background(), MySQLDBDefaultImage, dockerTypes.ImagePullOptions{
		All:          true,
		RegistryAuth: "",
		Platform:     "",
	})
	//	err = m.Client.PullImage(
	//		docker.PullImageOptions{
	//			Repository: MySQLDBDefaultImage,
	//		},
	//		docker.AuthConfiguration{})
	if err != nil {
		return err
	}

	//	hostConfig := &docker.HostConfig{
	//		AutoRemove: true,
	//		PortBindings: map[docker.Port][]docker.PortBinding{
	//			m.ContainerPort: {{
	//				HostIP:   m.HostIP,
	//				HostPort: strconv.Itoa(m.HostPort),
	//			}},
	//		},
	//	}
	config := &dcontainer.Config{
		Hostname:   "127.0.0.1",
		Domainname: m.Name,
		ExposedPorts: nat.PortMap{
			m.ContainerPort: []nat.PortBinding{
				{
					HostIP:   m.HostIP,
					HostPort: strconv.Itoa(m.HostPort),
				},
			},
		},
		//		ExposedPorts: map[nat.Port][]nat.PortBinding{
		//			m.HostPort},
		Image: MySQLDBDefaultImage,
	}

	hostConfig := &dcontainer.HostConfig{
		PortBindings: map[nat.Port][]nat.PortBinding{
			m.HostPort},
		AutoRemove: true,
	}

	networkingConfig := &dnetwork.NetworkingConfig{}

	container, err := m.Client.ContainerCreate(context.Background(),
		config,
		hostConfig,
		networkingConfig,
		m.Name)

	//	container, err := m.Client.CreateContainer(
	//		docker.CreateContainerOptions{
	//			Name: m.Name,
	//			Config: &docker.Config{
	//				Image: m.Image,
	//				Env: []string{
	//					fmt.Sprintf("MYSQL_ROOT_PASSWORD=%s", m.Passwd),
	//				},
	//			},
	//			HostConfig: hostConfig,
	//		},
	//	)
	if err != nil {
		return err
	}
	m.containerID = container.ID

	err = m.Client.ContainerStart(context.Background(), m.containerID, dockerTypes.ContainerStartOptions{})
	//	err = m.Client.StartContainer(container.ID, nil)
	if err != nil {
		return err
	}
	defer m.Stop()

	//	container, err = m.Client.InspectContainer(container.ID)
	containInsp, err := m.Client.ContainerInspect(context.Background(), container.ID)
	if err != nil {
		return err
	}
	m.hostAddress = net.JoinHostPort(
		//		container.NetworkSettings.Ports[m.ContainerPort][0].HostIP,
		//		container.NetworkSettings.Ports[m.ContainerPort][0].HostPort,
		containInsp.NetworkSettings.NetworkSettingsBase.Ports[m.ContainerPort][0].HostIP,
		containInsp.NetworkSettings.NetworkSettingsBase.Ports[m.ContainerPort][0].HostPort,
	)
	m.containerAddress = net.JoinHostPort(
		//container.NetworkSettings.IPAddress,
		containInsp.NetworkSettings.DefaultNetworkSettings.IPAddress,
		m.ContainerPort.Port(),
	)

	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	go m.streamLogs(streamCtx)

	containerExit := m.wait()
	ctx, cancel := context.WithTimeout(context.Background(), m.StartTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "database in container %s did not start", m.containerID)
	case <-containerExit:
		return errors.New("container exited before ready")
	case <-m.ready(ctx, m.hostAddress):
		m.address = m.hostAddress
	case <-m.ready(ctx, m.containerAddress):
		m.address = m.containerAddress
	}

	cancel()
	close(ready)

	for {
		select {
		case err := <-containerExit:
			return err
		case <-sigCh:
			if err := m.Stop(); err != nil {
				return err
			}
		}
	}
}

func (m *MySQL) ready(ctx context.Context, addr string) <-chan struct{} {
	readyCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				conn.Close()
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

func (m *MySQL) wait() <-chan error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, errCh := m.Client.ContainerWait(ctx, m.containerID, "")
	if err := <-errCh; err != nil {
		err = fmt.Errorf("mysql: process exited with %s", err)
	}
	return errCh

	//	exitCh := make(chan error)
	//		exitCode, err := m.Client.ContainerWait(context.Background(), m.containerID, condition container.WaitCondition)(m.containerID)
	//	go func() {
	//		exitCode, err := m.Client.WaitContainer(m.containerID)
	//		if err == nil {
	//			err = fmt.Errorf("mysql: process exited with %d", exitCode)
	//		}
	//		exitCh <- err
	//	}()
	//
	//	return exitCh
}

func (m *MySQL) streamLogs(ctx context.Context) {
	if m.ErrorStream == nil && m.OutputStream == nil {
		return
	}
	//	logOptions := docker.LogsOptions{
	//		Context:      ctx,
	//		Container:    m.containerID,
	//		Follow:       true,
	//		ErrorStream:  m.ErrorStream,
	//		OutputStream: m.OutputStream,
	//		Stderr:       m.ErrorStream != nil,
	//		Stdout:       m.OutputStream != nil,
	//	}
	//	err := m.Client.Logs(logOptions)

	// Output Stream
	logOptions := dockerTypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
		Timestamps: true,
		Follow:     true,
		Details:    true,
	}
	reader, err := m.Client.ContainerLogs(ctx, m.containerID, logOptions)
	if err != nil {
		fmt.Fprintf(m.ErrorStream, "log stream ended with error: %s", err)
	}
	_, err = io.Copy(m.OutputStream, reader)
	if err != nil && err != io.EOF {
		fmt.Fprintf(m.ErrorStream, "unable to copy log to stream with error: %s", err)
	}

	// Error Stream
	logOptions.ShowStdout = false
	logOptions.ShowStderr = true
	reader, err = m.Client.ContainerLogs(ctx, m.containerID, logOptions)
	if err != nil {
		fmt.Fprintf(m.ErrorStream, "log stream ended with error: %s", err)
	}
	_, err = io.Copy(m.ErrorStream, reader)
	if err != nil && err != io.EOF {
		fmt.Fprintf(m.ErrorStream, "unable to copy log to stream with error: %s", err)
	}
}

// HostAddress returns the host address where this MySQL instance is available.
func (m *MySQL) HostAddress() string {
	return m.HostIP
}

func (m *MySQL) ContainerID() string {
	return m.containerID
}

// Start starts the MySQL container using an ifrit runner
func (m *MySQL) Start() error {
	p := ifrit.Invoke(m)

	select {
	case <-p.Ready():
		return nil
	case err := <-p.Wait():
		return err
	}
}

// Stop stops and removes the MySQL container
func (m *MySQL) Stop() error {
	var dur *time.Duration

	m.mutex.Lock()
	if m.stopped {
		m.mutex.Unlock()
		return errors.Errorf("container %s already stopped", m.ContainerID())
	}
	m.stopped = true
	m.mutex.Unlock()

	//return m.Client.StopContainer(m.ContainerID(), 0)
	return m.Client.ContainerStop(context.Background(), m.containerID, dur)
}
