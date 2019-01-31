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
	"syscall"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/tedsuo/ifrit"
)

var _ = Describe("PostgresDB Runner", func() {
	var (
		errBuffer  *gbytes.Buffer
		outBuffer  *gbytes.Buffer
		postgresDB *PostgresDB

		process ifrit.Process
	)

	BeforeEach(func() {
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		Expect(err).NotTo(HaveOccurred())
		client.NegotiateAPIVersion(context.Background())

		errBuffer = gbytes.NewBuffer()
		outBuffer = gbytes.NewBuffer()
		postgresDB = &PostgresDB{
			Name:         DefaultNamer(),
			StartTimeout: time.Second * 60,
			ErrorStream:  io.MultiWriter(errBuffer, GinkgoWriter),
			OutputStream: io.MultiWriter(outBuffer, GinkgoWriter),
			Client:       client,
		}

		process = nil
	})

	AfterEach(func() {
		if process != nil {
			process.Signal(syscall.SIGTERM)
		}
		postgresDB.Stop()
	})

	It("starts and stops a docker container with the specified image", func() {
		containerName := DefaultNamer()
		postgresDB.StartTimeout = 0
		postgresDB.Name = containerName

		By("starting postgres DB")
		process = ifrit.Invoke(postgresDB)
		Eventually(process.Ready(), time.Minute).Should(BeClosed())
		Consistently(process.Wait()).ShouldNot(Receive())

		By("inspecting the container by name")
		container, err := postgresDB.Client.ContainerInspect(context.Background(), postgresDB.containerID)
		Expect(err).NotTo(HaveOccurred())
		Expect(container.Name).To(Equal("/" + containerName))
		Expect(container.State.Status).To(Equal("running"))
		Expect(container.Config).NotTo(BeNil())
		Expect(container.Config.Image).To(Equal("postgres:9.6"))
		Expect(container.ID).To(Equal(postgresDB.ContainerID()))
		portBindings := container.NetworkSettings.Ports[nat.Port("5432/tcp")]
		Expect(portBindings).To(HaveLen(1))
		Expect(postgresDB.HostAddress()).To(Equal(net.JoinHostPort(portBindings[0].HostIP, portBindings[0].HostPort)))
		Expect(postgresDB.ContainerAddress()).To(Equal(net.JoinHostPort(container.NetworkSettings.IPAddress, "5432")))

		By("accessing the postgres DB server")
		address := postgresDB.HostAddress()
		Expect(address).NotTo(BeEmpty())
		conn, err := net.Dial("tcp", address)
		if err == nil {
			conn.Close()
		}
		Expect(err).NotTo(HaveOccurred())

		By("terminating the container")
		process.Signal(syscall.SIGTERM)
		Eventually(process.Wait(), time.Second*30).Should(Receive())
		process = nil

		Eventually(ContainerExists(context.Background(), postgresDB.Client, containerName), time.Second*30).Should(BeFalse())
	})

	It("can be started and stopped with ifrit", func() {
		process = ifrit.Invoke(postgresDB)
		Eventually(process.Ready(), time.Second*30).Should(BeClosed())

		process.Signal(syscall.SIGTERM)
		Eventually(process.Wait(), time.Second*30).Should(Receive())
		process = nil
	})

	It("can be started and stopped without ifrit", func() {
		err := postgresDB.Start()
		Expect(err).NotTo(HaveOccurred())

		err = postgresDB.Stop()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when a host port is provided", func() {
		BeforeEach(func() {
			postgresDB.HostPort = 33333
		})

		It("exposes postgres on the specified port", func() {
			err := postgresDB.Start()
			Expect(err).NotTo(HaveOccurred())
			Expect(postgresDB.HostPort).To(Equal(33333))

			err = postgresDB.Stop()
			Expect(err).NotTo(HaveOccurred())
			postgresDB.Stop()
		})
	})

	Context("when creating the container fails", func() {
		It("returns an error", func() {
			err := postgresDB.Start()
			Expect(err).ToNot(HaveOccurred())

			db2 := &PostgresDB{Name: postgresDB.Name}
			err = db2.Start()
			Expect(err).To(HaveOccurred())

			postgresDB.Stop()
			db2.Stop()
		})
	})

	Context("when starting the container fails", func() {
		It("returns an error", func() {
			err := postgresDB.Start()
			Expect(err).ToNot(HaveOccurred())

			db2 := &PostgresDB{HostPort: postgresDB.HostPort}
			err = db2.Start()
			Expect(err).To(HaveOccurred())

			postgresDB.Stop()
			db2.Stop()
		})
	})

	Context("when the log streams are both nil", func() {
		BeforeEach(func() {
			postgresDB.ErrorStream = nil
			postgresDB.OutputStream = nil
		})

		It("doesn't request logs from docker", func() {
			err := postgresDB.Start()
			Expect(err).NotTo(HaveOccurred())

			err = postgresDB.Stop()
			Expect(err).NotTo(HaveOccurred())
			postgresDB.Stop()
		})
	})

	Context("when the container has already been stopped", func() {
		It("returns an error", func() {
			err := postgresDB.Start()
			Expect(err).NotTo(HaveOccurred())

			err = postgresDB.Stop()
			Expect(err).NotTo(HaveOccurred())

			err = postgresDB.Stop()
			id := fmt.Sprintf("container %s already stopped", postgresDB.ContainerID())
			Expect(err).To(MatchError(id))

			postgresDB.Stop()
		})
	})

	Context("when stopping the container fails", func() {
		It("returns an error", func() {
			err := postgresDB.Start()
			Expect(err).NotTo(HaveOccurred())

			err = postgresDB.Stop()
			Expect(err).ToNot(HaveOccurred())

			postgresDB.containerID = DefaultNamer()

			err = postgresDB.Stop()
			errMsg := fmt.Sprintf("container %s already stopped", postgresDB.containerID)
			Expect(err).To(MatchError(ContainSubstring(errMsg)))
		})
	})

	Context("when startup times out", func() {
		BeforeEach(func() {
			postgresDB.StartTimeout = time.Millisecond * 500
		})

		It("returns an error", func() {
			err := postgresDB.Start()
			id := fmt.Sprintf("database in container %s did not start", postgresDB.ContainerID())
			Expect(err).To(MatchError(ContainSubstring(id)))
			postgresDB.Stop()
		})
	})

	Context("when a name isn't provided", func() {
		It("generates a unique name", func() {
			err := postgresDB.Start()
			Expect(err).ToNot(HaveOccurred())
			Expect(postgresDB.Name).ShouldNot(BeEmpty())
			Expect(postgresDB.Name).To(HaveLen(26))

			db2 := &PostgresDB{}
			err = db2.Start()
			Expect(err).ToNot(HaveOccurred())
			Expect(db2.Name).ShouldNot(BeEmpty())
			Expect(db2.Name).To(HaveLen(26))

			Expect(postgresDB.Name).NotTo(Equal(db2.Name))

			postgresDB.Stop()
			db2.Stop()
		})
	})
})
