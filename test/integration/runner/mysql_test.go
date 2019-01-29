/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner_test

import (
	"fmt"
	"io"
	"syscall"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric-ca/test/integration/runner"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/ghttp"
	"github.com/tedsuo/ifrit"
)

var _ = FDescribe("MySQL Runner", func() {
	var (
		dockerServer *ghttp.Server

		waitResponse string
		waitChan     chan struct{}

		errBuffer *gbytes.Buffer
		outBuffer *gbytes.Buffer
		mysqlDB   *runner.MySQL

		process ifrit.Process
	)

	BeforeEach(func() {
		waitChan = make(chan struct{}, 1)
		dockerServer = ghttp.NewServer()
		dockerServer.Writer = GinkgoWriter
		waitResponse = `{ StatusCode: 0 }`

		errBuffer = gbytes.NewBuffer()
		outBuffer = gbytes.NewBuffer()
		mysqlDB = &runner.MySQL{
			User:   "user",
			Passwd: "password",
			DBName: "testDB",
			TLSInfo: &runner.TLSInfo{
				Enabled: false,
			},
			StartTimeout: time.Second,
			ErrorStream:  io.MultiWriter(errBuffer, GinkgoWriter),
			OutputStream: io.MultiWriter(outBuffer, GinkgoWriter),
		}

		process = nil
	})

	AfterEach(func() {
		if process != nil {
			process.Signal(syscall.SIGTERM)
		}
		close(waitChan)
	})

	It("starts and stops mysql with the specified information", func() {
		containerName := runner.DefaultNamer()

		By("using a real docker daemon")
		client, err := docker.NewClientFromEnv()
		Expect(err).NotTo(HaveOccurred())
		mysqlDB.Client = nil
		mysqlDB.StartTimeout = 0
		mysqlDB.Name = containerName

		By("starting mysql DB")
		process = ifrit.Invoke(mysqlDB)
		Eventually(process.Ready(), runner.DefaultStartTimeout).Should(BeClosed())
		Consistently(process.Wait()).ShouldNot(Receive())
		Eventually(errBuffer, 30*time.Second).Should(gbytes.Say(`X Plugin ready for connections.`))

		By("inspecting the container by name")
		container, err := client.InspectContainer(containerName)
		Expect(err).NotTo(HaveOccurred())
		Expect(container.Name).To(Equal("/" + containerName))
		Expect(container.State.Status).To(Equal("running"))
		Expect(container.Config).NotTo(BeNil())
		Expect(container.Config.Image).To(Equal("mysql:latest"))
		Expect(container.ID).To(Equal(mysqlDB.ContainerID()))
		Expect(mysqlDB.HostAddress()).To(Equal("127.0.0.1"))

		By("getting the container logs")
		Eventually(outBuffer, 30*time.Second).Should(gbytes.Say(`MySQL init process done. Ready for start up.`))
		Eventually(errBuffer, 30*time.Second).Should(gbytes.Say(`X Plugin ready for connections.`))

		By("terminating the container")
		process.Signal(syscall.SIGTERM)
		Eventually(process.Wait(), time.Minute).Should(Receive())
		process = nil

		Eventually(ContainerExists(client, containerName)).Should(BeFalse())
	})

	It("can be started and stopped with ifrit", func() {
		process = ifrit.Invoke(mysqlDB)
		Eventually(process.Ready()).Should(BeClosed())

		process.Signal(syscall.SIGTERM)
		Eventually(process.Wait()).Should(Receive())
		process = nil
	})

	It("can be started and stopped without ifrit", func() {
		err := mysqlDB.Start()
		Expect(err).NotTo(HaveOccurred())

		err = mysqlDB.Stop()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when a host port is provided", func() {
		BeforeEach(func() {
			port, err := runner.RandomPort()
			Expect(err).NotTo(HaveOccurred())
			mysqlDB.HostPort = port
		})

		It("exposes mysql on the specified port", func() {
			err := mysqlDB.Start()
			Expect(err).NotTo(HaveOccurred())
			err = mysqlDB.Stop()
			Expect(err).NotTo(HaveOccurred())

		})
	})

	Context("when starting multiple servers fails", func() {
		BeforeEach(func() {
			err := mysqlDB.Start()
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns an error", func() {
			err := mysqlDB.Start()
			Expect(err).To(HaveOccurred())
			err = mysqlDB.Stop()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when the log streams are both nil", func() {
		BeforeEach(func() {
			mysqlDB.ErrorStream = nil
			mysqlDB.OutputStream = nil
		})

		It("doesn't request logs from docker", func() {
			err := mysqlDB.Start()
			Expect(err).NotTo(HaveOccurred())

			err = mysqlDB.Stop()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when the container has already been stopped", func() {
		BeforeEach(func() {
			mysqlDB.Name = "container-name"
		})
		It("returns an error", func() {
			err := mysqlDB.Start()
			Expect(err).NotTo(HaveOccurred())

			err = mysqlDB.Stop()
			Expect(err).NotTo(HaveOccurred())

			err = mysqlDB.Stop()
			Expect(err).To(MatchError(fmt.Sprintf("container %s already stopped", mysqlDB.ContainerID())))
		})
	})
})
