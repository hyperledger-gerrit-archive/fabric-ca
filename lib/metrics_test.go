/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

func TestAPICountMetric(t *testing.T) {
	gt := NewGomegaWithT(t)

	se := &serverEndpoint{
		Path: "/test",
	}

	router := mux.NewRouter()
	router.Handle(se.Path, se).Name(se.Path)

	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	fakeErrCounter := &metricsfakes.Counter{}
	fakeErrCounter.WithReturns(fakeErrCounter)
	fakeHist := &metricsfakes.Histogram{}
	fakeHist.WithReturns(fakeHist)
	server := &Server{
		CA: CA{
			Config: &CAConfig{
				CA: CAInfo{
					Name: "ca1",
				},
			},
		},
		Metrics: Metrics{
			APICounter:      fakeCounter,
			APIErrorCounter: fakeErrCounter,
			APIDuration:     fakeHist,
		},
		mux: router,
	}

	server.mux.Use(server.middleware)
	se.Server = server

	req, err := http.NewRequest("GET", se.Path, nil)
	gt.Expect(err).NotTo(HaveOccurred())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	gt.Expect(fakeCounter.AddCallCount()).To(Equal(1))
	gt.Expect(fakeCounter.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeCounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test"}))

	gt.Expect(fakeErrCounter.AddCallCount()).To(Equal(1))
	gt.Expect(fakeErrCounter.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeErrCounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test", "error_code", "405"}))

	gt.Expect(fakeHist.ObserveCallCount()).To(Equal(1))
	gt.Expect(fakeHist.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeHist.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test"}))
}

func TestMetricsE2E(t *testing.T) {
	gt := NewGomegaWithT(t)
	var err error

	server := TestGetRootServer(t)

	// Statsd
	datagramReader := NewDatagramReader(t)
	go datagramReader.Start()

	server.Config.Metrics = MetricsConfig{
		Provider: "statsd",
		Statsd: &Statsd{
			Network:       "udp",
			Address:       datagramReader.Address(),
			Prefix:        "server",
			WriteInterval: time.Duration(time.Millisecond),
		},
	}

	server.CA.Config.CA.Name = "ca"
	err = server.Start()
	gt.Expect(err).NotTo(HaveOccurred())
	defer server.Stop()
	defer os.RemoveAll(rootDir)

	client := TestGetClient(rootPort, "metrics")
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "badpass",
		CAName: "ca",
	})
	gt.Expect(err).To(HaveOccurred())
	defer os.RemoveAll("metrics")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CAName: "ca",
	})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(datagramReader.String()).Should(ContainSubstring("server.api_request.error_count.ca.enroll.401:1.000000|c"))
	gt.Expect(datagramReader.String()).Should(ContainSubstring("server.api_request.count.ca.enroll:1.000000|c"))
	gt.Expect(datagramReader.String()).Should(ContainSubstring("server.api_request.duration.ca.enroll"))

	err = server.Stop()
	gt.Expect(err).NotTo(HaveOccurred())

	// Prometheus
	server.Config.Metrics.Provider = "prometheus"
	metricsURL := fmt.Sprintf("http://localhost:%d/metrics", rootPort)
	err = server.Start()
	gt.Expect(err).NotTo(HaveOccurred())

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "badpass",
		CAName: "ca",
	})
	gt.Expect(err).To(HaveOccurred())

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})

	// Prometheus client
	c := &http.Client{}
	resp, err := c.Get(metricsURL)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(resp.StatusCode).To(Equal(http.StatusOK))
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	gt.Expect(err).NotTo(HaveOccurred())
	body := string(bodyBytes)

	gt.Expect(body).To(ContainSubstring(`# HELP api_request_error_count Number of errors that have occurred for requests to an API`))
	gt.Expect(body).To(ContainSubstring(`# TYPE api_request_error_count counter`))
	gt.Expect(body).To(ContainSubstring(`api_request_error_count{api_name="enroll",ca_name="ca",error_code="401"} 1.0`))
	gt.Expect(body).To(ContainSubstring(`# HELP api_request_count Number of requests made to an API`))
	gt.Expect(body).To(ContainSubstring(`# TYPE api_request_count counter`))
	gt.Expect(body).To(ContainSubstring(`api_request_count{api_name="enroll",ca_name="ca"} 2.0`))
	gt.Expect(body).To(ContainSubstring(`# HELP api_request_duration Time taken in seconds for the request to an API to be completed`))
	gt.Expect(body).To(ContainSubstring(`# TYPE api_request_duration histogram`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.005"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.01"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.025"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.05"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.1"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.25"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="0.5"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="1.0"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="2.5"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="5.0"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="10.0"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_bucket{api_name="enroll",ca_name="ca",le="+Inf"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_sum{api_name="enroll",ca_name="ca"}`))
	gt.Expect(body).To(ContainSubstring(`api_request_duration_count{api_name="enroll",ca_name="ca"} 2.0`))

	err = server.Stop()
	gt.Expect(err).NotTo(HaveOccurred())
}

type DatagramReader struct {
	buffer    *gbytes.Buffer
	errCh     chan error
	sock      *net.UDPConn
	doneCh    chan struct{}
	closeOnce sync.Once
	err       error
}

func NewDatagramReader(t *testing.T) *DatagramReader {
	gt := NewGomegaWithT(t)

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	gt.Expect(err).NotTo(HaveOccurred())
	sock, err := net.ListenUDP("udp", udpAddr)
	gt.Expect(err).NotTo(HaveOccurred())
	err = sock.SetReadBuffer(1024 * 1024)
	gt.Expect(err).NotTo(HaveOccurred())

	return &DatagramReader{
		buffer: gbytes.NewBuffer(),
		sock:   sock,
		errCh:  make(chan error, 1),
		doneCh: make(chan struct{}),
	}
}

func (dr *DatagramReader) Buffer() *gbytes.Buffer {
	return dr.buffer
}

func (dr *DatagramReader) Address() string {
	return dr.sock.LocalAddr().String()
}

func (dr *DatagramReader) String() string {
	return string(dr.buffer.Contents())
}

func (dr *DatagramReader) Start() {
	buf := make([]byte, 1024*1024)
	for {
		select {
		case <-dr.doneCh:
			dr.errCh <- nil
			return

		default:
			n, _, err := dr.sock.ReadFrom(buf)
			if err != nil {
				dr.errCh <- err
				return
			}
			_, err = dr.buffer.Write(buf[0:n])
			if err != nil {
				dr.errCh <- err
				return
			}
		}
	}
}

func (dr *DatagramReader) Close() error {
	dr.closeOnce.Do(func() {
		close(dr.doneCh)
		err := dr.sock.Close()
		dr.err = <-dr.errCh
		if dr.err == nil && err != nil && err != io.EOF {
			dr.err = err
		}
	})
	return dr.err
}
