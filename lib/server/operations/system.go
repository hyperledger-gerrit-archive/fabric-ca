/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operations

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/fabric-lib-go/healthz"

	"github.com/cloudflare/cfssl/log"
	kitstatsd "github.com/go-kit/kit/metrics/statsd"
	"github.com/gorilla/mux"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/common/metrics/prometheus"
	"github.com/hyperledger/fabric/common/metrics/statsd"
	prom "github.com/prometheus/client_golang/prometheus"
)

// System is an operations server that is responsible for metrics and health checks
type System struct {
	metrics.Provider
	config        *Config
	healthHandler *healthz.HealthHandler
	statsd        *kitstatsd.Statsd
	sendTicker    *time.Ticker
	httpServer    *http.Server
	mux           *mux.Router
	addr          string
}

// Config contains configuration for the operations system
type Config struct {
	ListenAddress string
	Metrics       MetricsConfig
	TLS           TLS
}

// MetricsConfig contains the information on providers
type MetricsConfig struct {
	Provider string
	Statsd   *Statsd
}

// Statsd contains configuration of statsd
type Statsd struct {
	Network       string
	Address       string
	WriteInterval time.Duration
	Prefix        string
}

// NewSystem creates a System struct
func NewSystem(c *Config) *System {
	system := &System{
		config: c,
	}

	system.initializeServer()
	system.initializeHealthCheckHandler()
	system.initializeMetricsProvider()

	return system
}

// Start starts the operations system server
func (s *System) Start() error {
	err := s.startMetricsTickers()
	if err != nil {
		return err
	}

	listener, err := s.listen()
	if err != nil {
		return err
	}
	s.addr = listener.Addr().String()

	log.Infof("Operation Server Listening on %s", listener.Addr())
	go s.httpServer.Serve(listener)

	return nil
}

// Stop stop the operations system server
func (s *System) Stop() error {
	if s.sendTicker != nil {
		s.sendTicker.Stop()
		s.sendTicker = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

func (s *System) initializeServer() {
	s.mux = mux.NewRouter()
	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddress,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 2 * time.Minute,
	}
}

func (s *System) initializeMetricsProvider() {
	m := s.config.Metrics
	providerType := m.Provider
	switch providerType {
	case "statsd":
		prefix := m.Statsd.Prefix
		if prefix != "" && !strings.HasSuffix(prefix, ".") {
			prefix = prefix + "."
		}

		ks := kitstatsd.New(prefix, s)
		s.Provider = &statsd.Provider{Statsd: ks}
		s.statsd = ks

	case "prometheus":
		s.Provider = &prometheus.Provider{}
		s.mux.Handle("/metrics", prom.Handler())

	default:
		if providerType != "disabled" {
			log.Warningf("Unknown provider type: %s; metrics disabled", providerType)
		}

		s.Provider = &disabled.Provider{}
	}
}

func (s *System) initializeHealthCheckHandler() {
	s.healthHandler = healthz.NewHealthHandler()
	s.mux.Handle("/healthz", s.healthHandler)
}

func (s *System) startMetricsTickers() error {
	m := s.config.Metrics
	if s.statsd != nil {
		network := m.Statsd.Network
		address := m.Statsd.Address
		c, err := net.Dial(network, address)
		if err != nil {
			return err
		}
		c.Close()

		writeInterval := s.config.Metrics.Statsd.WriteInterval

		s.sendTicker = time.NewTicker(writeInterval)
		go s.statsd.SendLoop(s.sendTicker.C, network, address)
	}

	return nil
}

// Log is a function required to meet the interface required by statsd
func (s *System) Log(keyvals ...interface{}) error {
	log.Warning(keyvals...)
	return nil
}

//RegisterChecker registers the /healthz endpoint with the server
func (s *System) RegisterChecker(component string, checker healthz.HealthChecker) error {
	err := s.healthHandler.RegisterChecker(component, checker)
	if err != nil {
		return err
	}
	return nil
}

func (s *System) listen() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := s.config.TLS.Config()
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	return listener, nil
}

// Addr returns the address of the listener
func (s *System) Addr() string {
	return s.addr
}
