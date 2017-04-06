/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lib

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

const (
	defaultClientAuth = "noclientcert"
)

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server
	HomeDir string
	// BlockingStart if true makes the Start function blocking;
	// It is non-blocking by default.
	BlockingStart bool
	// The server's configuration
	Config *ServerConfig
	// The parent server URL, which is non-null if this is an intermediate server
	ParentServerURL string
	// The server mux
	mux *http.ServeMux
	// The current listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// Pointer to CA instance
	*CA
	// A map of CAs stored by CA name as key
	CAs map[string]*CA
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {
	// Initialize the config, setting defaults, etc
	err = s.initConfig()
	if err != nil {
		return err
	}

	// Successful initialization
	return nil
}

// Start the fabric-ca server
func (s *Server) Start() (err error) {
	log.Infof("Server Home Directory: %s", s.HomeDir)

	s.serveError = nil

	if s.listener != nil {
		return errors.New("server is already started")
	}

	// Initialize the server
	err = s.Init(false)
	if err != nil {
		return err
	}

	s.CAs = make(map[string]*CA)
	var ca *CA

	if len(s.Config.CAfiles) != 0 {
		log.Infof("CAs to be started: %s", s.Config.CAfiles)
		var caFiles []string

		caFiles, err = util.NormalizeFileList(util.NormalizeStringSlice(s.Config.CAfiles), s.HomeDir)
		if err != nil {
			return err
		}

		for _, caFile := range caFiles {

			ca, err = s.loadCA(caFile)
			if err != nil {
				return err
			}
			log.Infof("CA %s has been added to server ", ca.Config.CA.Name)
		}
	}

	ca, err = s.loadStandardCA()
	if err != nil {
		return err
	}
	s.CA = ca

	log.Infof("CA '%s' has been added to server ", ca.Config.CA.Name)

	// Register http handlers
	s.registerHandlers()

	// Start listening and serving
	return s.listenAndServe()

}

// Stop the server
// WARNING: This forcefully closes the listening socket and may cause
// requests in transit to fail, and so is only used for testing.
// A graceful shutdown will be supported with golang 1.8.
func (s *Server) Stop() error {
	if s.listener == nil {
		return errors.New("server is not currently started")
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

// RegisterBootstrapUser registers the bootstrap user with appropriate privileges
func (s *Server) RegisterBootstrapUser(user, pass, affiliation string) error {
	// Initialize the config, setting defaults, etc
	log.Debugf("RegisterBootstrapUser - User: %s, Pass: %s, affiliation: %s", user, pass, affiliation)

	if user == "" || pass == "" {
		return errors.New("empty user and/or pass not allowed")
	}

	id := ServerConfigIdentity{
		Name:           user,
		Pass:           pass,
		Type:           "user",
		Affiliation:    affiliation,
		MaxEnrollments: s.Config.Registry.MaxEnrollments,
		Attrs: map[string]string{
			"hf.Registrar.Roles":         "client,user,peer,validator,auditor",
			"hf.Registrar.DelegateRoles": "client,user,validator,auditor",
			"hf.Revoker":                 "true",
			"hf.IntermediateCA":          "true",
		},
	}
	registry := &s.Config.Registry
	registry.Identities = append(registry.Identities, id)
	log.Debugf("Registered bootstrap identity: %+v", &id)
	return nil
}

// Initialize the config, setting any defaults and making filenames absolute
func (s *Server) initConfig() (err error) {
	// Init home directory if not set
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("Failed to initialize server's home directory: %s", err)
		}
	}
	// Init config if not set
	if s.Config == nil {
		s.Config = new(ServerConfig)
	}
	// Set config defaults
	cfg := s.Config
	if cfg.Address == "" {
		cfg.Address = DefaultServerAddr
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultServerPort
	}
	// Set log level if debug is true
	if cfg.Debug {
		log.Level = log.LevelDebug
	}

	return nil
}

func (s *Server) loadStandardCA() (*CA, error) {
	ca := &CA{}
	ca.Config = new(ServerConfig)

	// No configuration provided for CA, user server's configuration
	ca.Config = s.Config
	ca.HomeDir = s.HomeDir
	ca.ParentServerURL = s.ParentServerURL
	if ca.Config.CA.Name == "" {
		ca.Config.CA.Name = DefaultCAName
	}

	ca.Init(false)

	return s.addCA(ca)
}

func (s *Server) loadCA(caFile string) (*CA, error) {
	log.Infof("Loading CA from %s", caFile)
	var err error

	ca := &CA{}
	ca.Config = new(ServerConfig)

	exists := util.FileExists(caFile)
	if !exists {
		return nil, fmt.Errorf("%s file does not exist", caFile)
	}

	ca.HomeDir = filepath.Dir(caFile)

	viper.SetConfigFile(caFile)
	err = viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to read config file: %s", err)
	}

	// Unmarshal the config into 'serverCfg'
	// When viper bug https://github.com/spf13/viper/issues/327 is fixed
	// and vendored, the work around code can be deleted.
	viperIssue327WorkAround := true
	if viperIssue327WorkAround {
		sliceFields := []string{
			"csr.hosts",
			"tls.clientauth.certfiles",
			"db.tls.certfiles",
			"cafiles",
		}
		err = util.ViperUnmarshal(ca.Config, sliceFields)
		if err != nil {
			return nil, fmt.Errorf("Incorrect format in file '%s': %s", caFile, err)
		}
	} else {
		err = viper.Unmarshal(ca.Config)
		if err != nil {
			return nil, fmt.Errorf("Incorrect format in file '%s': %s", caFile, err)
		}
	}

	util.CheckForMissingValues(ca.Config, s.Config)

	if !viper.IsSet("registry.maxenrollments") {
		ca.Config.Registry.MaxEnrollments = s.Config.Registry.MaxEnrollments
	}

	if !viper.IsSet("db.tls.enabled") {
		ca.Config.DB.TLS.Enabled = s.Config.DB.TLS.Enabled
	}

	ca.Init(false)

	return s.addCA(ca)

}

func (s *Server) addCA(ca *CA) (*CA, error) {
	log.Infof("Adding CA %s to server", ca.Config.CA.Name)

	if _, ok := s.CAs[ca.Config.CA.Name]; ok {
		return nil, fmt.Errorf("CA by name '%s' already exists", ca.Config.CA.Name)
	}

	s.CAs[ca.Config.CA.Name] = ca

	return ca, nil
}

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux = http.NewServeMux()
	s.registerHandler("info", newInfoHandler, noAuth)
	s.registerHandler("register", newRegisterHandler, token)
	s.registerHandler("enroll", newEnrollHandler, basic)
	s.registerHandler("reenroll", newReenrollHandler, token)
	s.registerHandler("revoke", newRevokeHandler, token)
	s.registerHandler("tcert", newTCertHandler, token)
}

// Register an endpoint handler
func (s *Server) registerHandler(
	path string,
	getHandler func(server *Server) (http.Handler, error),
	at authType) {

	var handler http.Handler

	handler, err := getHandler(s)
	if err != nil {
		log.Warningf("Endpoint '%s' is disabled: %s", path, err)
		return
	}
	handler = &fcaAuthHandler{
		server:   s,
		authType: at,
		next:     handler,
	}
	s.mux.Handle("/"+path, handler)
	// TODO: Remove the following line once all SDKs stop using the prefixed paths
	// See https://jira.hyperledger.org/browse/FAB-2597
	s.mux.Handle("/api/v1/cfssl/"+path, handler)
}

// Starting listening and serving
func (s *Server) listenAndServe() (err error) {

	var listener net.Listener
	var clientAuth tls.ClientAuthType
	var ok bool

	c := s.Config

	// Set default listening address and port
	if c.Address == "" {
		c.Address = DefaultServerAddr
	}
	if c.Port == 0 {
		c.Port = DefaultServerPort
	}
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))

	if c.TLS.Enabled {
		log.Debug("TLS is enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			return err
		}

		if c.TLS.ClientAuth.Type == "" {
			c.TLS.ClientAuth.Type = defaultClientAuth
		}

		log.Debugf("Client authentication type requested: %s", c.TLS.ClientAuth.Type)

		authType := strings.ToLower(c.TLS.ClientAuth.Type)
		if clientAuth, ok = clientAuthTypes[authType]; !ok {
			return errors.New("Invalid client auth type provided")
		}

		var certPool *x509.CertPool
		if authType != defaultClientAuth {
			certPool, err = LoadPEMCertPool(c.TLS.ClientAuth.CertFiles)
			if err != nil {
				return err
			}
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{cer},
			ClientAuth:   clientAuth,
			ClientCAs:    certPool,
		}

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return fmt.Errorf("TLS listen failed: %s", err)
		}
		log.Infof("Listening at https://%s", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen failed: %s", err)
		}
		log.Infof("Listening at http://%s", addr)
	}
	s.listener = listener

	// Start serving requests, either blocking or non-blocking
	if s.BlockingStart {
		return s.serve()
	}
	go s.serve()
	return nil
}

func (s *Server) serve() error {
	s.serveError = http.Serve(s.listener, s.mux)
	log.Errorf("Server has stopped serving: %s", s.serveError)
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
	return s.serveError
}
