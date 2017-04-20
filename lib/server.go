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
	"io/ioutil"
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
	// The server mux
	mux *http.ServeMux
	// The current listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// Server's default CA
	CA
	// A map of CAs stored by CA name as key
	caMap map[string]*CA
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {
	// Initialize the config, setting defaults, etc
	err = s.initConfig()
	if err != nil {
		return err
	}

	err = s.initDefaultCA(&s.CA, renew)
	if err != nil {
		return err
	}

	// Successful initialization
	return nil
}

// Start the fabric-ca server
func (s *Server) Start() (err error) {
	log.Infof("Starting server in home directory: %s", s.HomeDir)

	s.serveError = nil

	if s.listener != nil {
		return errors.New("server is already started")
	}

	// Initialize the server
	err = s.Init(false)
	if err != nil {
		return err
	}

	if s.Config.CAcount != 0 && len(s.Config.CAfiles) > 0 {
		return fmt.Errorf("Can't set values for both cacount and cafiles")
	}

	s.Config.TLS.ClientAuth.CertFiles = util.NormalizeStringSlice(s.Config.TLS.ClientAuth.CertFiles)

	if s.Config.CAcount >= 1 {
		s.createDefaultCAConfigs(s.Config.CAcount)
	}

	if len(s.Config.CAfiles) != 0 {
		log.Infof("CAs to be started: %s", s.Config.CAfiles)
		var caFiles []string

		caFiles, err = util.NormalizeFileList(s.Config.CAfiles, s.HomeDir)
		if err != nil {
			return err
		}
		for _, caFile := range caFiles {
			err = s.loadCA(caFile, false)
			if err != nil {
				return err
			}
		}
	}

	// Register http handlers
	s.registerHandlers()

	log.Infof("%d CA instance(s) running on server", len(s.caMap))

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

	id := CAConfigIdentity{
		Name:           user,
		Pass:           pass,
		Type:           "user",
		Affiliation:    affiliation,
		MaxEnrollments: s.CA.Config.Registry.MaxEnrollments,
		Attrs: map[string]string{
			"hf.Registrar.Roles":         "client,user,peer,validator,auditor",
			"hf.Registrar.DelegateRoles": "client,user,validator,auditor",
			"hf.Revoker":                 "true",
			"hf.IntermediateCA":          "true",
		},
	}

	registry := &s.CA.Config.Registry
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

	s.makeFileNamesAbsolute()
	s.caMap = make(map[string]*CA)

	return nil
}

func (s *Server) initDefaultCA(ca *CA, renew bool) error {
	log.Debug("Initializing default ca")

	err := initCA(ca, s.HomeDir, s.CA.Config, s, renew)
	if err != nil {
		return err
	}

	if ca.Config.CA.Name == "" {
		ca.Config.CA.Name = DefaultCAName
	}

	err = s.addCA(ca)
	if err != nil {
		return err
	}

	return nil
}

// loadCA loads up a CA's configuration from the specified
func (s *Server) loadCA(caFile string, renew bool) error {
	log.Infof("Loading CA from %s", caFile)
	var err error

	caConfig := new(CAConfig)

	exists := util.FileExists(caFile)
	if !exists {
		return fmt.Errorf("%s file does not exist", caFile)
	}

	viper.SetConfigFile(caFile)
	err = viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Failed to read config file: %s", err)
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
		err = util.ViperUnmarshal(caConfig, sliceFields)
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", caFile, err)
		}
	} else {
		err = viper.Unmarshal(caConfig)
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", caFile, err)
		}
	}

	if caConfig.CA.Name == "" {
		return errors.New("No CA name provided in configuration, CA name is required")
	}

	util.CopyMissingValues(s.CA.Config, caConfig)

	caConfig.CA.Certfile = filepath.Base(caConfig.CA.Certfile)
	caConfig.CA.Keyfile = filepath.Base(caConfig.CA.Keyfile)

	if caConfig.DB.Type == defaultDatabaseType {
		caConfig.DB.Datasource = filepath.Base(caConfig.DB.Datasource)
	}

	// Need to error if no CA name provided in config file, we cannot revert to using
	// the name of default CA cause CA names must be unique
	if caConfig.CA.Name == "" {
		return errors.New("No CA name provide in CA configuration file. CA name is required")
	}

	if !viper.IsSet("registry.maxenrollments") {
		caConfig.Registry.MaxEnrollments = s.CA.Config.Registry.MaxEnrollments
	}

	if !viper.IsSet("db.tls.enabled") {
		caConfig.DB.TLS.Enabled = s.CA.Config.DB.TLS.Enabled
	}

	ca, err := NewCA(filepath.Dir(caFile), caConfig, s, renew)
	if err != nil {
		return err
	}

	return s.addCA(ca)

}

// addCA adds the CA to the server and registers its handlers
func (s *Server) addCA(ca *CA) error {
	log.Infof("Adding CA %s to server", ca.Config.CA.Name)

	if _, ok := s.caMap[ca.Config.CA.Name]; ok {
		return fmt.Errorf("CA by name '%s' already exists", ca.Config.CA.Name)
	}

	s.caMap[ca.Config.CA.Name] = ca

	log.Infof("CA '%s' has been added to server ", ca.Config.CA.Name)

	return nil
}

// createDefaultCAConfigs creates specified number of default CA configuration files
func (s *Server) createDefaultCAConfigs(cacount int) error {
	log.Debugf("Creating %d default CA configuration files", cacount)

	cashome, err := util.MakeFileAbs("ca", s.HomeDir)
	if err != nil {
		return err
	}

	os.Mkdir(cashome, 0755)

	for i := 1; i <= cacount; i++ {
		cahome := fmt.Sprintf(cashome+"/ca%d", i)
		cfgFileName := filepath.Join(cahome, "fabric-ca-config.yaml")

		caName := fmt.Sprintf("ca%d", i)
		cfg := strings.Replace(defaultCACfgTemplate, "<<<CANAME>>>", caName, 1)

		s.Config.CAfiles = append(s.Config.CAfiles, cfgFileName)

		// Now write the file
		err := os.MkdirAll(filepath.Dir(cfgFileName), 0755)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
		if err != nil {
			return err
		}

	}
	return nil
}

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux = http.NewServeMux()
	s.registerHandler("cainfo", newInfoHandler, noAuth)
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

// Make all file names in the config absolute
func (s *Server) makeFileNamesAbsolute() error {
	fields := []*string{
		&s.Config.TLS.CertFile,
		&s.Config.TLS.KeyFile,
	}
	for _, namePtr := range fields {
		abs, err := util.MakeFileAbs(*namePtr, s.HomeDir)
		if err != nil {
			return err
		}
		*namePtr = abs
	}
	return nil
}
