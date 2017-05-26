/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled    bool   `help:"Enable TLS on the listening port"`
	CertFile   string `def:"ca-cert.pem" help:"PEM-encoded TLS certificate file for server's listening port"`
	KeyFile    string `def:"ca-key.pem" help:"PEM-encoded TLS key for server's listening port"`
	ClientAuth ClientAuth
}

// ClientAuth defines the key material needed to verify client certificates
type ClientAuth struct {
	Type      string   `def:"noclientcert" help:"Policy the server will follow for TLS Client Authentication."`
	CertFiles []string `help:"PEM-encoded list of trusted certificate files"`
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled   bool     `skip:"true"`
	CertFiles []string `help:"PEM-encoded list of trusted certificate files"`
	Client    KeyCertFiles
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string `help:"PEM-encoded key file when mutual authentication is enabled"`
	CertFile string `help:"PEM-encoded certificate file when mutual authenticate is enabled"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig) (*tls.Config, error) {
	var certs []tls.Certificate

	log.Debugf("CA Files: %+v\n", cfg.CertFiles)
	log.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)

	if cfg.Client.CertFile != "" && cfg.Client.KeyFile != "" {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := tls.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile)
		if err != nil {
			return nil, err
		}

		certs = append(certs, clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := x509.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No TLS certificate files were provided")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, fmt.Errorf("Failed to read '%s': %s", cacert, err)
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}

// AbsTLSClient makes TLS client files absolute
func AbsTLSClient(cfg *ClientTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.CertFiles); i++ {
		cfg.CertFiles[i], err = util.MakeFileAbs(cfg.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.Client.CertFile, err = util.MakeFileAbs(cfg.Client.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.Client.KeyFile, err = util.MakeFileAbs(cfg.Client.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

// AbsTLSServer makes TLS client files absolute
func AbsTLSServer(cfg *ServerTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.ClientAuth.CertFiles); i++ {
		cfg.ClientAuth.CertFiles[i], err = util.MakeFileAbs(cfg.ClientAuth.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.CertFile, err = util.MakeFileAbs(cfg.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.KeyFile, err = util.MakeFileAbs(cfg.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

func checkCertDates(certFile string) error {
	log.Debug("Check client TLS certificate for valid dates")
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}
