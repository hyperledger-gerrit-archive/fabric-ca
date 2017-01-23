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
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

// ClientTLSConfig defines the root ca and client certificate and key files
type ClientTLSConfig struct {
	CAFiles  []string `mapstructure:"caFiles"` // The filenames of pem files for CA certificates
	CertFile string   `mapstructure:"certFile"`
	KeyFile  string   `mapstructure:"keyFile"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig) (*tls.Config, error) {
	log.Debug("Get Client TLS Configuration")
	var certs []tls.Certificate

	log.Infof("Client Cert File: %s\n", cfg.CertFile)
	log.Infof("Client Key File: %s\n", cfg.KeyFile)
	clientCert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Warningf("Client Cert or Key not provided, if server requires mutual TLS, the connection will fail [error: %s]", err)
	}

	certs = append(certs, clientCert)

	caCertPool := x509.NewCertPool()

	if len(cfg.CAFiles) == 0 {
		log.Error("No CA cert files provided. If server requires TLS, connection will fail")
	}

	for _, cacert := range cfg.CAFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("Failed to parse and append certificate [certificate: %s]", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      caCertPool,
	}

	return config, nil
}

// AbsTLSClient makes TLS client files absolute
func AbsTLSClient(cfg *ClientTLSConfig, configDir string) {
	for i := 0; i < len(cfg.CAFiles); i++ {
		cfg.CAFiles[i] = util.Abs(cfg.CAFiles[i], configDir)
	}
	cfg.CertFile = util.Abs(cfg.CertFile, configDir)
	cfg.KeyFile = util.Abs(cfg.KeyFile, configDir)
}
