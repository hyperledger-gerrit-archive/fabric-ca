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
	"testing"
)

const (
	configDir = "../../testdata"
	caCert    = "root.pem"
	certFile  = "tls_client-cert.pem"
	keyFile   = "tls_client-key.pem"
)

type testTLSConfig struct {
	TLS *ClientTLSConfig
}

func TestGetClientTLSConfig(t *testing.T) {

	cfg := &ClientTLSConfig{
		CertFilesList: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}

	AbsTLSClient(cfg, configDir)

	_, err := GetClientTLSConfig(cfg)
	if err != nil {
		t.Errorf("Failed to get TLS Config: %s", err)
	}

}

func TestProcessCertFiles(t *testing.T) {
	cfg := &ClientTLSConfig{
		CertFiles: "root1.pem, root2.pem",
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}

	ProcessCertFiles(cfg)

	if cfg.CertFilesList[0] != "root1.pem" || cfg.CertFilesList[1] != "root2.pem" {
		t.Error("Failed to process comma seperated string into array")
	}

}
