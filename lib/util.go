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

package lib

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	rootPort         = 7055
	rootDir          = "rootDir"
	intermediatePort = 7056
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
)

var clientAuthTypes = map[string]tls.ClientAuthType{
	"noclientcert":               tls.NoClientCert,
	"requestclientcert":          tls.RequestClientCert,
	"requireanyclientcert":       tls.RequireAnyClientCert,
	"verifyclientcertifgiven":    tls.VerifyClientCertIfGiven,
	"requireandverifyclientcert": tls.RequireAndVerifyClientCert,
}

// GetCertID returns both the serial number and AKI (Authority Key ID) for the certificate
func GetCertID(bytes []byte) (string, string, error) {
	cert, err := BytesToX509Cert(bytes)
	if err != nil {
		return "", "", err
	}
	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	return serial, aki, nil
}

// BytesToX509Cert converts bytes (PEM or DER) to an X509 certificate
func BytesToX509Cert(bytes []byte) (*x509.Certificate, error) {
	dcert, _ := pem.Decode(bytes)
	if dcert != nil {
		bytes = dcert.Bytes
	}
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, fmt.Errorf("buffer was neither PEM nor DER encoding: %s", err)
	}
	return cert, err
}

// LoadPEMCertPool loads a pool of PEM certificates from list of files
func LoadPEMCertPool(certFiles []string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if len(certFiles) > 0 {
		for _, cert := range certFiles {
			log.Debugf("Reading cert file: %s", cert)
			pemCerts, err := ioutil.ReadFile(cert)
			if err != nil {
				return nil, err
			}

			log.Debugf("Appending cert %s to pool", cert)
			if !certPool.AppendCertsFromPEM(pemCerts) {
				return nil, errors.New("Failed to load cert pool")
			}
		}
	}

	return certPool, nil
}

func getRootServerURL() string {
	return fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)
}

// GetRootServer creates a server with root configuration
func GetRootServer(t *testing.T) *Server {
	return GetServer(rootPort, rootDir, "", -1, t)
}

// GetIntermediateServer creates a server with intermediate server configuration
func GetIntermediateServer(idx int, t *testing.T) *Server {
	return GetServer(
		intermediatePort,
		path.Join(intermediateDir, strconv.Itoa(idx)),
		getRootServerURL(),
		0,
		t)
}

// GetServer creates and returns a pointer to a server struct
func GetServer(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	if home != testdataDir {
		os.RemoveAll(home)
	}
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2": nil,
	}
	srv := &Server{
		Config: &ServerConfig{
			Port:         port,
			Debug:        true,
			Affiliations: affiliations,
			Registry: ServerConfigRegistry{
				MaxEnrollments: maxEnroll,
			},
		},
		HomeDir:         home,
		ParentServerURL: parentURL,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", "adminpw", "hyperledger")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}
