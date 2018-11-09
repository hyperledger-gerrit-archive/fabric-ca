/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/hyperledger/fabric-ca/api"
)

const (
	// Bootstrapadminpw is the password for the test admin user
	Bootstrapadminpw = "@dminPW1"
	rootPort         = 7075
	rootDir          = "rootDir"
	rootClientDir    = "rootClientDir"
	intermediatePort = 7076
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
)

// GetEnrollmentURL returns the non-secure enrollment URL for the test admin user
func GetEnrollmentURL(port int) string {
	return fmt.Sprintf("http://admin:%s@localhost:%d", Bootstrapadminpw, port)
}

// GetSecureEnrollmentURL returns the secure enrollment URL for the test admin user
func GetSecureEnrollmentURL(port int) string {
	return fmt.Sprintf("https://admin:%s@localhost:%d", Bootstrapadminpw, port)
}

// TestGetRootServer creates a server with root configuration
func TestGetRootServer(t *testing.T) *Server {
	return TestGetServer(rootPort, rootDir, "", -1, t)
}

// TestGetIntermediateServer creates a server with intermediate server configuration
func TestGetIntermediateServer(idx int, t *testing.T) *Server {
	return TestGetServer(
		intermediatePort,
		path.Join(intermediateDir, strconv.Itoa(idx)),
		getRootServerURL(),
		-1,
		t)
}

// TestGetServerActiveDir creates and returns a pointer to a server struct but does not delete the home directory
func TestGetServerActiveDir(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	return serverWithDefaultConfig(port, home, parentURL, maxEnroll, t)
}

// TestGetServer creates and returns a pointer to a server struct
func TestGetServer(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	if home != testdataDir {
		os.RemoveAll(home)
	}

	return serverWithDefaultConfig(port, home, parentURL, maxEnroll, t)
}

// TestServerWithCustomConfig creates and returns a pointer to server using custom configuration
func TestServerWithCustomConfig(port int, home, parentURL string, maxEnroll int, serverCfg *ServerConfig, caCfg *CAConfig, t *testing.T) *Server {
	if serverCfg == nil || caCfg == nil {
		t.Fatal("Either missing server or CA config")
	}
	srv := &Server{
		HomeDir: home,
		Config:  serverCfg,
		CA: CA{
			Config: caCfg,
		},
	}
	return BootstrapTestIdentities(srv, t)
}

// BootstrapTestIdentities bootstraps test identities, creates and returns a pointer to a server struct
func BootstrapTestIdentities(srv *Server, t *testing.T) *Server {
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", Bootstrapadminpw, "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

// CopyFile copies a file
func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	defer srcFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

// GenerateECDSATestCert generates EC based certificate for testing purposes
func GenerateECDSATestCert() error {
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"IBM"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(15, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	privKey, err := ioutil.ReadFile("../testdata/ec_key.pem")
	if err != nil {
		return err
	}

	decoded, _ := pem.Decode(privKey)
	if decoded == nil {
		return errors.New("Failed to decode the PEM-encoded ECDSA key")
	}
	privateKey, err := x509.ParseECPrivateKey(decoded.Bytes)
	if err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey

	var parent = template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create("../testdata/ec_cert.pem")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

	return nil
}

// EnrollDefaultTestBootstrapAdmin enrolls the test admin user
func EnrollDefaultTestBootstrapAdmin(c *Client) (*EnrollmentResponse, error) {
	Bootstrapadminpw := "@dminPW1"
	return c.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: Bootstrapadminpw,
	})
}

// Currently not being used anywhere, commenting it out for right now
// it was just bringing test coverage.

// StopAndCleanupServer stops the server and removes the server's home directory
// func StopAndCleanupServer(t *testing.T, srv *Server) {
// 	if srv != nil {
// 		defer os.RemoveAll(srv.HomeDir)
// 		err := srv.Stop()
// 		if err != nil {
// 			t.Errorf("Server stop failed: %s", err)
// 		}
// 	}
// }

// TestGetRootClient returns a Fabric CA client that is meant for a root Fabric CA server
func TestGetRootClient() *Client {
	return TestGetClient(rootPort, rootClientDir)
}

// TestGetClient returns a Fabric CA client
func TestGetClient(port int, home string) *Client {
	return &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: home,
	}
}

func serverWithDefaultConfig(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2":      []string{"dept1"},
		"org1":      nil,
		"org2dept1": nil,
	}
	profiles := map[string]*config.SigningProfile{
		"tls": &config.SigningProfile{
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth", "key agreement"},
			ExpiryString: "8760h",
		},
		"ca": &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "8760h",
			CAConstraint: config.CAConstraint{
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
	}
	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "8760h",
	}
	srv := &Server{
		Config: &ServerConfig{
			Port:  port,
			Debug: true,
		},
		CA: CA{
			Config: &CAConfig{
				Intermediate: IntermediateCA{
					ParentServer: ParentServer{
						URL: parentURL,
					},
				},
				Affiliations: affiliations,
				Registry: CAConfigRegistry{
					MaxEnrollments: maxEnroll,
				},
				Signing: &config.Signing{
					Profiles: profiles,
					Default:  defaultProfile,
				},
				Version: "1.1.0", // The default test server/ca should use the latest version
			},
		},
		HomeDir: home,
	}
	return BootstrapTestIdentities(srv, t)
}

func getRootServerURL() string {
	return GetEnrollmentURL(rootPort)
}
