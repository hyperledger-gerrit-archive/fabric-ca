/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package x509_test

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/client/credential"
	. "github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/hyperledger/fabric-ca/lib/client/credential/x509/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/stretchr/testify/assert"
)

const (
	testDataDir = "../../../../testdata"
)

func TestX509Credential(t *testing.T) {
	clientHome, err := ioutil.TempDir(testDataDir, "x509credtest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(clientHome)

	err = lib.CopyFile(filepath.Join(testDataDir, "ec256-1-cert.pem"), filepath.Join(clientHome, "ec256-1-cert.pem"))
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-cert.pem to %s: %s", clientHome, err.Error())
	}
	err = os.MkdirAll(filepath.Join(clientHome, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create msp/keystore directory: %s", err.Error())
	}

	client := &lib.Client{
		Config: &lib.ClientConfig{
			URL: fmt.Sprintf("http://localhost:7054"),
			CSP: &factory.FactoryOpts{
				SwOpts: &factory.SwOpts{
					HashFamily: "SHA2",
					SecLevel:   256,
					FileKeystore: &factory.FileKeystoreOpts{
						KeyStorePath: "msp/keystore",
					},
				},
			},
		},
		HomeDir: clientHome,
	}
	certFile := filepath.Join(client.HomeDir, "fake-cert.pem")
	keyFile := filepath.Join(client.HomeDir, "fake-key.pem")
	x509Cred := NewCredential(certFile, keyFile, client)

	assert.Equal(t, x509Cred.Type(), CredType, "Type for a X509Credential instance must be X509")
	_, err = x509Cred.Val()
	assert.Error(t, err, "Val should return error as credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Credential value is not set")
	}
	_, err = x509Cred.EnrollmentID()
	assert.Error(t, err, "EnrollmentID should retrun an error as credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Credential value is not set")
	}

	err = x509Cred.Store()
	assert.Error(t, err, "Store should must retrun an error as credential has not been loaded from disk or set")

	err = x509Cred.SetVal("hello")
	assert.Error(t, err, "SetVal should fail as it expects an object of type *Signer")

	_, err = x509Cred.RevokeSelf()
	assert.Error(t, err, "RevokeSelf should return an error as credential has not been loaded from disk or set")

	err = x509Cred.Load()
	assert.Error(t, err, "Load should have failed to load non-existent certificate file")

	certFile = filepath.Join(client.HomeDir, "ec256-1-cert.pem")
	keyFile = filepath.Join(client.HomeDir, "ec256-1-key.pem")

	err = client.Init()
	if err != nil {
		t.Fatalf("Failed to initialize client: %s", err.Error())
	}
	x509Cred = NewCredential(certFile, keyFile, client)
	err = x509Cred.Load()
	assert.Error(t, err, "Load should have failed to load key file")
	assert.Contains(t, err.Error(), "Could not find the private key in the BCCSP keystore nor in the keyfile")

	err = lib.CopyFile(filepath.Join(testDataDir, "ec256-1-key.pem"), filepath.Join(client.HomeDir, "ec256-1-key.pem"))
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-key.pem to %s: %s", clientHome, err.Error())
	}
	err = x509Cred.Load()
	assert.NoError(t, err, "Load should not fail to load as both cert and key files exist and are valid")

	err = os.Remove(keyFile)
	if err != nil {
		t.Fatalf("Failed to remove file %s: %s", keyFile, err.Error())
	}
	keystore := filepath.Join(clientHome, "msp/keystore/ec256-1-key.pem")
	err = lib.CopyFile(filepath.Join(testDataDir, "ec256-1-key.pem"), keystore)
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-key.pem to %s: %s", keystore, err.Error())
	}
	err = x509Cred.Load()
	assert.NoError(t, err, "Should not fail to load x509 credential as cert exists and key is in bccsp keystore")

	_, err = x509Cred.Val()
	assert.NoError(t, err, "Val should not return error as x509 credential has been loaded")

	_, err = x509Cred.EnrollmentID()
	assert.NoError(t, err, "EnrollmentID should not return error as credential has been loaded")

	if err = os.Chmod(certFile, 0000); err != nil {
		t.Fatalf("Failed to chmod certificate file %s: %v", certFile, err)
	}
	err = x509Cred.Store()
	assert.Error(t, err, "Store should fail as %s is not writable", certFile)

	if err = os.Chmod(certFile, 0644); err != nil {
		t.Fatalf("Failed to chmod certificate file %s: %v", certFile, err)
	}

	err = x509Cred.Store()
	assert.NoError(t, err, "Store should not fail as x509 credential is set and cert file path is valid")

	_, err = x509Cred.CreateOAuthToken([]byte("hello"))
	assert.NoError(t, err, "CreateOAuthToken should not return error")
}

func TestRevokeSelf(t *testing.T) {
	clientHome, err := ioutil.TempDir(testDataDir, "revokeselftest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(clientHome)

	err = lib.CopyFile(filepath.Join(testDataDir, "ec256-1-cert.pem"), filepath.Join(clientHome, "ec256-1-cert.pem"))
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-cert.pem to %s: %s", clientHome, err.Error())
	}
	err = os.MkdirAll(filepath.Join(clientHome, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create msp/keystore directory: %s", err.Error())
	}
	keystore := filepath.Join(clientHome, "msp/keystore/ec256-1-key.pem")
	err = lib.CopyFile(filepath.Join(testDataDir, "ec256-1-key.pem"), keystore)
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-key.pem to %s: %s", keystore, err.Error())
	}

	id := new(mocks.Identity)
	client := new(mocks.Client)
	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: "msp/keystore",
			},
		},
	}
	bccsp, err := util.InitBCCSP(&opts, filepath.Join(clientHome, "msp/keystore"), clientHome)
	if err != nil {
		t.Fatalf("Failed initialize BCCSP: %s", err.Error())
	}
	client.On("GetCSP").Return(bccsp)
	client.On("GetCSP").Return(nil)
	certFile := filepath.Join(clientHome, "ec256-1-cert.pem")
	cert, err := readCert(certFile)
	if err != nil {
		t.Fatalf("Failed to read the cert: %s", err.Error())
	}
	x509Cred := NewCredential(certFile, keystore, client)
	err = x509Cred.Load()
	if err != nil {
		t.Fatalf("Should not fail to load x509 credential as cert exists and key is in bccsp keystore: %s", err.Error())
	}
	name, err := x509Cred.EnrollmentID()
	assert.NoError(t, err, "EnrollmentID() should not return an error")
	client.On("NewX509Identity", name, []credential.Credential{x509Cred}).Return(id)

	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	req := &api.RevocationRequest{
		Serial: serial,
		AKI:    aki,
	}
	id.On("Revoke", req).Return(&api.RevocationResponse{}, nil)

	_, err = x509Cred.RevokeSelf()
	assert.NoError(t, err)

	_, err = x509Cred.CreateOAuthToken([]byte{})
	assert.NoError(t, err)
}

func readCert(certFile string) (*x509.Certificate, error) {
	certBytes, err := util.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cert, err := util.GetX509CertificateFromPEM(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
