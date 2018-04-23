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

package lib_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/stretchr/testify/assert"
)

func TestX509Credential(t *testing.T) {
	clientHome, err := ioutil.TempDir("../testdata", "x509credtest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(clientHome)

	err = CopyFile("../testdata/ec256-1-cert.pem", filepath.Join(clientHome, "ec256-1-cert.pem"))
	if err != nil {
		t.Fatalf("Failed to copy ec256-1-cert.pem to %s: %s", clientHome, err.Error())
	}
	err = os.MkdirAll(filepath.Join(clientHome, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create msp/keystore directory: %s", err.Error())
	}

	client := &Client{
		Config: &ClientConfigImpl{
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
	x509Cred := NewX509Credential(certFile, keyFile, client)

	assert.Equal(t, x509Cred.Type(), X509, "Type for a X509Credential instance must be X509")
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
	x509Cred = NewX509Credential(certFile, keyFile, client)
	err = x509Cred.Load()
	assert.Error(t, err, "Load should have failed to load key file")
	assert.Contains(t, err.Error(), "Could not find the private key in the BCCSP keystore nor in the keyfile")

	err = CopyFile("../testdata/ec256-1-key.pem", filepath.Join(client.HomeDir, "ec256-1-key.pem"))
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
	err = CopyFile("../testdata/ec256-1-key.pem", keystore)
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

func TestIdemixCredential(t *testing.T) {
	clientHome, err := ioutil.TempDir("../testdata", "idemixcredtest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(clientHome)

	signerConfig := filepath.Join(clientHome, "SignerConfig")
	client := &Client{
		Config: &ClientConfigImpl{
			URL: fmt.Sprintf("http://localhost:7054"),
		},
		HomeDir: clientHome,
	}

	idemixCred := NewIdemixCredential(signerConfig, client)

	assert.Equal(t, idemixCred.Type(), Idemix, "Type for a IdemixCredential instance must be Idemix")
	_, err = idemixCred.Val()
	assert.Error(t, err, "Val should return error if credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Credential value is not set")
	}
	_, err = idemixCred.EnrollmentID()
	assert.Error(t, err, "EnrollmentID should retrun an error if credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Credential value is not set")
	}

	err = idemixCred.Store()
	assert.Error(t, err, "Store should must retrun an error if credential has not been loaded from disk or set")

	err = idemixCred.SetVal("hello")
	assert.Error(t, err, "SetVal should fail as it expects an object of type *mspprotos.IdemixMSPSignerConfig")

	err = idemixCred.Load()
	assert.Error(t, err, "Load should fail as %s is not found", signerConfig)

	err = ioutil.WriteFile(signerConfig, []byte("hello"), 0744)
	if err != nil {
		t.Fatalf("Failed to write to file %s: %s", signerConfig, err.Error())
	}
	err = idemixCred.Load()
	assert.Error(t, err, "Load should fail as %s contains invalid data", signerConfig)

	signerConfigTestFile := "../testdata/IdemixSignerConfig"
	err = CopyFile(signerConfigTestFile, signerConfig)
	if err != nil {
		t.Fatalf("Failed to copy %s to %s: %s", signerConfigTestFile, signerConfig, err.Error())
	}

	err = idemixCred.Load()
	assert.NoError(t, err, "Load should not return error as %s exists and is valid", signerConfig)

	_, err = idemixCred.Val()
	assert.NoError(t, err, "Val should not return error as credential is loaded")

	if err = os.Chmod(signerConfig, 0000); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", signerConfig, err)
	}
	err = idemixCred.Store()
	assert.Error(t, err, "Store should fail as %s is not writable", signerConfig)

	if err = os.Chmod(signerConfig, 0644); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", signerConfig, err)
	}
	err = idemixCred.Store()
	assert.NoError(t, err, "Store should not fail as %s is writable and Idemix credential value is set", signerConfig)

	_, err = idemixCred.Val()
	assert.NoError(t, err, "Val should not return error as Idemix credential has been loaded")

	_, err = idemixCred.EnrollmentID()
	assert.Error(t, err, "EnrollmentID is not implemented for Idemix credential")

	_, err = idemixCred.CreateOAuthToken([]byte("hello"))
	assert.Error(t, err, "CreateOAuthToken is not implemented for Idemix credential")

	_, err = idemixCred.RevokeSelf()
	assert.Error(t, err, "RevokeSelf should fail as it is not implmented for Idemix credential")
}
