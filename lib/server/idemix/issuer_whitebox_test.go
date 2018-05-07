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

package idemix

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/stretchr/testify/assert"
)

const (
	testPublicKeyFile = "../../../testdata/IdemixPublicKey"
	testSecretKeyFile = "../../../testdata/IdemixSecretKey"
)

// TestIssuer tests issuer
func TestIssuer(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := issuer{name: "ca1", homeDir: testdir, cfg: &Config{}, db: &dbutil.DB{}, idemixLib: NewLib()}
	assert.NotNil(t, issuer.DB(), "DB() should not return nil")
	assert.NotNil(t, issuer.IdemixLib(), "GetIdemixLib() should not return nil")
	assert.Equal(t, "ca1", issuer.Name())
	assert.Nil(t, issuer.IssuerCredential(), "IssueCredential() should return nil")
	assert.Nil(t, issuer.RevocationAuthority(), "RevocationAuthority() should return nil")
	assert.Nil(t, issuer.NonceManager(), "NonceManager() should return nil")
	assert.Nil(t, issuer.IdemixRand(), "IdemixRand() should return nil")
	assert.Nil(t, issuer.CredDBAccessor(), "CredDBAccessor() should return nil")

	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if db is nil")

	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "IssuerPublicKey should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.IssueCredential(nil)
	assert.Error(t, err, "IssueCredential should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	issuer.isInitialized = true
	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if it is already initialized")
}

func TestIssuerPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	issuer := issuer{name: "ca1",
		homeDir:       testdir,
		cfg:           &Config{IssuerPublicKeyfile: "IssuerPublicKey", IssuerSecretKeyfile: "IssuerSecretKey"},
		db:            &dbutil.DB{},
		idemixLib:     NewLib(),
		isInitialized: true,
	}
	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, NewLib())
	issuer.issuerCred = issuerCred
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as issuer credential has not been loaded")

	err = issuer.issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential: %s", err.Error())
	}
	ik, _ := issuerCred.GetIssuerKey()
	ik.IPk = nil
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as it should fail to marshal issuer public key")
}
func TestWallClock(t *testing.T) {
	clock := wallClock{}
	assert.NotNil(t, clock.Now())
}
