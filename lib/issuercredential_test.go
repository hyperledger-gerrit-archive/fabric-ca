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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/idemix"

	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/stretchr/testify/assert"
)

func TestLoadEmptyIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	privkeyfile := "../testdata/IdemixSecretKey"
	defer os.RemoveAll(testdir)
	ik := NewCAIdemixCredential(pubkeyfile.Name(), privkeyfile)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "CA's Idemix public key file is empty")
	}
}

func TestLoadFakeIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	defer os.RemoveAll(testdir)
	_, err = pubkeyfile.WriteString("foo")
	if err != nil {
		t.Fatalf("Failed to write to the file %s", pubkeyfile.Name())
	}
	ik := NewCAIdemixCredential(pubkeyfile.Name(), privkeyfile.Name())
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to unmarshal CA's Idemix public key bytes")
	}
}

func TestLoadNonExistentIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	pubkeyfile := "../testdata/IdemixPublicKey"
	defer os.RemoveAll(testdir)
	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile.Name())
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "CA's Idemix secret key file is empty")
	}
}

func TestLoadEmptyIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	pubkeyfile := "../testdata/IdemixPublicKey"
	defer os.RemoveAll(testdir)
	ik := NewCAIdemixCredential(pubkeyfile, filepath.Join(testdir, "IdemixSecretKey"))
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read CA's Idemix secret key")
	}
}

func TestLoad(t *testing.T) {
	pubkeyfile := "../testdata/IdemixPublicKey"
	privkeyfile := "../testdata/IdemixSecretKey"
	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	err := ik.Load()
	assert.NoError(t, err, "Failed to load CA's issuer idemix credential")
}

func TestStoreNilIssuerKey(t *testing.T) {
	pubkeyfile := "../testdata/IdemixPublicKey"
	privkeyfile := "../testdata/IdemixSecretKey"
	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "CA's Idemix credential is not set")
	}
}

func TestStoreNilIdemixPublicKey(t *testing.T) {
	pubkeyfile := "../testdata/IdemixPublicKey"
	privkeyfile := "../testdata/IdemixSecretKey"
	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	ik.SetIssuerKey(&idemix.IssuerKey{})
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called with empty issuer public key byte array")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to marshal CA's Idemix public key")
	}
}

func TestStoreInvalidPublicKeyFilePath(t *testing.T) {
	pubkeyfile := "../testdata1/IdemixPublicKey"
	privkeyfile := "../testdata/IdemixSecretKey"

	// Valid issuer public key
	validPubKeyFile := "../testdata/IdemixPublicKey"
	pubKeyBytes, err := ioutil.ReadFile(validPubKeyFile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", validPubKeyFile)
	}

	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		t.Fatalf("Failed to unmarshal idemix public key bytes from %s", validPubKeyFile)
	}

	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	ik.SetIssuerKey(&idemix.IssuerKey{IPk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to non-existent directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store CA's Idemix public key")
	}
}

func TestStoreInvalidSecretKeyFilePath(t *testing.T) {
	pubkeyfile := "../testdata/IdemixPublicKey"
	testdir, err := ioutil.TempDir(".", "issuerkeystoreTest")
	defer os.RemoveAll(testdir)

	// foo directory is non-existent
	privkeyfile := filepath.Join(testdir, "foo/IdemixSecretKey")

	// Valid issuer public key
	pubKeyBytes, err := ioutil.ReadFile(pubkeyfile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", pubkeyfile)
	}

	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		t.Fatalf("Failed to unmarshal idemix public key bytes from %s", pubkeyfile)
	}

	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	ik.SetIssuerKey(&idemix.IssuerKey{IPk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer secret key is being stored to non-existent directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store CA's Idemix secret key")
	}
}

func TestGetIssuerKey(t *testing.T) {
	pubkeyfile := "../testdata/IdemixPublicKey"
	privkeyfile := "../testdata/IdemixSecretKey"
	ik := NewCAIdemixCredential(pubkeyfile, privkeyfile)
	_, err := ik.GetIssuerKey()
	assert.Error(t, err, "GetIssuerKey should return an error if it is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "CA's Idemix credential is not set")
	}
	err = ik.Load()
	if err != nil {
		t.Fatalf("Load of valid issuer public and secret key should not fail: %s", err)
	}
	_, err = ik.GetIssuerKey()
	assert.NoError(t, err, "GetIssuerKey should not return an error if the issuer key is set")
}
