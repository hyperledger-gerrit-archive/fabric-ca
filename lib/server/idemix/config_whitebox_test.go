/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitConfig(t *testing.T) {
	cfg := Config{
		IssuerPublicKeyfile:      DefaultIssuerPublicKeyFile,
		IssuerSecretKeyfile:      DefaultIssuerSecretKeyFile,
		RevocationPublicKeyfile:  DefaultRevocationPublicKeyFile,
		RevocationPrivateKeyfile: DefaultRevocationPrivateKeyFile,
	}
	homeDir, err := ioutil.TempDir(".", "configinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(homeDir)
	err = cfg.init(homeDir)
	assert.NoError(t, err)
	keystore := path.Join(homeDir, "msp/keystore")
	_, err = os.Stat(keystore)
	assert.NoError(t, err)
}

func TestInitConfigExistingHome(t *testing.T) {
	cfg := Config{
		IssuerPublicKeyfile:      DefaultIssuerPublicKeyFile,
		IssuerSecretKeyfile:      DefaultIssuerSecretKeyFile,
		RevocationPublicKeyfile:  DefaultRevocationPublicKeyFile,
		RevocationPrivateKeyfile: DefaultRevocationPrivateKeyFile,
	}
	homeDir, err := ioutil.TempDir(".", "configinittest1")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(homeDir)

	err = os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0755)
	if err != nil {
		t.Fatalf("Failed to create directory:%s", err.Error())
	}

	err = cfg.init(homeDir)
	assert.NoError(t, err)
}

func TestInitConfigReadonlyHome(t *testing.T) {
	cfg := Config{
		IssuerPublicKeyfile:      DefaultIssuerPublicKeyFile,
		IssuerSecretKeyfile:      DefaultIssuerSecretKeyFile,
		RevocationPublicKeyfile:  DefaultRevocationPublicKeyFile,
		RevocationPrivateKeyfile: DefaultRevocationPrivateKeyFile,
	}
	tmpDir, err := ioutil.TempDir(".", "configinittest1")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(tmpDir)

	homeDir2 := path.Join(tmpDir, "homeDir2")
	err = os.MkdirAll(homeDir2, 4444)
	if err != nil {
		t.Errorf("Failed to chmod directory: %s", err.Error())
	}

	err = cfg.init(homeDir2)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to create directory")
	}
}
