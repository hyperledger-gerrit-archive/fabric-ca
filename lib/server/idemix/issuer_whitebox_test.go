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
}

func TestWallClock(t *testing.T) {
	clock := wallClock{}
	assert.NotNil(t, clock.Now())
}
