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
	"path/filepath"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestNewSignerError(t *testing.T) {
	_, err := NewSigner(nil, []byte{})
	assert.Error(t, err, "NewSigner should return an error if cert byte array is empty")
}

func TestNewSigner(t *testing.T) {
	certBytes, err := util.ReadFile(filepath.Join(testDataDir, "ec256-1-cert.pem"))
	if err != nil {
		t.Fatalf("Failed to read the cert: %s", err.Error())
	}
	signer, err := NewSigner(nil, certBytes)
	assert.NoError(t, err, "NewSigner should not return an error if cert bytes are valid")

	assert.NotNil(t, signer.GetX509Cert())
	assert.Nil(t, signer.Key())
	assert.NotEmpty(t, signer.GetName())
	_, err = signer.Attributes()
	assert.NoError(t, err)
}
