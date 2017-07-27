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
package attrmgr_test

import (
	"crypto/x509"
	"testing"

	"github.com/hyperledger/fabric-ca/attrmgr"
	"github.com/stretchr/testify/assert"
)

// TestAttrs tests attributes
func TestAttrs(t *testing.T) {
	mgr := attrmgr.New(nil)
	attrs := []attrmgr.Attribute{
		&Attribute{Name: "attr1", Value: "val1"},
		&Attribute{Name: "attr2", Value: "val2"},
		&Attribute{Name: "attr3", Value: "val3"},
		&Attribute{Name: "attr4", Value: "val4"},
		&Attribute{Name: "attr5", Value: "val5"},
	}
	reqs := []attrmgr.AttributeRequest{
		&AttributeRequest{Name: "attr1", Require: false, Encrypt: false},
		&AttributeRequest{Name: "attr2", Require: true, Encrypt: false},
		&AttributeRequest{Name: "attr3", Require: false, Encrypt: true},
		&AttributeRequest{Name: "attr4", Require: true, Encrypt: true},
		&AttributeRequest{Name: "noattr1", Require: false, Encrypt: true},
		&AttributeRequest{Name: "noattr2", Require: false, Encrypt: false},
	}
	// Add the requested attributes to an X509 certificate
	cert := &x509.Certificate{}
	secretAttrInfo, err := mgr.ProcessAttributeRequestsForCert(reqs, attrs, cert)
	assert.NoError(t, err)
	// Get the Attributes object from the cert and secret info
	at, err := mgr.GetAttributesFromCert(cert, secretAttrInfo)
	assert.NoError(t, err)
	// Get names of attributes
	numAttrs := len(at.Names())
	assert.True(t, numAttrs == 4, "expecting 4 attributes but found %d", numAttrs)

	// Check individual attributes
	checkAttr(t, "attr1", "val1", at)
	checkAttr(t, "attr2", "val2", at)
	checkAttr(t, "attr3", "val3", at)
	checkAttr(t, "attr4", "val4", at)
	checkAttr(t, "attr5", "", at)
	checkAttr(t, "noattr1", "", at)
	checkAttr(t, "noattr2", "", at)

	// Negative test case: add required attributes which don't exist
	reqs = []attrmgr.AttributeRequest{
		&AttributeRequest{Name: "noattr1", Require: true, Encrypt: true},
		&AttributeRequest{Name: "noattr2", Require: true, Encrypt: false},
	}
	_, err = mgr.ProcessAttributeRequestsForCert(reqs, attrs, cert)
	assert.Error(t, err)

	// Negative test case: get attributes with bad secret info
	_, err = mgr.GetAttributesFromCert(cert, []byte("bad secret info"))
	assert.Error(t, err)

	// Negative test case: get attributes with bad public info in cert
	cert = &x509.Certificate{}
	mgr.AddAttributesToCert([]byte("bad public info"), cert)
	_, err = mgr.GetAttributesFromCert(cert, nil)
	assert.Error(t, err)
}

func checkAttr(t *testing.T, name, val string, attrs *attrmgr.Attributes) {
	v, ok, err := attrs.Value(name)
	assert.NoError(t, err)
	if val == "" {
		assert.False(t, attrs.Contains(name), "contains attribute '%s'", name)
		assert.False(t, ok, "attribute '%s' was found", name)
	} else {
		assert.True(t, attrs.Contains(name), "does not contain attribute '%s'", name)
		assert.True(t, ok, "attribute '%s' was not found", name)
		assert.True(t, v == val, "incorrect value for '%s'; expected '%s' but found '%s'", name, val, v)
	}
}

type Attribute struct {
	Name, Value string
}

func (a *Attribute) GetName() string {
	return a.Name
}

func (a *Attribute) GetValue() string {
	return a.Value
}

type AttributeRequest struct {
	Name    string
	Require bool
	Encrypt bool
}

func (ar *AttributeRequest) GetName() string {
	return ar.Name
}

func (ar *AttributeRequest) IsRequired() bool {
	return ar.Require
}

func (ar *AttributeRequest) ShouldEncrypt() bool {
	return ar.Encrypt
}
