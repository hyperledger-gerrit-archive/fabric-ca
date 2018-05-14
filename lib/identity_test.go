/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"io/ioutil"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/stretchr/testify/assert"
)

func getIdentity() *Identity {
	key, _ := util.ImportBCCSPKeyFromPEM("../tesdata/ec-key.pem", factory.GetDefault(), true)
	cert, _ := ioutil.ReadFile("../tesdata/ec.pem")
	id := newIdentity(nil, "test", key, cert)
	return id
}

func TestIdentity(t *testing.T) {
	id := getIdentity()
	testGetName(id, t)
	testGetECert(id, t)
}

func TestBadStoreIdentity(t *testing.T) {
	id := &Identity{}
	err := id.Store()
	if err == nil {
		t.Error("TestBadStoreIdentity passed but should have failed")
	}
}

func TestBadRegistration(t *testing.T) {
	id := &Identity{}
	req := &api.RegistrationRequest{}
	_, err := id.Register(req)
	if err == nil {
		t.Error("Empty registration request should have failed")
	}
}

func testGetName(id *Identity, t *testing.T) {
	name := id.GetName()
	if name != "test" {
		t.Error("Incorrect name retrieved")
	}
}

func testGetECert(id *Identity, t *testing.T) {
	ecert := id.GetECert()
	if ecert == nil {
		t.Error("No ECert was returned")
	}
}

func TestGetCertificates(t *testing.T) {
	id := getIdentity()
	id.client = &Client{
		Config: &ClientConfig{},
	}
	err := id.GetCertificates(&api.GetCertificatesRequest{}, "", nil)
	assert.Error(t, err, "Should fail, no server to contact")
}
