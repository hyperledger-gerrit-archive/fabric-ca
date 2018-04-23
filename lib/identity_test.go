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

package lib

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
)

func getIdentity(t *testing.T) *Identity {
	cred := NewX509Credential("../testdata/ec.pem", "../testdata/ec-key.pem", nil)
	err := cred.Load()
	if err != nil {
		t.Fatalf("Failed to load credential from non existant file ../tesdata/ec.pem: %s", err.Error())
	}
	id := NewIdentity(nil, "test", []Credential{cred})
	return id
}

func TestIdentity(t *testing.T) {
	id := getIdentity(t)
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
