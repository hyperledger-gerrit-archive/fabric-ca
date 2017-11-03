/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetAllIDs(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	// Register several users
	admin := resp.Identity
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Secret:      "admin2pw",
		Type:        "peer",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'admin2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "hyperledger",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Type:        "peer",
		Affiliation: "org2.dept1",
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser4",
		Type:        "client",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser3'")

	// As bootstrap user that has all root permission, should get back all the users in the database
	getAllResp, err := admin.GetAllIdentities("")
	assert.NoError(t, err, "Failed to get all the appropriate identities")
	if len(getAllResp.Identities) != 6 {
		t.Error("Failed to get all the appropriate users")
	}

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity

	getAllResp, err = admin2.GetAllIdentities("")
	assert.NoError(t, err, "Failed to get all the appropriate identities")
	if len(getAllResp.Identities) != 3 {
		t.Error("Failed to get all the appropriate users")
	}

	// Check to make sure that right users got returned
	expectedIDs := []string{"admin2", "testuser2", "testuser3"}
	for _, resp := range getAllResp.Identities {
		name := resp.ID
		if !util.StrContained(name, expectedIDs) {
			t.Error("Failed to get right user back")
		}
	}
}

func TestGetID(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	// Register several users
	admin := resp.Identity
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Secret:      "admin2pw",
		Type:        "peer",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'admin2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "hyperledger",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Type:        "peer",
		Affiliation: "org2.dept1",
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser4",
		Type:        "client",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser3'")

	// admin has all root permissions and should be able to get any user
	_, err = admin.GetIdentity("testuser", "")
	assert.NoError(t, err, "Failed to get user")

	_, err = admin.GetIdentity("testuser3", "")
	assert.NoError(t, err, "Failed to get user")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity

	_, err = admin2.GetIdentity("testuser3", "")
	assert.NoError(t, err, "Failed to get user")

	// 'admin2' with affiliation of 'org2' is not authorized to get 'testuser' with affiliation of 'hyperledger'
	_, err = admin2.GetIdentity("testuser", "")
	assert.Error(t, err, "'admin2' with affiliation of 'org2' is not authorized to get 'testuser' with affiliation of 'hyperledger'")

	// 'admin2' of type 'peer' is not authorized to get 'testuser4' of type 'client'
	_, err = admin2.GetIdentity("testuser4", "")
	assert.Error(t, err, "'admin2' of type 'peer' is not authorized to get 'testuser4' of type 'client'")

}

func TestDynamicAddIdentity(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "notregistrar",
		Type:        "client",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	addReq := &api.AddIdentityRequest{}
	_, err = admin.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	modReq := &api.ModifyIdentityRequest{}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	addReq.ID = "testuser"
	addReq.Type = "client"
	addReq.Affiliation = "org2"
	_, err = notregistrar.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed to add identity, caller is not a registrar")

	_, err = admin.AddIdentity(addReq)
	assert.NoError(t, err, "Failed to add identity")

	modReq.ID = "testuser"
	modReq.Type = "peer"
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Not yet implemented")
}

func TestDynamicRemoveIdentity(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	// Register and enroll a user that is not a registrar
	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "notregistrar",
		Type:        "client",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	// Register and enroll a registrar that is has limited ability
	// to act on identities
	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Secret:      "admin2pw",
		Type:        "peer",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer",
			},
		},
	})
	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")
	admin2 := resp.Identity

	// Registers users that will be removed
	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "org2",
	})

	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "hyperledger",
	})
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "testuser2",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser2'")

	remReq := &api.RemoveIdentityRequest{}
	remReq.ID = "testuser"
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identities; identity removal is not enabled on server")

	srv.CA.Config.Cfg.Identities.AllowRemove = true

	remReq.ID = ""
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed; no name specified in request")

	remReq.ID = "testuser"
	_, err = admin2.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller does not have the right type")

	remReq.ID = "testuser2"
	_, err = admin2.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller does not have the right affiliation")

	_, err = notregistrar.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller is not a registrar")

	_, err = admin.RemoveIdentity(remReq)
	assert.NoError(t, err, "Failed to remove user")

	registry := srv.CA.registry
	_, err = registry.GetUser(remReq.ID, nil)
	assert.Error(t, err, "User should not exist")

	certs, err := srv.CA.certDBAccessor.GetCertificatesByID(remReq.ID)
	if len(certs) == 0 {
		t.Errorf("No certificates found for '%s'", remReq.ID)
	}
	cert := certs[0]
	if cert.Status != "revoked" {
		t.Error("Failed to revoke certificate when an affiliation was removed")
	}
}
