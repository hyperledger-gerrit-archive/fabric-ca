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
	"strings"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetAllAffiliations(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})

	admin2 := resp.Identity

	getAllAffResp, err := admin.GetAllAffiliations("")
	assert.NoError(t, err, "Failed to get all affiliations")

	affiliations := []spi.AffiliationImpl{}
	err = srv.CA.db.Select(&affiliations, srv.CA.db.Rebind("SELECT * FROM affiliations"))
	if err != nil {
		t.Error("Failed to get all affiliations in database")
	}

	if len(affiliations) != len(getAllAffResp.Affiliations) {
		t.Error("Failed to correctly get all affiliations for a root user")
	}

	// admin2's affilations is "org2"
	getAllAffResp, err = admin2.GetAllAffiliations("")
	assert.NoError(t, err, "Failed to get all affiliations for admin2")

	if len(getAllAffResp.Affiliations) != 2 {
		t.Error("Failed to correctly get all affiliations for a root user")
	}

	for _, aff := range getAllAffResp.Affiliations {
		if !strings.Contains(aff.Name, "org2") {
			t.Errorf("Incorrect affiliation received: %s", aff.Name)
		}
	}

	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
	})
	util.FatalError(t, err, "Failed to register a user that is not affiliation manager")

	_, err = notAffMgr.GetAllAffiliations("")
	assert.Error(t, err, "Should have failed, as the caller does not have the attribute 'hf.AffiliationMgr'")
}

func TestGetAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})

	admin2 := resp.Identity

	getAffResp, err := admin.GetAffiliation("org2.dept1", "")
	assert.NoError(t, err, "Failed to get requested affiliations")

	if getAffResp.Name != "org2.dept1" {
		t.Error("Failed to get correct affiliation")
	}

	getAffResp, err = admin2.GetAffiliation("org1", "")
	assert.Error(t, err, "Should have failed, caller not authorized to get affiliation")

	getAffResp, err = admin2.GetAffiliation("org2.dept2", "")
	assert.Error(t, err, "Should have returned an error, requested affiliation does not exist")

	getAffResp, err = admin2.GetAffiliation("org2.dept1", "")
	assert.NoError(t, err, "Failed to get requested affiliation")

	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
	})
	util.FatalError(t, err, "Failed to register a user that is not affiliation manager")

	_, err = notAffMgr.GetAffiliation("org2", "")
	assert.Error(t, err, "Should have failed, as the caller does not have the attribute 'hf.AffiliationMgr'")
}

func TestDynamicAddAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	// Register an admin with "hf.AffiliationMgr" role
	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "false",
			},
		},
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin2 := resp.Identity

	addAffReq := &api.AddAffiliationRequest{}
	addAffReq.Info.Name = "org3"

	addAffResp, err := notAffMgr.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, caller does not have 'hf.AffiliationMgr' attribute")

	addAffResp, err = admin2.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed affiliation, caller's affilation is 'org2'. Caller can't add affiliation 'org3'")

	addAffResp, err = admin.AddAffiliation(addAffReq)
	util.FatalError(t, err, "Failed to add affiliation 'org3'")

	if addAffResp.Name != "org3" {
		t.Error("Incorrect affilation name in response to add 'org3'")
	}

	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed affiliation 'org3' already exists")

	addAffReq.Info.Name = "org3.dept1"
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.NoError(t, err, "Failed to affiliation")

	registry := srv.registry
	_, err = registry.GetAffiliation("org3.dept1")
	assert.NoError(t, err, "Failed to add affiliation correctly")

	addAffReq.Info.Name = "org4.dept1.team2"
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, parent affiliation does not exist. Force option is required")

	addAffReq.Force = true
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.NoError(t, err, "Failed to add multiple affiliations with force option")

	_, err = registry.GetAffiliation("org4.dept1.team2")
	assert.NoError(t, err, "Failed to add affiliation correctly")

	_, err = registry.GetAffiliation("org4.dept1")
	assert.NoError(t, err, "Failed to add affiliation correctly")
}

func TestDynamicRemoveAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity

	_, err = admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "testuser1",
		Affiliation: "org2",
	})
	assert.NoError(t, err, "Failed to register and enroll 'testuser1'")

	registry := srv.CA.registry
	_, err = registry.GetUser("testuser1", nil)
	assert.NoError(t, err, "User should exist")

	certdbregistry := srv.CA.certDBAccessor
	certs, err := certdbregistry.GetCertificatesByID("testuser1")
	if len(certs) != 1 {
		t.Error("Failed to correctly enroll identity")
	}

	removeAffReq := &api.RemoveAffiliationRequest{
		Name: "org2",
	}

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, affiliation removal not allowed")

	srv.CA.Config.Cfg.Affiliations.AllowRemove = true

	_, err = admin2.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, can't remove affiliation as the same level as caller")

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, there is an identity associated with affiliation. Need to use force option")

	removeAffReq.Force = true
	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, there is an identity associated with affiliation but identity removal is not allowed")

	srv.CA.Config.Cfg.Identities.AllowRemove = true

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.NoError(t, err, "Failed to remove affiliation")

	_, err = registry.GetUser("testuser1", nil)
	assert.Error(t, err, "User should not exist")

	certs, err = certdbregistry.GetCertificatesByID("testuser1")
	if len(certs) != 0 {
		t.Error("Failed to remove certificates for an identity that removed as part of affiliation removal")
	}
	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, trying to remove an affiliation that does not exist")
}

func TestDynamicModifyAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "hyperledger")
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

	modifyAffReq := &api.ModifyAffiliationRequest{
		Name: "org3",
	}
	modifyAffReq.Info.Name = "org2"
	_, err = admin.ModifyAffiliation(modifyAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
}
