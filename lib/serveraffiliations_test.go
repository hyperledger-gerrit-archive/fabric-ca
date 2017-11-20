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
		Name:        "admin2",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: regResp.Secret,
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
}

func TestGetAffiliation(t *testing.T) {
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
		Name:        "admin2",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: regResp.Secret,
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
}

func TestDynamicAddAffiliation(t *testing.T) {
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

	addAffReq := &api.AddAffiliationRequest{}
	addAffReq.Name = "org3"

	_, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
}

func TestDynamicRemoveAffiliation(t *testing.T) {
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

	removeAffReq := &api.RemoveAffiliationRequest{
		Name: "org3",
	}

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
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
