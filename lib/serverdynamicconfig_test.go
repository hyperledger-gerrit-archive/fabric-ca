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
	"strconv"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestUpdatingConfig(t *testing.T) {
	os.RemoveAll("cfgtest")
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll("cfgtest")
	defer os.RemoveAll("../testdata/msp")

	var err error
	srv := TestGetServer(rootPort, "cfgtest", "", -1, t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(rootPort)
	respEnroll, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin' user")
	admin := respEnroll.Identity

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "notadmin",
		Affiliation: "org2",
	})
	respEnroll, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notadmin",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll 'notadmin' user")
	notadmin := respEnroll.Identity

	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "true",
			},
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "client,user,peer",
			},
		},
	})
	respEnroll, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll 'admin2' user")

	admin2 := respEnroll.Identity

	testPermissions(admin, client, t)
	addIdentities(t, notadmin, admin, srv)
	addAffiliations(t, notadmin, admin, admin2, srv)
	badInput(t, admin2)

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

}

func testPermissions(admin *Identity, client *Client, t *testing.T) {
	// Register a user that does not posses the attributes to modify identites, should result in an authorization error
	regResp, err := admin.Register(&api.RegistrationRequest{
		Name: "cant_update_id",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "true",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'cant_update_id'")
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "cant_update_id",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll 'cant_update_id' user")
	notadmin2 := resp.Identity
	_, err = notadmin2.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities:{"id": "test"}`},
			},
		},
	})
	if assert.Error(t, err, "Error should have occured, invoker does not have proper attributes modify identities") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrAuthFailure))
	}

	// Register a user that does not posses the attributes to modify affiliations, should result in an authorization error
	regResp, err = admin.Register(&api.RegistrationRequest{
		Name: "cant_update_aff",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "false",
			},
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "client,user,peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'cant_update_aff'")
	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "cant_update_aff",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll 'cant_update_aff' user")
	notadmin3 := resp.Identity
	_, err = notadmin3.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations:org3"},
			},
		},
	})
	if assert.Error(t, err, "Error should have occured, invoker does not have proper attributes modify affiliations") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrAuthFailure))
	}
}

func addIdentities(t *testing.T, notadmin, admin *Identity, srv *Server) {
	var err error

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser1", "secret": "testpass", "type": "user", "max_enrollments": 5, "attrs": [{"name": "hf.Revoker", "value": "false"}]}`},
			},
		},
	})
	assert.Error(t, err, "Should error, invoker does not have authority to edit identities")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser1", "secret": "testpass", "type": "user", "max_enrollments": 5, "attrs": [{"name": "hf.Revoker", "value": "false"}]}`},
			},
		},
	})
	assert.NoError(t, err, "Failed to add identity")

	registry := srv.CA.registry
	ui, err := registry.GetUserInfo("testuser1")
	assert.NoError(t, err, "Failed to add user")

	if ui.Attributes[0].Name != "hf.Revoker" {
		t.Error("Failed to correctly add user 'testuser1', attribute 'hf.Revoker' was not added for user")
	}

	// Should return a response for successfull adding of new identity and errors for duplicate registerations
	resp, err := admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser", "secret": "testpass", "type": "user"}`},
			},
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser1", "secret": "testpass", "type": "user"}`},
			},
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser2", "secret": "testpass", "type": "user"}`},
			},
		},
	})
	assert.Error(t, err, "Should have failed to add duplicate identity")
	if resp.Success == "" {
		t.Error("Failed to return a response for an appropriate request to add new identity for user 'testuser2'")
	}

	// Only returning back multiple errors
	resp, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser", "secret": "testpass", "type": "user"}`},
			},
			api.Command{
				Args: []string{"add", `registry.identities={"id": "testuser1", "secret": "testpass", "type": "user"}`},
			},
		},
	})
	assert.Error(t, err, "Should have failed to add duplicate identities")
	if resp.Success != "" {
		t.Error("A successfull response should not have been returned")
	}

}

func addAffiliations(t *testing.T, notadmin, admin, admin2 *Identity, srv *Server) {
	var err error

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org2.dept1.team4"},
			},
		},
	})
	assert.Error(t, err, "Should error, invoker does not have authority to edit affiliations")

	// Test adding affilation with a caller that has root affiliation
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org4"},
			},
		},
	})
	assert.NoError(t, err, "Failed to add affiliations")

	// Test adding affilation with a caller that does not have root affiliation
	_, err = admin2.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org2.dept1.team4"},
			},
		},
	})
	assert.NoError(t, err, "Failed to add affiliations")

	registry := srv.CA.registry

	_, err = registry.GetAffiliation("org2.dept1")
	assert.NoError(t, err, "Affiliation should exist")

	_, err = registry.GetAffiliation("org2.dept1.team4")
	assert.NoError(t, err, "Affiliation should exist")

	// Should return error if trying to add affiliation that already exists
	_, err = admin2.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org2.dept1.team4"},
			},
		},
	})
	assert.Error(t, err, "Should return error if affiliation already exists")

	_, err = admin2.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org1"},
			},
		},
	})
	assert.Error(t, err, "Should have failed to add affiliation that invoker does not have access to")
}

func badInput(t *testing.T, admin *Identity) {
	var err error

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"fake", "affiliations=org3"}}},
	})
	assert.Error(t, err, "Should result in error if no updates requested")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"fake", "affiliations=org3"}}},
	})
	assert.Error(t, err, "Should error out if unsupported action request")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"add", "db=sqlite3"}}},
	})
	assert.Error(t, err, "Should error out if unsupported configuration update requested")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"remove", "affiliation=org2"}}},
	})
	assert.Error(t, err, "Should error out, remove not yet supported")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"modify", "affiliation.org2=org1"}}},
	})
	assert.Error(t, err, "Should error out, modify not yet supported")
}
