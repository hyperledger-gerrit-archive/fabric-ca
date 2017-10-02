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
				Value: "client,peer",
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
	removeIdentitiesNotAllowed(t, admin)

	srv.CA.Config.Options.Identities.AllowRemove = true

	editIdentitiesNotAuthorized(t, notadmin, client)
	removeIdentitiesAllowedFail(t, admin2, srv)
	removeIdentitiesAllowedPass(t, admin, srv)
	removeAffiliationsNotAllowed(t, admin2, srv)

	srv.CA.Config.Options.Affiliations.AllowRemove = true

	removeAffiliationsAllowed(t, admin2, srv)
	removeAffCheckUserAndCerts(t, admin2, client, srv)

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
	if len(resp.Responses) == 0 {
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
	if len(resp.Responses) != 0 {
		t.Error("A successfull response should not have been returned")
	}
}

func removeIdentitiesNotAllowed(t *testing.T, admin *Identity) {
	var err error

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "registry.identities.testuser1"},
			},
		},
	})
	assert.Error(t, err, "Should fail, server does not allow deletions")
}

func editIdentitiesNotAuthorized(t *testing.T, notadmin *Identity, client *Client) {
	var err error

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "registry.identities={\"id\": \"testuser1_1\", \"secret\": \"testpass\", \"type\": \"user\"}"},
			},
		},
	})
	assert.Error(t, err, "Should error, invoker does not have authority to edit identities")

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "registry.identities.testuser1"},
			},
		},
	})
	assert.Error(t, err, "Should fail, caller is not authorized to edit identities")

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org2.dept1.team4"},
			},
		},
	})
	assert.Error(t, err, "Should error, invoker does not have authority to edit affiliations")

	_, err = notadmin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org3"},
			},
		},
	})
	assert.Error(t, err, "Should fail, caller is not authorized to edit identities")
}

func removeIdentitiesAllowedFail(t *testing.T, admin2 *Identity, srv *Server) {
	var err error

	// Caller does now have 'user' as part of its 'hf.Registrar.Roles' attribute should not be able to remove
	_, err = admin2.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "registry.identities.testuser1"},
			},
		},
	})
	assert.Error(t, err, "Should have failed to remove user")

	_, err = srv.CA.registry.GetUser("testuser1", nil)
	assert.NoError(t, err, "User should exist")
}

func removeIdentitiesAllowedPass(t *testing.T, admin *Identity, srv *Server) {
	var err error

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "registry.identities.testuser1"},
			},
		},
	})
	assert.NoError(t, err, "Failed to remove user")

	_, err = srv.CA.registry.GetUser("testuser1", nil)
	assert.Error(t, err, "User should not exist")
}

func addAffiliations(t *testing.T, notadmin, admin, admin2 *Identity, srv *Server) {
	var err error

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

func removeAffiliationsNotAllowed(t *testing.T, admin *Identity, srv *Server) {
	var err error

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations:org2.dept1"},
			},
		},
	})
	assert.Error(t, err, "Should have failed to remove affiliation")

	_, err = srv.CA.registry.GetAffiliation("org2.dept1")
	assert.NoError(t, err, "Affiliation should exist")
}

func removeAffiliationsAllowed(t *testing.T, admin *Identity, srv *Server) {
	var err error

	// Deletion of users is not allowed even though deletion of affiliations is allowed
	srv.CA.Config.Options.Identities.AllowRemove = false

	// Affiliation can be removed, even if removing of identities is not allwed by server, as long as the affiliation being removed
	// does not have any identities associated with it
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2.dept1.team4"},
			},
		},
	})
	assert.NoError(t, err, "Should have removed affiliation")

	_, err = srv.CA.registry.GetAffiliation("org2.dept1.team4")
	assert.Error(t, err, "Affiliation should not exist")

	srv.CA.Config.Options.Affiliations.ForceRemoveIdentities = true

	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testAffRemoval1",
		Affiliation: "org2.dept1",
		Type:        "client",
	})
	util.FatalError(t, err, "Failed to register user")

	// If server does not allow removal of identities and there is an identity that
	// is using the affiliation even if 'option.affiliations.forceremoveidentities' config is set to true
	// the affiliation won't be removed
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2.dept1"},
			},
		},
	})
	assert.Error(t, err, "Should have failed to remove affiliation because server does not allow removal of identities")

	_, err = srv.CA.registry.GetAffiliation("org2.dept1")
	assert.NoError(t, err, "Affiliation should exist")

	_, err = srv.CA.registry.GetUser("testAffRemoval1", nil)
	assert.NoError(t, err, "User should exist")

	srv.CA.Config.Options.Identities.AllowRemove = true
	srv.CA.Config.Options.Affiliations.ForceRemoveIdentities = false

	// Affiliation can't be removed, if there is an identity that is using the affiliation even if server allows removing of identities unless
	// the 'option.affiliations.forceremoveidentities' config is set to true
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2.dept1"},
			},
		},
	})
	assert.Error(t, err, "Should have failed to remove affiliation because there is an identity using this affiliation")

	_, err = srv.CA.registry.GetAffiliation("org2.dept1")
	assert.NoError(t, err, "Affiliation should exist")

	_, err = srv.CA.registry.GetUser("testAffRemoval1", nil)
	assert.NoError(t, err, "User should exist")

	srv.CA.Config.Options.Affiliations.ForceRemoveIdentities = true

	// Affiliation can be removed, even if there is an identity that is using the affiliation if 'option.affiliations.forceremoveidentities'
	// and 'option.identities.allowremove' are both set to true
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2.dept1"},
			},
		},
	})
	assert.NoError(t, err, "Should have removed this affiliation")

	_, err = srv.CA.registry.GetAffiliation("org2.dept1")
	assert.Error(t, err, "Affiliation should not exist")

	_, err = srv.CA.registry.GetUser("testAffRemoval1", nil)
	assert.Error(t, err, "User should not exist")

	// Should not be able to remove affiliation that invoker is part of
	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2"},
			},
		},
	})
	assert.Error(t, err, "Should not be able to remove affiliation that invoker is part of")
}

func removeAffCheckUserAndCerts(t *testing.T, admin *Identity, client *Client, srv *Server) {
	var err error

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", "affiliations.org2.dept2.team1"},
			},
		},
	})
	util.FatalError(t, err, "Failed to add affiliations")

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Affiliation: "org2.dept2.team1",
		Type:        "client",
	})
	util.FatalError(t, err, "Failed to register user")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "testuser3",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"remove", "affiliations.org2.dept2.team1"},
			},
		},
	})
	assert.NoError(t, err, "Failed to remove affiliaton")

	_, err = srv.CA.registry.GetAffiliation("org2.dept2.team1")
	assert.Error(t, err, "Affiliation should not exist")

	_, err = srv.CA.registry.GetUser("testuser3", nil)
	assert.Error(t, err, "Failed to remove user when its corresponding affiliation was removed")

	certs, err := srv.CA.certDBAccessor.GetCertificatesByID("testuser3")
	if len(certs) == 0 {
		t.Error("No certificates found for 'testuser3'")
	}
	cert := certs[0]
	if cert.Status != "revoked" {
		t.Error("Failed to revoke certificate when an affiliation was removed")
	}
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
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities:{"id": "testuser", "secret": "testpass", "type": "user"}`},
			},
		},
	})
	assert.Error(t, err, "Should error out if missing '=' in adding a new identity request")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{
			api.Command{
				Args: []string{"add", `registry.identities={"secret": "testpass", "type": "user"}`},
			},
		},
	})
	assert.Error(t, err, "Should error out if missing 'ID' in adding a new identity request")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"remove", "affiliation=org2"}}},
	})
	assert.Error(t, err, "Should error out, remove not yet supported")

	_, err = admin.UpdateServerConfig(&api.ConfigRequest{
		Commands: []api.Command{api.Command{Args: []string{"modify", "affiliation.org2=org1"}}},
	})
	assert.Error(t, err, "Should error out, modify not yet supported")
}
