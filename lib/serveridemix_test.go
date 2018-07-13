/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestIdemixFunctions(t *testing.T) {
	var err error

	server := TestGetRootServer(t)
	err = server.Start()
	util.FatalError(t, err, "Failed to start server")
	defer server.Stop()

	// Enroll request
	client := TestGetRootClient()
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin'")
	admin := eresp.Identity

	id := testRegisterAndIdemixEnroll(t, admin)
	testIdemixRevoke(t, admin, id)
}

func testRegisterAndIdemixEnroll(t *testing.T, admin *Identity) *Identity {
	id, err := admin.RegisterAndIdemixEnroll(&api.RegistrationRequest{
		Name: "testIdemixUser",
	})
	assert.NoError(t, err, "Failed to register and enroll 'testIdemixUser'")
	assert.NotEqual(t, len(id.creds), 0)
	return id
}

func testIdemixRevoke(t *testing.T, admin *Identity, idemixUser *Identity) {
	_, err := admin.RevokeIdemix(&api.IdemixRevocationRequest{
		Name: "testIdemixUser",
	})
	assert.NoError(t, err, "Failed to revoke 'testIdemixUser'")

	_, err = idemixUser.Register(&api.RegistrationRequest{
		Name: "testRegistering",
	})
	assert.Error(t, err, "A revoked Identity using Idemix credential should not be able to register")
}
