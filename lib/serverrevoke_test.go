/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestParseInput(t *testing.T) {
	input := "01:AA:22:bb"

	parsedInput := parseInput(input)

	assert.NotContains(t, parsedInput, ":", "failed to correctly remove colons from input")
	assert.NotEqual(t, string(parsedInput[0]), "0", "failed to correctly remove leading zeros from input")
	assert.NotContains(t, parsedInput, "AA", "failed to correctly lowercase capital letters")
}

func TestRevokeSelf(t *testing.T) {
	var err error
	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()
	defer os.RemoveAll("rootDir")
	defer os.RemoveAll("../testdata/msp")

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity
	name := "testuser"
	password := "password"
	_, err = admin.Register(&api.RegistrationRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser'")
	testuser := resp.Identity

	db := srv.CA.CertDBAccessor()
	cert, err := db.GetCertificatesByID("testuser")
	util.FatalError(t, err, "Failed to get certificvate for 'testuser'")

	_, err = testuser.Revoke(&api.RevocationRequest{
		Serial: cert[0].Serial,
		AKI:    cert[0].AKI,
	})
	assert.NoError(t, err, "Failed to revoke one's own certificate using serial and AKI")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser'")
	testuser = resp.Identity

	_, err = testuser.RevokeSelf()
	assert.NoError(t, err, "Failed to revoke one self")
}
