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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestStateUpdate(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	var err error
	srv := TestGetRootServer(t)

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	client := getTestClient(rootPort)
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registry := srv.CA.DBAccessor()
	userInfo, err := registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	// User state should have gotten updated to 1 after a successful enrollment
	if userInfo.(*DBUser).State != 1 {
		t.Error("Incorrect state set for user")
	}

	// Send bad CSR to cause the enroll to fail but the login to succeed
	reqNet := &api.EnrollmentRequestNet{}
	reqNet.SignRequest.Request = "badcsr"
	body, err := util.Marshal(reqNet, "SignRequest")
	assert.NoError(t, err, "Failed to marshal enroll request")

	// Send the CSR to the fabric-ca server with basic auth header
	post, err := client.newPost("enroll", body)
	assert.NoError(t, err, "Failed to create post request")
	post.SetBasicAuth("admin", "adminpw")
	err = client.SendReq(post, nil)
	if assert.Error(t, err, "Should have failed due to bad csr") {
		assert.Contains(t, err.Error(), "CSR Decode failed")
	}

	// State should not have gotten updated because the enrollment failed
	userInfo, err = registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	if userInfo.(*DBUser).State != 1 {
		t.Error("Incorrect state set for user")
	}

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

}

func cleanTestSlateSE(t *testing.T) {
	err := os.RemoveAll(rootDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll("../testdata/msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}

// Reenroll is not supported for an Idemix type credential.
// If the identity only posses an Idemix credential, it should
// not be able to reenroll. If an identity has both x509 and Idmex
// credential than reenroll should be allowed.
func TestReenrollIdemixCred(t *testing.T) {
	var err error
	srvHome := "serverHome"
	clientHome := "clientHome"
	ctport1 := 7098

	srv := TestGetServer(ctport1, srvHome, "", 5, t)

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")
	defer srv.Stop()
	defer os.RemoveAll(srvHome)
	defer os.RemoveAll(clientHome)

	req := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		Type:   "idemix",
	}

	client := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", ctport1)},
		HomeDir: clientHome,
	}

	cainfo, err := client.GetCAInfo(&api.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("Failed to get CA info: %s", err)
	}
	err = util.WriteFile(filepath.Join(clientHome, "msp/IssuerPublicKey"), cainfo.IssuerPublicKey, 0644)
	if err != nil {
		t.Fatalf("Failed to store CA's idemix public key: %s", err)
	}

	idemixEnrollRes, err := client.Enroll(req)
	assert.NoError(t, err, "Idemix enroll should not have failed with valid userid/password")

	_, err = idemixEnrollRes.Identity.Reenroll(&api.ReenrollmentRequest{})
	assert.Error(t, err, "Identity with only Idemix crdential should not be able to reenroll")

	req.Type = "" // Use default type: x509
	x509EnrollRes, err := client.Enroll(req)
	assert.NoError(t, err, "x509 enroll should not have failed with valid userid/password")

	_, err = x509EnrollRes.Identity.Reenroll(&api.ReenrollmentRequest{})
	assert.NoError(t, err, "Failed to enroll identity with both x509 and Idemix credential")
}
