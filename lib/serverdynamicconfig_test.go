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
	"os"
	"strconv"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/stretchr/testify/assert"
)

func TestUpdatingConfig(t *testing.T) {
	os.RemoveAll(rootDir)
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll("../testdata/msp")

	var err error
	srv := TestGetRootServer(t)

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	client := getTestClient(rootPort)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	admin := resp.Identity
	err = admin.UpdateServerConfig(&api.UpdateConfigRequest{
		List: true,
	})
	if assert.Error(t, err, "Error should have occured, list is not yet supported") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrUpdateConfig))
	}

	err = admin.UpdateServerConfig(&api.UpdateConfigRequest{
		Add: []string{"foo:bar"},
	})
	if assert.Error(t, err, "Error should have occured, add is not yet supported") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrUpdateConfig))
	}

	err = admin.UpdateServerConfig(&api.UpdateConfigRequest{
		Remove: []string{"foo:bar"},
	})
	if assert.Error(t, err, "Error should have occured, remove is not yet supported") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrUpdateConfig))
	}

	err = admin.UpdateServerConfig(&api.UpdateConfigRequest{
		Modify: []string{"foo:bar"},
	})
	if assert.Error(t, err, "Error should have occured, modify is not yet supported") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrUpdateConfig))
	}

	testPermissions(admin, client, t)

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

}

func testPermissions(admin *Identity, client *Client, t *testing.T) {
	// Register a user that does not posses the attributes to modify server's config, should result in an authorization error
	regResp, err := admin.Register(&api.RegistrationRequest{
		Name: "testuser",
	})
	assert.NoError(t, err, "Failed to register user 'testuser'")

	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "testuser",
		Secret: regResp.Secret,
	})
	assert.NoError(t, err, "Failed to enroll 'testuser' user")

	nonadmin := resp.Identity
	err = nonadmin.UpdateServerConfig(&api.UpdateConfigRequest{
		List: true,
	})
	if assert.Error(t, err, "Error should have occured, invoker does not have proper attributes to modify server config") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrUpdateConfigAuth))
	}
}
