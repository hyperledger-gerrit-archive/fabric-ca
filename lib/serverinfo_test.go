/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetServerVersion(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	metadata.Version = "1.1.0"
	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := TestGetClient(rootPort, testdataDir)
	resp, err := client.GetCAInfo(&api.GetCAInfoRequest{
		CAName: "",
	})
	assert.NoError(t, err, "Failed to get back server info")

	assert.Equal(t, "1.1.0", resp.Version)
}
