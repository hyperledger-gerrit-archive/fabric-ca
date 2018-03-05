/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cmd "github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	serverDir  = "testCertificates"
	serverPort = 7090
	cmdName    = "fabric-ca-client"
)

var (
	enrollURL = fmt.Sprintf("http://admin:adminpw@localhost:%d", serverPort)
)

func TestMain(m *testing.M) {
	metadata.Version = "1.1.0"
	os.Exit(m.Run())
}

func TestListCertificateCmd(t *testing.T) {
	os.RemoveAll(serverDir)

	srv := lib.TestGetServer(serverPort, serverDir, "", -1, t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer lib.StopAndCleanupServer(t, srv)

	// Remove default client home location to remove any existing enrollment information
	os.RemoveAll(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")))

	// Command should fail if caller has not yet enrolled
	err = cmd.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Enrollment information does not exist", "Should have failed to call command, if caller has not yet enrolled")

	// Enroll a user that will be used for subsequent certificate commands
	err = cmd.RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = cmd.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Not Implemented", "Should fail, not yet implemented")
}
