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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// Unit Tests
func TestNewCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := newCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
}

func TestAddCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := newCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
	addCmd := addCertificateCommand(certCmd)
	assert.NotNil(t, addCmd)
}

func TestCreateCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := createCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
}

func TestBadPreRunCertificate(t *testing.T) {
	mockBadClientCmd := new(mocks.Command)
	mockBadClientCmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to initialize config", "Should have failed")
}

func TestGoodPreRunCertificate(t *testing.T) {
	mockGoodClientCmd := new(mocks.Command)
	mockGoodClientCmd.On("ConfigInit").Return(nil)
	mockGoodClientCmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	cmd := newCertificateCommand(mockGoodClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	assert.NoError(t, err, "Should not have failed")
}

func TestFailLoadIdentity(t *testing.T) {
	mockBadClientCmd := new(mocks.Command)
	mockBadClientCmd.On("LoadMyIdentity").Return(nil, errors.New("Failed to load identity"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.runListCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to load identity", "Should have failed")
}

// Integration Tests
func TestListCertificateCmd(t *testing.T) {
	os.RemoveAll(testdataDir)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer stopAndCleanupServer(t, srv)

	// Remove default client home location to remove any existing enrollment information
	os.RemoveAll(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")))

	// Command should fail if caller has not yet enrolled
	err = RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Enrollment information does not exist", "Should have failed to call command, if caller has not yet enrolled")

	// Enroll a user that will be used for subsequent certificate commands
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Not Implemented", "Should fail, not yet implemented")
}
