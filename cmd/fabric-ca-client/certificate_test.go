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

	"time"

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

func TestBadRunListCertificate(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d:15d",
	}
	err := certCmd.runListCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Invalid format for expiration, use '::'", "Should have failed")
}

func TestBadExpirationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d:15d",
	}
	err := certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid format for expiration, use '::'", "Should have failed")
}

func TestGoodExpirationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d::15d",
	}
	err := certCmd.getCertListReq()
	assert.NoError(t, err, "Failed to parse properly formated expiration time range")
}

func TestBadRevocationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Revocation: "30d:15d",
	}
	err := certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid format for revocation, use '::'", "Should have failed")
}

func TestGoodRevocationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Revocation: "30d::15d",
	}
	err := certCmd.getCertListReq()
	assert.NoError(t, err, "Failed to parse properly formated revocation time range")
}

func TestTimeRangeWithNow(t *testing.T) {
	timeNow := time.Now().UTC().Format(time.RFC3339)
	timeStr := getTime("now")
	assert.Equal(t, timeNow, timeStr)
}

// Integration Tests

func TestListCertificateCmdNegative(t *testing.T) {
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

	// Test with --revocation flag
	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::+15y"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, invalid duration type (y)")

	// Test with --expiration flag
	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "+30m::+15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, invalid duration type (m)")

}

func TestListCertificateCmdPositive(t *testing.T) {
	os.RemoveAll(testdataDir)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer stopAndCleanupServer(t, srv)

	// Enroll a user that will be used for subsequent certificate commands
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = RunMain([]string{cmdName, "reenroll", "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = RunMain([]string{cmdName, "certificate", "list", "-d"})
	assert.NoError(t, err, "Failed to get certificates")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d::+15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d::-15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "now::+15d"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now'")

	err = RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-15d::now"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now'")
}
