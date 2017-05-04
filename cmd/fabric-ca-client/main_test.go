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

package main

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml             = "../../testdata/test.yaml"
	mspDir               = "../../testdata/msp"
	myhost               = "hostname"
	certfile             = "ec.pem"
	keyfile              = "ec-key.pem"
	tlsCertFile          = "tls_server-cert.pem"
	tlsKeyFile           = "tls_server-key.pem"
	rootCert             = "root.pem"
	tlsClientCertFile    = "tls_client-cert.pem"
	tlsClientCertExpired = "expiredcert.pem"
	tlsClientKeyFile     = "tls_client-key.pem"
	tdDir                = "../../testdata"
	db                   = "fabric-ca-server.db"
	serverPort           = 7090
	rootCertEnvVar       = "FABRIC_CA_CLIENT_TLS_CERTFILES"
	clientKeyEnvVar      = "FABRIC_CA_CLIENT_TLS_CLIENT_KEYFILE"
	clientCertEnvVar     = "FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE"
)

const jsonConfig = `{
  "URL": "http://localhost:8888",
  "tls": {
    "enabled": false,
    "certfiles": null,
    "client": {
      "certfile": null,
      "keyfile": null
    }
  },
  "csr": {
    "cn": "admin",
    "names": [
      {
        "C": "US",
        "ST": "North Carolina",
        "L": null,
        "O": "Hyperledger",
        "OU": "Fabric"
      }
    ],
    "hosts": [
      "charente"
    ],
    "ca": {
      "pathlen": null,
      "pathlenzero": null,
      "expiry": null
    }
  },
  "id": {
    "name": null,
    "type": null,
    "group": null,
    "attributes": [
      {
        "name": null,
        "value": null
      }
    ]
  },
  "enrollment": {
    "hosts": null,
    "profile": null,
    "label": null
  }
}`

var (
	defYaml       string
	fabricCADB    = path.Join(tdDir, db)
	srv           *lib.Server
	serverURL     = fmt.Sprintf("http://localhost:%d", serverPort)
	enrollURL     = fmt.Sprintf("http://admin:adminpw@localhost:%d", serverPort)
	enrollURL1    = fmt.Sprintf("http://admin2:adminpw2@localhost:%d", serverPort)
	tlsServerURL  = fmt.Sprintf("https://localhost:%d", serverPort)
	tlsEnrollURL  = fmt.Sprintf("https://admin:adminpw@localhost:%d", serverPort)
	tlsEnrollURL1 = fmt.Sprintf("https://admin2:adminpw2@localhost:%d", serverPort)
)

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml)

	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-m", myhost})
	if err == nil {
		t.Errorf("Server is not running, should have errored")
	}

	fileBytes, err := ioutil.ReadFile(defYaml)
	if err != nil {
		t.Error(err)
	}

	configFile := string(fileBytes)

	if !strings.Contains(configFile, "localhost:7090") {
		t.Error("Failed to update default config file with url")
	}

	if !strings.Contains(configFile, myhost) {
		t.Error("Failed to update default config file with host name")
	}

	os.Remove(defYaml)
}

func TestClientCommandsNoTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.HomeDir = tdDir
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "company1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["hyperledger"] = []string{"org1", "org2", "org3"}
	aff["company1"] = []string{}
	aff["company2"] = []string{}

	srv.CA.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testConfigFileTypes(t)
	testGetCACert(t)
	testEnroll(t)
	testProfiling(t)
	testRegisterConfigFile(t)
	testRegisterEnvVar(t)
	testRegisterCommandLine(t)
	testRevoke(t)
	testBogus(t)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func testConfigFileTypes(t *testing.T) {
	t.Log("Testing config file types")

	// Viper supports file types:
	//    yaml, yml, json, hcl, toml, props, prop, properties, so
	// any other file type will result in an error. However, not all
	// these file types are suitable to represent fabric-ca
	// client/server config properties -- for example, props/prop/properties
	// file type
	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", "config/client-config.txt"})
	if err == nil {
		t.Errorf("Enroll command invoked with -c config/client-config.txt should have failed: %v",
			err.Error())
	}

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", "config/client-config.mf"})
	if err == nil {
		t.Errorf("Enroll command invoked with -c config/client-config.mf should have failed: %v",
			err.Error())
	}

	fName := os.TempDir() + "/client-config.json"
	f, err := os.Create(fName)
	if err != nil {
		t.Fatalf("Unable to create json config file: %v", err.Error())
	}
	w := bufio.NewWriter(f)
	nb, err := w.WriteString(jsonConfig)
	if err != nil {
		t.Fatalf("Unable to write to json config file: %v", err.Error())
	}
	t.Logf("Wrote %d bytes to %s", nb, fName)
	w.Flush()

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", fName})
	if err != nil {
		t.Errorf("Enroll command invoked with -c %s failed: %v",
			fName, err.Error())
	}
	os.RemoveAll("./config")
}

// TestGetCACert tests fabric-ca-client getcacert
func testGetCACert(t *testing.T) {
	t.Log("Testing getcacert command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml) // Clean up any left over config file
	os.RemoveAll("msp")

	err := RunMain([]string{cmdName, "getcacert", "-d", "-u", serverURL})
	if err != nil {
		t.Errorf("getcacert failed: %s", err)
	}

	err = RunMain([]string{cmdName, "getcacert", "-d", "-u", "http://localhost:9999"})
	if err == nil {
		t.Error("getcacert with bogus URL should have failed but did not")
	}

	err = RunMain([]string{cmdName, "getcacert", "-d"})
	if err == nil {
		t.Error("getcacert with no URL should have failed but did not")
	}

	err = RunMain([]string{cmdName, "getcacert", "Z"})
	if err == nil {
		t.Error("getcacert called with bogus argument, should have failed")
	}
	os.RemoveAll("cacerts")
	os.RemoveAll("msp")
	os.Remove(defYaml)
}

// TestEnroll tests fabric-ca-client enroll
func testEnroll(t *testing.T) {
	t.Log("Testing Enroll command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Clean up any left over config file

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	testReenroll(t)

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin2:adminpw2@localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}

	err = RunMain([]string{cmdName, "enroll", "Z"})
	if err == nil {
		t.Error("enroll called with bogus argument, should have failed")
	}
	os.Remove(defYaml)
}

// TestReenroll tests fabric-ca-client reenroll
func testReenroll(t *testing.T) {
	t.Log("Testing Reenroll command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", serverURL,
		"--enrollment.hosts", "host1,host2"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-u", serverURL,
		"--enrollment.hosts", "host1,host2", "Z"})
	if err == nil {
		t.Error("reenroll called with bogus argument, should have failed")
	}

	os.Remove(defYaml)
}

// testRegisterConfigFile tests fabric-ca-client register using the config file
func testRegisterConfigFile(t *testing.T) {
	t.Log("Testing Register command using config file")

	err := RunMain([]string{cmdName, "enroll", "-d", "-c",
		"../../testdata/fabric-ca-client-config.yaml", "-u", enrollURL1})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-d", "-c",
		"../../testdata/fabric-ca-client-config.yaml"})
	if err != nil {
		t.Errorf("client register failed using config file: %s", err)
	}
}

// testRegisterEnvVar tests fabric-ca-client register using environment variables
func testRegisterEnvVar(t *testing.T) {
	t.Log("Testing Register command using env variables")

	os.Setenv("FABRIC_CA_CLIENT_HOME", "../../testdata/")
	os.Setenv("FABRIC_CA_CLIENT_ID_NAME", "testRegister2")
	os.Setenv("FABRIC_CA_CLIENT_ID_AFFILIATION", "company1")
	os.Setenv("FABRIC_CA_CLIENT_ID_TYPE", "client")

	err := RunMain([]string{cmdName, "register"})
	if err != nil {
		t.Errorf("client register failed using environment variables: %s", err)
	}

	os.Unsetenv("FABRIC_CA_CLIENT_HOME")
	os.Unsetenv("FABRIC_CA_CLIENT_ID_NAME")
	os.Unsetenv("FABRIC_CA_CLIENT_ID_AFFILIATION")
	os.Unsetenv("FABRIC_CA_CLIENT_TLS_ID_TYPE")
}

// testRegisterCommandLine tests fabric-ca-client register using command line input
func testRegisterCommandLine(t *testing.T) {
	t.Log("Testing Register using command line options")
	os.Setenv("FABRIC_CA_CLIENT_HOME", "../../testdata/")

	err := RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister3",
		"--id.affiliation", "hyperledger.org1", "--id.type", "client", "--id.attr",
		"hf.test=a=b"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister4",
		"--id.affiliation", "company2", "--id.type", "client"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "register", "-u", "http://localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}

	err = RunMain([]string{cmdName, "register", "-u", serverURL, "Y"})
	if err == nil {
		t.Error("register called with bogus argument, should have failed")
	}
	os.Unsetenv("FABRIC_CA_CLIENT_HOME")
}

// TestRevoke tests fabric-ca-client revoke
func testRevoke(t *testing.T) {
	t.Log("Testing Revoke command")
	os.Setenv("FABRIC_CA_CLIENT_HOME", "../../testdata/")

	err := RunMain([]string{cmdName, "revoke"})
	if err == nil {
		t.Errorf("No enrollment ID or serial/aki provided, should have failed")
	}

	serial, aki, err := getSerialAKIByID("admin")
	if err != nil {
		t.Error(err)
	}

	// Revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "nonexistinguser"})
	if err == nil {
		t.Errorf("Non existing user being revoked, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.serial", serial})
	if err == nil {
		t.Errorf("Only serial specified, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.aki", aki})
	if err == nil {
		t.Errorf("Only aki specified, should have failed")
	}

	// revoker's affiliation: company1, revoking affiliation: ""
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.serial", serial, "--revoke.aki", aki})
	if err == nil {
		t.Error("Should have failed, admin2 cannot revoke root affiliation")
	}

	// When serial, aki and enrollment id are specified in a revoke request,
	// fabric ca server returns an error if the serial and aki do not belong
	// to the enrollment ID.
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "blah", "--revoke.serial", serial, "--revoke.aki", aki})
	if err == nil {
		t.Errorf("The Serial and AKI are not associated with the enrollment ID: %s", err)
	}

	// Revoked user's affiliation: hyperledger.org3
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "testRegister3"})
	if err == nil {
		t.Error("Should have failed, admin2 does not have authority revoke")
	}

	// testRegister2's affiliation: company1, revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "testRegister2"})
	if err != nil {
		t.Errorf("Failed to revoke proper affiliation hierarchy, error: %s", err)
	}

	// testRegister4's affiliation: company2, revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister4"})
	if err == nil {
		t.Error("Should have failed have different affiliation path")
	}

	// Enroll admin with root affiliation and test revoking with root
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// testRegister4's affiliation: company2, revoker's affiliation: "" (root)
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "testRegister4"})
	if err != nil {
		t.Errorf("User with root affiliation failed to revoke, error: %s", err)

	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "U"})
	if err == nil {
		t.Error("revoke called with bogus argument, should have failed")

	}
	os.Unsetenv("FABRIC_CA_CLIENT_HOME")
	os.RemoveAll(filepath.Dir(defYaml))
}

// testProfiling tests enablement of fabric CA client heap/cpu profiling
func testProfiling(t *testing.T) {
	t.Log("Testing profiling")
	var testCases = []struct {
		pEnvVal       string
		input         []string
		mProfExpected bool
		cProfExpected bool
	}{
		{"heap", []string{cmdName, "getcacert", "-u", serverURL}, true, false},
		{"cpu", []string{cmdName, "getcacert", "-u", serverURL}, false, true},
		{"", []string{cmdName, "getcacert", "-u", serverURL}, false, false},
		{"foo", []string{cmdName, "getcacert", "-u", serverURL}, false, false},
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = os.Getenv("HOME")
	}
	mfile := wd + "/mem.pprof"
	cfile := wd + "/cpu.pprof"
	for _, testCase := range testCases {
		os.Setenv(fabricCAClientProfileMode, testCase.pEnvVal)
		_ = RunMain(testCase.input)
		_, err := os.Stat(mfile)
		_, err1 := os.Stat(cfile)
		if testCase.cProfExpected && err1 != nil {
			t.Errorf("%s is found. It should not be created when cpu profiling is NOT enabled: %s", cfile, err1)
		}
		if !testCase.cProfExpected && err1 == nil {
			t.Errorf("%s is not found. It should be created when cpu profiling is enabled", cfile)
		}
		if testCase.mProfExpected && err != nil {
			t.Errorf("%s is found. It should not be created when memory profiling is NOT enabled: %s", mfile, err)
		}
		if !testCase.mProfExpected && err == nil {
			t.Errorf("%s is not found. It should be created when memory profiling is enabled", mfile)
		}
		os.Remove(mfile)
		os.Remove(cfile)
		os.Remove(defYaml)
	}
	os.Unsetenv(fabricCAClientProfileMode)
}

// TestBogus tests a negative test case
func testBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("client bogus passed but should have failed")
	}
}

func TestClientCommandsUsingConfigFile(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c",
		"../../testdata/fabric-ca-client-config.yaml", "-u",
		tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestClientCommandsTLSEnvVar(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	os.Setenv(rootCertEnvVar, rootCert)
	os.Setenv(clientKeyEnvVar, tlsClientKeyFile)
	os.Setenv(clientCertEnvVar, tlsClientCertFile)

	err = RunMain([]string{cmdName, "enroll", "-d", "-c", testYaml,
		"-u", tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	os.Unsetenv(rootCertEnvVar)
	os.Unsetenv(clientKeyEnvVar)
	os.Unsetenv(clientCertEnvVar)
}

func TestClientCommandsTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles",
		rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile",
		tlsClientCertFile, "-u", tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles",
		rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile",
		tlsClientCertExpired, "-u", tlsEnrollURL, "-d"})
	if err == nil {
		t.Errorf("Expired certificate used for TLS connection, should have failed")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
	os.Remove(testYaml)
}

func TestMultiCA(t *testing.T) {
	cleanMultiCADir()

	srv = getServer()
	srv.HomeDir = "../../testdata"
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml",
		"ca/rootca/ca2/fabric-ca-server-config.yaml"}
	srv.CA.Config.CSR.Hosts = []string{"hostname"}
	t.Logf("Server configuration: %+v\n", srv.Config)

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.BlockingStart = false
	err = srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	// Test going to default CA if no caname provided in client request
	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", enrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	enrURL := fmt.Sprintf("http://adminca1:adminca1pw@localhost:%d", serverPort)
	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", enrURL, "-d",
		"--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u --caname failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml, "-d", "--caname",
		"rootca1"})
	if err != nil {
		t.Errorf("client reenroll -c --caname failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-c", testYaml, "-d", "--id.name",
		"testuser", "--id.type", "user", "--id.affiliation", "org1", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "-c", testYaml, "-d",
		"--revoke.name", "adminca1", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client revoke failed: %s", err)
	}

	err = RunMain([]string{cmdName, "getcacert", "-u", serverURL, "-c", testYaml, "-d",
		"--caname", "rootca1"})
	if err != nil {
		t.Errorf("client getcacert failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u",
		enrollURL, "-d", "--caname", "rootca2"})
	if err != nil {
		t.Errorf("client enroll failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u",
		enrURL, "-d", "--caname", "rootca3"})
	if err == nil {
		t.Errorf("Should have failed, rootca3 does not exist on server")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestCleanUp(t *testing.T) {
	os.Remove("../../testdata/ca-cert.pem")
	os.Remove("../../testdata/ca-key.pem")
	os.Remove(testYaml)
	os.Remove(fabricCADB)
	os.RemoveAll(mspDir)
	cleanMultiCADir()
}

func cleanMultiCADir() {
	caFolder := "../../testdata/ca/rootca"
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"msp", "ec.pem", "ec-key.pem",
		"fabric-ca-server.db", "fabric-ca2-server.db", "ca-chain.pem"}

	for _, nestedFolder := range nestedFolders {
		path := filepath.Join(caFolder, nestedFolder)
		for _, file := range removeFiles {
			os.RemoveAll(filepath.Join(path, file))
		}
	}
}

func TestRegisterWithoutEnroll(t *testing.T) {
	err := RunMain([]string{cmdName, "register", "-c", testYaml})
	if err == nil {
		t.Errorf("Should have failed, as no enrollment information should exist. Enroll commands needs to be the first command to be executed")
	}
}

// TestProcessAttributes tests processAttributes function
func TestProcessAttributes(t *testing.T) {
	var attrs []api.Attribute
	clientCfg := &lib.ClientConfig{
		ID: api.RegistrationRequest{
			Attr:       "foo=bar",
			Attributes: attrs,
		},
	}
	// This should not result in "index out of range" error
	processAttributes(clientCfg)

	// add an attribute to attributes array and call processAttributes
	clientCfg.ID.Attributes[0] = api.Attribute{
		Name:  "revoker",
		Value: "true",
	}
	processAttributes(clientCfg)
	if clientCfg.ID.Attributes[0].Name != "foo" {
		t.Errorf("Attribute was not correctly added to the attributes array by processAttributes function")
	}
}

func getServer() *lib.Server {
	return &lib.Server{
		HomeDir: ".",
		Config:  getServerConfig(),
		CA: lib.CA{
			Config: getCAConfig(),
		},
	}
}

func getServerConfig() *lib.ServerConfig {
	return &lib.ServerConfig{
		Debug: true,
		Port:  serverPort,
	}
}

func getCAConfig() *lib.CAConfig {
	affiliations := map[string]interface{}{
		"org1": nil,
	}

	return &lib.CAConfig{
		CA: lib.CAInfo{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		Affiliations: affiliations,
		CSR: csr.CertificateRequest{
			CN: "TestCN",
		},
	}
}

func getSerialAKIByID(id string) (serial, aki string, err error) {
	testdb, _, _ := dbutil.NewUserRegistrySQLLite3(srv.CA.Config.DB.Datasource)
	acc := lib.NewCertDBAccessor(testdb)

	certs, err := acc.GetCertificatesByID(id)
	if err != nil {
		return "", "", err
	}

	block, _ := pem.Decode([]byte(certs[0].PEM))
	if block == nil {
		return "", "", errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("Error from x509.ParseCertificate: %s", err)
	}

	serial = util.GetSerialAsHex(x509Cert.SerialNumber)
	aki = hex.EncodeToString(x509Cert.AuthorityKeyId)

	return
}
