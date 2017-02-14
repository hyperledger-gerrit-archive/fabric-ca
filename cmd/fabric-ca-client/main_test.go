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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml = "test.yaml"
	myhost   = "hostname"
	certfile = "../../testdata/ec.pem"
	keyfile  = "../../testdata/ec-key.pem"
	tdDir    = "../../testdata"
	db       = "fabric-ca-server.db"
)

var (
	defYaml    string
	fabricCADB = path.Join(tdDir, db)
	rrFile     = path.Join(tdDir, "registerrequest.json")
)

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml)

	fabricCAServerURL := "http://localhost:7058"

	err := RunMain([]string{cmdName, "enroll", "-u", fabricCAServerURL, "-m", myhost})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	fileBytes, err := ioutil.ReadFile(defYaml)
	if err != nil {
		t.Error(err)
	}

	configFile := string(fileBytes)

	if !strings.Contains(configFile, fabricCAServerURL) {
		t.Error("Failed to update default config file with url")
	}

	if !strings.Contains(configFile, myhost) {
		t.Error("Failed to update default config file with host name")
	}

	os.Remove(defYaml)

}

func TestClientCommandsNoTLS(t *testing.T) {
	os.Remove(db)

	srv := getServer()

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["bank_a"] = "banks"

	srv.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testEnroll(t)
	testReenroll(t)
	testRegister(t)
	testRevoke(t)
	testBogus(t)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func getServer() *lib.Server {
	return &lib.Server{
		HomeDir: ".",
		Config:  getServerConfig(),
	}
}

func getServerConfig() *lib.ServerConfig {
	return &lib.ServerConfig{
		Debug: true,
		Port:  7054,
		CA: lib.ServerConfigCA{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		CSR: csr.CertificateRequest{
			CN: "TestCN",
		},
	}
}

// TestEnroll tests fabric-ca-client enroll
func testEnroll(t *testing.T) {
	t.Log("Testing Enroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.RemoveAll(defYaml) // Clean up any left over config file

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin:adminpw@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://admin2:adminpw2@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	os.Remove(defYaml)

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin2:adminpw2@localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestReenroll tests fabric-ca-client reenroll
func testReenroll(t *testing.T) {
	t.Log("Testing Reenroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", "http://localhost:7054"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml})
	if err != nil {
		t.Errorf("client reenroll -c failed: %s", err)
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestRegister tests fabric-ca-client register
func testRegister(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "register", "-c", testYaml})
	if err == nil {
		t.Error("Should have failed, no register request file provided")
	}

	err = RunMain([]string{cmdName, "register", "-f", rrFile})
	if err != nil {
		t.Errorf("client register -f failed: %s", err)
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "register", "--url", "http://localhost:7055", "-f", rrFile})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestRevoke tests fabric-ca-client revoke
func testRevoke(t *testing.T) {
	t.Log("Testing Revoke CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Delete default config file

	err := RunMain([]string{cmdName, "revoke"})
	if err == nil {
		t.Errorf("No enrollment ID or serial/aki provided, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "admin"})
	if err != nil {
		t.Errorf("client revoke -u -e failed: %s", err)
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")

	}

	os.RemoveAll(filepath.Dir(defYaml))
	os.Remove(testYaml)
}

// TestBogus tests a negative test case
func testBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("client bogus passed but should have failed")
	}
}

func TestClientCommandsTLS(t *testing.T) {
	os.Remove(db)

	dir, err := ioutil.TempDir("", "clientCMD")
	if err != nil {
		t.Errorf("Failed to create temp directory: %s", err)
	}

	srv := getServer()

	srv.Config.Debug = true
	os.Setenv("FABRIC_CA_ENROLLMENT_DIR", dir)

	err = srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "../../testdata/tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "../../testdata/tls_server-key.pem"

	aff := make(map[string]interface{})
	aff["bank_a"] = "banks"

	srv.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", "../../testdata/fabric-ca-client-config.yaml", "-u", "https://admin:adminpw@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	os.RemoveAll(dir)

}

func TestCleanUp(t *testing.T) {
	os.Remove("cert.pem")
	os.Remove("key.pem")
	os.Remove(db)
}
