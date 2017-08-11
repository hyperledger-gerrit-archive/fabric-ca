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

package lib_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	libtls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	rootPort         = 7075
	rootDir          = "rootDir"
	intermediatePort = 7076
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
	pportEnvVar      = "FABRIC_CA_SERVER_PROFILE_PORT"
)

func TestSRVServerInit(t *testing.T) {
	server := TestGetRootServer(t)
	if server == nil {
		return
	}

	err := server.Init(false)
	if err != nil {
		t.Errorf("First server init failed")
	}
	err = server.Init(false)
	if err != nil {
		t.Errorf("Second server init failed")
	}
	err = server.Init(true)
	if err != nil {
		t.Errorf("Third Server init renew failed: %s", err)
	}
	// Verify that the duration of the newly created certificate is 15 years
	d, err := util.GetCertificateDurationFromFile(path.Join(rootDir, "ca-cert.pem"))
	assert.NoError(t, err)
	assert.True(t, d.Hours() == 131400, fmt.Sprintf("Expecting 131400 but found %f", d.Hours()))

	server.Config.CAcfg.CA.Certfile = "../testdata/ec.pem"
	server.Config.CAcfg.CA.Keyfile = "../testdata/ec-key.pem"
	err = server.Init(false)
	if err != nil {
		t.Errorf("Server init with known key/cert files failed: %s", err)
	}
	server.Config.CAcfg.CA.Certfile = ""
	server.Config.CAcfg.CA.Keyfile = ""
	err = server.Init(false)
	if err != nil {
		t.Errorf("Server init with known key/cert files failed: %s", err)
	}

	// Fail case - cannot get home directory
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd")
	}
	td, err := ioutil.TempDir(testdataDir, "ServerInitStat")
	if err != nil {
		t.Fatalf("failed to get tmp dir")
	}
	server.HomeDir = ""
	os.Chdir(td)

	fileInfo, err := os.Stat(".")
	if err != nil {
		t.Fatalf("os.Stat failed on current dir")
	}
	oldmode := fileInfo.Mode()
	curd, err := os.Getwd()
	t.Logf("Current dir: %s", fileInfo.Name())
	t.Logf("Current curd: %v", curd)
	err = os.Chmod(".", 0000)
	if err != nil {
		t.Fatalf("Chmod on %s failed", fileInfo.Name())
	}

	err = server.Init(false)
	t.Logf("Server.Init error: %v", err)
	if err == nil {
		t.Errorf("Server init should have failed (permission error)")
	}

	os.Chdir("..")
	_ = os.Chmod(td, oldmode)
	server.HomeDir = ""
	defer os.RemoveAll(td)
	os.Chdir(wd)
}

func TestSRVRootServer(t *testing.T) {
	var err error
	var admin, user1 *Identity
	var rr *api.RegistrationResponse
	var recs []CertRecord

	// Start the server
	server := TestGetRootServer(t)
	if server == nil {
		return
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	err = server.Start()
	t.Logf("Starting duplicate CA server: %s", err)
	if err == nil {
		t.Fatalf("Server start should have failed")
	}
	defer server.Stop()
	// Enroll request
	client := getRootClient()
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin = eresp.Identity
	// test registration permissions wrt roles and affiliation
	testRegistration(admin, t)
	// Register user1
	rr, err = admin.Register(&api.RegistrationRequest{
		Name:        "user1",
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
		Attributes:  []api.Attribute{api.Attribute{Name: "attr1", Value: "val1"}},
	})
	if err != nil {
		t.Fatalf("Failed to register user1: %s", err)
	}
	// Enroll user1
	eresp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: rr.Secret,
	})
	if err != nil {
		t.Fatalf("Failed to enroll user1: %s", err)
	}
	user1 = eresp.Identity
	// The admin ID should have 1 cert in the DB now
	dba := server.CA.CertDBAccessor()
	recs, err = dba.GetCertificatesByID("admin")
	if err != nil {
		t.Errorf("Could not get admin's certs from DB: %s", err)
	}
	if len(recs) != 1 {
		t.Errorf("Admin should have 1 cert in DB but found %d", len(recs))
	}
	_, err = dba.GetUnexpiredCertificates()
	if err != nil {
		t.Errorf("Failed to get unexpired certificates: %s", err)
	}
	dba = &CertDBAccessor{}
	_, err = dba.RevokeCertificatesByID("", 0)
	if err == nil {
		t.Error("dba.RevokeCertificatesByID on empty accessor should have failed")
	}
	var cr certdb.CertificateRecord
	err = dba.InsertCertificate(cr)
	if err == nil {
		t.Error("dba.InsertCertificate on empty accessor should have failed")
	}
	// User1 should not be allowed to register
	user2Registration := &api.RegistrationRequest{
		Name:        "user2",
		Type:        "user",
		Affiliation: "hyperledger.fabric-ca",
	}
	_, err = user1.Register(user2Registration)
	if err == nil {
		t.Error("User1 should have failed to register user2")
	}
	// Admin should be allowed to register user2
	_, err = admin.Register(user2Registration)
	if err != nil {
		t.Errorf("Admin failed to register user2: %s", err)
	}
	// User1 renew
	eresp, err = user1.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Fatalf("Failed to reenroll user1: %s", err)
	}
	user1 = eresp.Identity
	// User1 should not be allowed to revoke admin
	err = user1.Revoke(&api.RevocationRequest{Name: "admin"})
	if err == nil {
		t.Error("User1 should not be allowed to revoke admin")
	}
	// User1 should not be allowed to revoke user2 because of affiliation
	err = user1.Revoke(&api.RevocationRequest{Name: "user2"})
	if err == nil {
		t.Error("User1 should not be allowed to revoke user2 because of affiliation")
	}
	// User1 get's batch of tcerts
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1, AttrNames: []string{"attr1"}})
	if err != nil {
		t.Fatalf("Failed to get tcerts for user1: %s", err)
	}
	// User1 get's batch of tcerts with attributes
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		t.Fatalf("Failed to get tcerts for user1: %s", err)
	}
	// Admin should not be allowed to revoke an invalid cert
	err = admin.Revoke(&api.RevocationRequest{AKI: "foo", Serial: "bar"})
	if err == nil {
		t.Error("Admin should have failed to revoke foo/bar")
	}
	// Revoke user1's identity
	err = admin.Revoke(&api.RevocationRequest{Name: "user1"})
	if err != nil {
		t.Fatalf("Failed to revoke user1's identity: %s", err)
	}
	// User1 should not be allowed to get tcerts now that it is revoked
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err == nil {
		t.Errorf("User1 should have failed to get tcerts since it is revoked")
	}

	// Test to make sure that if an identity registered with an
	// attribute 'hf.Revoker=false' should not be able to make a
	// successfull revocation request
	secret, err := admin.Register(&api.RegistrationRequest{
		Name:        "user3",
		Type:        "user",
		Affiliation: "hyperledger.fabric-ca",
		Attributes:  makeAttrs(t, "hf.Revoker=false"),
	})
	assert.NoError(t, err, "Failed to register user")
	eresp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user3",
		Secret: secret.Secret,
	})
	assert.NoError(t, err, "Failed to enroll user2")
	user3 := eresp.Identity
	// User3 should not be allowed to revoke because of attribute 'hf.Revoker=false'
	err = user3.Revoke(&api.RevocationRequest{Name: "admin"})
	assert.Error(t, err)
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

// Test passwords with lowercase "e" to make sure it is stored
// correctly in the database with no conversion problems.
// See https://jira.hyperledger.org/projects/FAB/issues/FAB-5188
func TestSRVSpecialPassword(t *testing.T) {

	user := "admin2"
	pwd := "034e220796"

	// Start the server
	server := TestGetRootServer(t)
	if server == nil {
		return
	}
	err := server.RegisterBootstrapUser(user, pwd, "")
	if err != nil {
		t.Fatalf("Failed to register %s: %s", user, err)
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	defer server.Stop()
	// Enroll request
	client := getRootClient()
	_, err = client.Enroll(&api.EnrollmentRequest{Name: user, Secret: pwd})
	if err != nil {
		t.Fatalf("Failed to enroll %s: %s", user, err)
	}
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

// TestProfiling tests if profiling endpoint can be accessed when profiling is
// enabled and not accessible when disabled (default)
func TestSRVProfiling(t *testing.T) {
	t.Log("start TestProfiling")
	pport := rootPort + 1000
	url := fmt.Sprintf("http://localhost:%d/debug/pprof/heap", pport)

	// Start the server with profiling disabled
	os.Setenv(pportEnvVar, strconv.Itoa(-1))
	server := TestGetServer(rootPort, rootDir, "", -1, t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	resp1, err2 := sendGetReq(url, t)
	// send heap profiling request to the server and expect a bad response
	// as profiling is disabled
	if err2 == nil && resp1.StatusCode == 200 {
		responseData, _ := ioutil.ReadAll(resp1.Body)
		t.Errorf("Expected error response for profile request %s but got good response: %s",
			url, responseData)
	}
	server.Stop()

	// Start the server with profiling enabled but port set to server port
	os.Setenv(pportEnvVar, strconv.Itoa(rootPort))
	server = TestGetServer(rootPort, rootDir, "", -1, t)
	if server == nil {
		return
	}
	err = server.Start()
	if err == nil {
		t.Fatalf("Server should not have started because of port conflict")
	}

	// Start the server with profiling enabled
	os.Setenv(pportEnvVar, strconv.Itoa(pport))
	defer os.Unsetenv(pportEnvVar)
	server = TestGetServer(rootPort, rootDir, "", -1, t)
	if server == nil {
		return
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	defer server.Stop()

	// send heap profiling request to the server and expect a 200 response
	// as profiling is enabled
	resp, err1 := sendGetReq(url, t)
	if err1 != nil || resp.StatusCode != 200 {
		if err1 == nil {
			responseData, _ := ioutil.ReadAll(resp.Body)
			err1 = fmt.Errorf("Invalid response %s with code %d returned for the request %s",
				string(responseData), resp.StatusCode, url)
		}
		t.Errorf("Failed to send request to %s: %s", url, err1)
	}
}

// sendGetReq sends GET request to the specified URL
func sendGetReq(url string, t *testing.T) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("Failed to create request for url %s: %s", url, err)
	}
	var tr = new(http.Transport)
	httpClient := &http.Client{Transport: tr}
	return httpClient.Do(req)
}

func TestSRVIntermediateServerWithFalseAttr(t *testing.T) {
	var err error

	// Start the root server
	rootServer := TestGetRootServer(t)
	if rootServer == nil {
		return
	}
	rootServer.CA.Config.Registry.Identities[0].Attrs["hf.IntermediateCA"] = "false"
	err = rootServer.Start()
	if !assert.NoError(t, err, "Server failed start") {
		assert.FailNow(t, err.Error())
	}

	intermediateServer := TestGetIntermediateServer(0, t)
	if intermediateServer == nil {
		return
	}

	err = intermediateServer.Init(false)
	if assert.Error(t, err, "Should have failed, the attribute 'hf.IntermediateCA' is not set to true. Cannot register as Intermediate CA") {
		assert.Contains(t, err.Error(), "is not set to true")
	}

	err = rootServer.Stop()
	if err != nil {
		t.Errorf("Root server stop failed: %s", err)
	}

}

func TestSRVIntermediateServer(t *testing.T) {
	var err error

	// Start the root server
	rootServer := TestGetRootServer(t)
	if rootServer == nil {
		return
	}
	err = rootServer.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}
	defer func() {
		err = rootServer.Stop()
		if err != nil {
			t.Errorf("Root server stop failed: %s", err)
		}
	}()

	for idx := 0; idx < 3; idx++ {
		testIntermediateServer(idx, t)
	}
}

func TestSRVIntermediateServerWithTLS(t *testing.T) {
	var err error

	rootServer := TestGetRootServer(t)
	if rootServer == nil {
		return
	}
	rootServer.Config.TLS.Enabled = true
	rootServer.Config.TLS.CertFile = "../../testdata/tls_server-cert.pem"
	rootServer.Config.TLS.KeyFile = "../../testdata/tls_server-key.pem"
	rootServer.Config.TLS.ClientAuth.Type = "RequireAndVerifyClientCert"
	rootServer.Config.TLS.ClientAuth.CertFiles = []string{"../../testdata/root.pem"}

	//Invalid Authtype
	rootServer.Config.TLS.ClientAuth.Type = "Token"
	err = rootServer.Start()
	t.Logf("rootServer.Start err %v", err)
	if err == nil {
		t.Fatal("Root server start should have failed: (invalid authtype)")
	}
	defer func() {
		err = rootServer.Stop()
		if err != nil {
			t.Errorf("Root server stop failed: %s", err)
		}
	}()

	//Valid authtype
	rootServer.Config.TLS.ClientAuth.Type = "RequireAndVerifyClientCert"
	err = rootServer.Start()
	t.Logf("rootServer.Start err %v", err)
	if err != nil {
		t.Fatal("Root server start failed")
	}
	parentURL := fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort)
	intermediateServer := TestGetServer(intermediatePort, intermediateDir, parentURL, -1, t)
	if intermediateServer == nil {
		return
	}
	intermediateServer.CA.Config.Intermediate.TLS.Client.CertFile = "../../testdata/tls_client-cert.pem"
	intermediateServer.CA.Config.Intermediate.TLS.Client.KeyFile = "../../testdata/tls_client-key.pem"
	intermediateServer.CA.Config.CSR.CN = "intermediateServer"

	// Error case 1: CN specified for intermediate server
	err = intermediateServer.Start()
	if err == nil {
		t.Errorf("CN specified for intermediate server, the server should have failed to start")
	}

	intermediateServer.CA.Config.CSR.CN = ""
	intermediateServer.CA.Config.CSR.Hosts = []string{"testhost"}

	// Error case 2: tls.certfiles not specified for intermediate server while connecting to parent CA server over TLS
	err = intermediateServer.Start()
	if err == nil {
		t.Errorf("Certfiles not specified for the Intermediate server, the server should have failed to start")
	}

	// Success case
	intermediateServer.CA.Config.Intermediate.TLS.CertFiles = []string{"../../testdata/root.pem"}
	err = intermediateServer.Start()
	if err != nil {
		t.Errorf("Intermediate server start failed: %s", err)
	}
	time.Sleep(time.Second)

	err = intermediateServer.Stop()
	if err != nil {
		t.Errorf("Intermediate server stop failed: %s", err)
	}

	// Make sure that the hostname was not inserted into the CA certificate
	err = util.CheckHostsInCert(filepath.Join(intermediateDir, "ca-cert.pem"), "testhost")
	if err == nil {
		t.Error("A CA certificate should not have any hostnames")
	}

}

func TestSRVRunningTLSServer(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)

	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "../testdata/tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "../testdata/tls_server-key.pem"

	err := srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: libtls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
			Client: libtls.KeyCertFiles{
				KeyFile:  "../testdata/tls_client-key.pem",
				CertFile: "../testdata/tls_client-cert.pem",
			},
		},
	}

	rawURL := fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort)

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll over TLS: %s", err)
	}

	// make sure only TLS 1.2 is supported
	rootPool := x509.NewCertPool()
	rootBytes, _ := ioutil.ReadFile("../testdata/root.pem")
	rootPool.AppendCertsFromPEM(rootBytes)
	_, err = tls.Dial("tcp", fmt.Sprintf("localhost:%d", rootPort), &tls.Config{
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	assert.NoError(t, err, "Should have connected using TLS 1.2")
	for _, tlsVersion := range []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11} {
		_, err = tls.Dial("tcp", fmt.Sprintf("localhost:%d", rootPort), &tls.Config{
			MinVersion: tlsVersion,
			MaxVersion: tlsVersion,
		})
		t.Logf("Attempting TLS version [%d]", tlsVersion)
		assert.Error(t, err, "Should not have been able to connect with TLS version < 1.2")
		assert.Contains(t, err.Error(), "protocol version not supported")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestSRVDefaultDatabase(t *testing.T) {
	TestSRVServerClean(t)

	srv := TestGetServer(rootPort, testdataDir, "", -1, t)

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	exist := util.FileExists("../testdata/fabric-ca-server.db")
	if !exist {
		t.Error("Failed to create default sqlite fabric-ca-server.db")
	}
}

func TestSRVDefaultAddrPort(t *testing.T) {
	TestSRVServerClean(t)

	srv := getServer(rootPort, testdataDir, "", -1, t)
	srv.Config.Address = ""
	srv.Config.Port = 0
	err := srv.Start()
	t.Logf("srv.Start err: %v", err)
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	// Start server with default port (already in use)
	srv = getServer(rootPort, testdataDir, "", -1, t)
	srv.Config.Address = ""
	srv.Config.Port = 0
	err = srv.Start()
	t.Logf("srv.Start err: %v", err)
	if err == nil {
		t.Errorf("Root server start should have failed (port unavailable)")
	}

	// Again with TLS
	srv = getServer(rootPort, testdataDir, "", -1, t)
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "../testdata/tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "../testdata/tls_server-key.pem"
	srv.Config.TLS.ClientAuth.Type = "RequireAndVerifyClientCert"
	srv.Config.TLS.ClientAuth.CertFiles = []string{"../testdata/root.pem"}
	srv.Config.Address = ""
	srv.Config.Port = 0

	err = srv.Start()
	t.Logf("srv.Start err: %v", err)
	if err == nil {
		t.Errorf("Root server start should have failed (port unavailable)")
	}
}

func TestSRVBadAuthHeader(t *testing.T) {
	// Start the server
	server := TestGetRootServer(t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}

	invalidTokenAuthorization(t)
	invalidBasicAuthorization(t)
	perEndpointNegativeTests("info", "none", t)
	perEndpointNegativeTests("enroll", "basic", t)
	perEndpointNegativeTests("reenroll", "token", t)
	perEndpointNegativeTests("register", "token", t)
	perEndpointNegativeTests("tcert", "token", t)

	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

}

func invalidTokenAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)
	url := fmt.Sprintf("http://localhost:%d/enroll", rootPort)
	req, err := http.NewRequest("POST", url, bytes.NewReader(emptyByte))
	if err != nil {
		t.Errorf("Failed creating new request: %s", err)
	}

	addTokenAuthHeader(req, t)

	err = client.SendReq(req, nil)
	if err == nil {
		t.Error("Incorrect auth type set, request should have failed with authorization error")
	}
}

func addTokenAuthHeader(req *http.Request, t *testing.T) {
	CSP := factory.GetDefault()
	cert, err := ioutil.ReadFile("../testdata/ec.pem")
	if err != nil {
		t.Fatalf("Failed reading ec.pem: %s", err)
	}
	key, err := util.ImportBCCSPKeyFromPEM("../testdata/ec-key.pem", CSP, true)
	if err != nil {
		t.Fatalf("Failed importing key %s", err)
	}
	emptyByte := make([]byte, 0)
	token, err := util.CreateToken(CSP, cert, key, emptyByte)
	if err != nil {
		t.Fatalf("Failed to add token authorization header: %s", err)
	}
	req.Header.Set("authorization", token)
}

func perEndpointNegativeTests(endpoint string, authType string, t *testing.T) {
	client := getRootClient()
	emptyByte := make([]byte, 0)
	turl := fmt.Sprintf("http://localhost:7055/%s?ca=bogus", endpoint)
	req, err := http.NewRequest("POST", turl, bytes.NewReader(emptyByte))
	if err != nil {
		t.Fatalf("Failed in NewRequest with %s", turl)
	}
	err = client.SendReq(req, nil)
	if err == nil {
		if authType != "" {
			t.Fatalf("No authorization header; should have failed for %s", turl)
		} else {
			t.Fatalf("Bad CA should have failed for %s", turl)
		}
	}
	switch authType {
	case "none":
	case "basic":
		req.SetBasicAuth("admin", "adminpw")
	case "token":
		addTokenAuthHeader(req, t)
	default:
		t.Fatalf("Invalid auth type: %s", authType)
	}
	err = client.SendReq(req, nil)
	if err == nil {
		t.Errorf("Invalid CA should have failed for %s", turl)
	}
}

func invalidBasicAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)
	url := fmt.Sprintf("http://localhost:%d/register", rootPort)
	req, err := http.NewRequest("POST", url, bytes.NewReader(emptyByte))
	if err != nil {
		t.Error(err)
	}

	req.SetBasicAuth("admin", "adminpw")

	err = client.SendReq(req, nil)
	if err == nil {
		t.Error("Incorrect auth type set for register request; it should have failed but passed")
	}
}

func TestSRVTLSAuthClient(t *testing.T) {
	TestSRVServerClean(t)
	testNoClientCert(t)
	testInvalidRootCertWithNoClientAuth(t)
	testInvalidRootCertWithClientAuth(t)
	testClientAuth(t)
}

func TestSRVMultiCAConfigs(t *testing.T) {
	t.Log("TestMultiCA...")

	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv.Config.CAfiles = []string{"ca/ca1/fabric-ca-server-config.yaml", "ca/ca1/fabric-ca-server-config.yaml", "ca/ca2/fabric-ca-server-config.yaml"}

	srv.CA.Config.CSR.Hosts = []string{"hostname"}
	t.Logf("Server configuration: %+v", srv.Config)

	// Starting server with two cas with same name
	err := srv.Start()
	t.Logf("Start two CAs with the same name: %v", err)
	if err == nil {
		t.Error("Trying to create two CAs with the same name, server start should have failed")
	}

	// Starting server with a missing ca config file
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml", "ca/rootca/ca4/fabric-ca-server-config.yaml"}
	err = srv.Start()
	t.Logf("Start CA with missing config: %v", err)
	if err == nil {
		t.Error("Should have failed to start server, missing ca config file")
	}

	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml", "ca/rootca/ca3/fabric-ca-server-config.yaml"}
	err = srv.Start()
	t.Logf("Starting 3 CAs with a duplicated CN name: %s", err)
	if err == nil {
		t.Error("Should have failed to start server, CN name is the same across rootca2 and rootca3")
	}

	// Starting server with (bad) existing certificate
	err = ioutil.WriteFile("../testdata/ca/rootca/ca1/ca-key.pem", make([]byte, 1), 0644)
	t.Logf("Create err: %v", err)
	if !util.FileExists("../testdata/ca/rootca/ca1/ca-key.pem") {
		t.Fatal("../testdata/ca1/ca-key.pem doesn't exist")
	}
	err = ioutil.WriteFile("../testdata/ca/rootca/ca1/ca-cert.pem", make([]byte, 1), 0644)
	t.Logf("Create err: %v", err)
	if !util.FileExists("../testdata/ca/rootca/ca1/ca-cert.pem") {
		t.Fatal("../testdata/ca1/ca-cert.pem doesn't exist")
	}
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml"}
	err = srv.Start()
	t.Logf("srv.Start ERROR %v", err)
	if err == nil {
		t.Error("Should have failed to start server, invalid cert")
	}

	// Starting server with unreadable certificate
	if err = os.Chmod("../testdata/ca/rootca/ca1/ca-key.pem", 0000); err != nil {
		t.Errorf("Failed to chmod file: ../testdata/ca1/ca-key.pem, %v", err)
	}
	if err = os.Chmod("../testdata/ca/rootca/ca1/ca-cert.pem", 0000); err != nil {
		t.Errorf("Failed to chmod file: ../testdata/ca/rootca/ca1/ca-cert.pem, %v", err)
	}
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml"}
	err = srv.Start()
	t.Logf("srv.Start ERROR %v", err)
	if err == nil {
		t.Error("Should have failed to start server, unreadable cert")
	}
	err = os.Remove("../testdata/ca/rootca/ca1/ca-key.pem")
	err = os.Remove("../testdata/ca/rootca/ca1/ca-cert.pem")

	testBadCryptoData(t, srv, []string{"../testdata/expiredcert.pem", "../testdata/tls_client-key.pem", "expired cert"})
	testBadCryptoData(t, srv, []string{"../testdata/noKeyUsage.cert.pem", "../testdata/noKeyUsage.key.pem", "invalid usage cert"})
	testBadCryptoData(t, srv, []string{"../testdata/caFalse.cert.pem", "../testdata/caFalse.key.pem", "invalid Basic Constraints"})
	testBadCryptoData(t, srv, []string{"../testdata/dsaCa-cert.pem", "../testdata/dsaCa-key.pem", "invalid key type"})
	testBadCryptoData(t, srv, []string{"../testdata/dsaCa-cert.pem", "../testdata/dsaCa-key.pem", "invalid key type"})
	testBadCryptoData(t, srv, []string{"../testdata/rsa512-cert.pem", "../testdata/rsa512-key.pem", "key too short"})
	testBadCryptoData(t, srv, []string{"../testdata/ec256-1-cert.pem", "../testdata/ec256-2-key.pem", "non-matching ecdsa key"})
	testBadCryptoData(t, srv, []string{"../testdata/rsa2048-1-cert.pem", "../testdata/rsa2048-2-key.pem", "non-matching rsa key"})
	testBadCryptoData(t, srv, []string{"../testdata/ec256-1-cert.pem", "../testdata/rsa2048-1-cert.pem", "non-matching key type"})

	// Starting server with correct configuration
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml"}
	t.Logf("Server configuration: %+v\n\n", srv.Config)

	err = srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	if !util.FileExists("../testdata/ca/rootca/ca1/fabric-ca-server.db") {
		t.Error("Failed to correctly add ca1")
	}

	if !util.FileExists("../testdata/ca/rootca/ca2/fabric-ca2-server.db") {
		t.Error("Failed to correctly add ca2")
	}

	// Non-existent CA specified by client
	clientCA := getRootClient()
	_, err = clientCA.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CAName: "rootca3",
	})
	if err == nil {
		t.Error("Should have failed, client using ca name of 'ca3' but no CA exist by that name on server")
	}

	//Send enroll request to specific CA
	clientCA1 := getRootClient()
	_, err = clientCA1.Enroll(&api.EnrollmentRequest{
		Name:   "adminca1",
		Secret: "adminca1pw",
		CAName: "rootca1",
	})
	if err != nil {
		t.Error("Failed to enroll, error: ", err)
	}

	clientCA2 := getRootClient()
	resp, err := clientCA2.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CAName: "rootca2",
	})
	if err != nil {
		t.Error("Failed to enroll, error: ", err)
	}

	_, err = resp.Identity.Reenroll(&api.ReenrollmentRequest{
		CAName: "rootca2",
	})
	if err != nil {
		t.Error("Failed to reenroll, error: ", err)
	}

	// User enrolled with rootca2, should not be able to reenroll with rootca1
	_, err = resp.Identity.Reenroll(&api.ReenrollmentRequest{
		CAName: "rootca1",
	})
	if err == nil {
		t.Error("Should have failed to reenroll a user with a different CA")
	}

	// No ca name specified should sent to default CA 'ca'
	clientCA3 := getRootClient()
	_, err = clientCA3.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Error("Failed to enroll, error: ", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Error("Failed to stop server:", err)
	}

	// Starting server with correct configuration and pre-existing cert/key
	err = os.Remove("../testdata/ca/rootca/ca1/ca-key.pem")
	err = os.Remove("../testdata/ca/rootca/ca1/ca-cert.pem")
	srv = getServer(rootPort, testdataDir, "", 0, t)
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml"}
	t.Logf("Server configuration: %+v\n\n", srv.Config)

	err = os.Link("../testdata/ec256-1-cert.pem", "../testdata/ca/rootca/ca1/ca-cert.pem")
	if err != nil {
		t.Errorf("symlink ec256-1 cert to ../testdata/ca1/ca-cert.pem failed %v", err)
	}
	err = os.Link("../testdata/ec256-1-key.pem", "../testdata/ca/rootca/ca1/ca-key.pem")
	if err != nil {
		t.Errorf("symlink key to ../testdata/ca/rootca/ca1/ca-key.pem failed %v", err)
	}

	err = srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Error("Failed to stop server:", err)
	}

	cleanMultiCADir()

}

func TestSRVDefaultCAWithSetCAName(t *testing.T) {
	srv := getServer(rootPort, testdataDir, "", -1, t)
	srv.CA.Config.CA.Name = "DefaultCA"

	err := srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	// No ca name specified should sent to default CA 'ca'
	client := getRootClient()
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Error("Failed to enroll, error: ", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Error("Failed to stop server:", err)
	}
}

func TestSRVMultiCAWithIntermediate(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml"}
	srv.CA.Config.CSR.Hosts = []string{"hostname"}
	t.Logf("Server configuration: %+v\n", srv.Config)

	// Starting server with two cas with same name
	err := srv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	intermediatesrv := TestGetServer(intermediatePort, testdataDir, "", -1, t)
	intermediatesrv.Config.CAfiles = []string{"ca/intermediateca/ca1/fabric-ca-server-config.yaml", "ca/intermediateca/ca2/fabric-ca-server-config.yaml"}
	intermediatesrv.CA.Config.CSR.Hosts = []string{"hostname"}

	// Start it
	err = intermediatesrv.Start()
	if err != nil {
		t.Errorf("Failed to start intermediate server: %s", err)
	}
	// Stop it
	err = intermediatesrv.Stop()
	if err != nil {
		t.Error("Failed to stop intermediate server: ", err)
	}

	if !util.FileExists("../testdata/ca/intermediateca/ca1/ca-chain.pem") {
		t.Error("Failed to enroll intermediate ca")
	}

	err = srv.Stop()
	if err != nil {
		t.Error("Failed to stop server: ", err)
	}

	// Make sure there is no host name in the intermediate CA cert
	err = util.CheckHostsInCert(filepath.Join("../testdata/ca/intermediateca/ca1", "ca-cert.pem"), "testhost1")
	if err == nil {
		t.Error("Intermediate CA should not contain a hostname, but does")
	}
}

func TestSRVDefaultMultiCA(t *testing.T) {
	t.Log("TestDefaultMultiCA...")
	srv := TestGetServer(rootPort, "multica", "", -1, t)
	srv.Config.CAcount = 4 // Starting 4 default CA instances
	srv.Config.CAfiles = []string{"fabric-ca1-config.yaml"}

	err := srv.Start()
	if err == nil {
		t.Error("Both cacount and cafiles set, should have failed to start server")
	}

	srv.Config.CAfiles = []string{}

	err = srv.Start()
	if err != nil {
		t.Error("Failed to start server: ", err)
	}

	//Send enroll request to specific CA
	clientCA1 := getRootClient()
	_, err = clientCA1.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CAName: "ca4",
	})
	if err != nil {
		t.Error("Failed to enroll, error: ", err)
	}

	if srv.DBAccessor() == nil {
		t.Error("No registry found")
	}

	err = srv.Stop()
	if err != nil {
		t.Error("Failed to stop server: ", err)
	}
}

// Test the combination of multiple CAs in both root and intermediate servers.
func TestSRVMultiCAIntermediates(t *testing.T) {
	myTestDir := "multicaIntermediates"
	os.RemoveAll(myTestDir)
	defer os.RemoveAll(myTestDir)
	// Start the root server with 2 non-default CAs
	rootServer := TestGetServer(rootPort, path.Join(myTestDir, "root"), "", -1, t)
	rootServer.Config.CAcount = 2
	err := rootServer.Start()
	if err != nil {
		t.Fatalf("Failed to start root CA: %s", err)
	}
	home := path.Join(myTestDir, "intermediate")
	parentURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)
	intServer := TestGetServer(0, home, parentURL, -1, t)
	intServer.Config.CAfiles = []string{"ca1/ca1.yaml", "ca2/ca2.yaml"}
	ca1home := filepath.Join(home, "ca1")
	ca2home := filepath.Join(home, "ca2")

	// Negative Case - same CA name from two intermediate CAs sent to the same root CA
	// Check that CA file paths are getting printed
	// Create ca1.yaml and ca2.yaml for the intermediate server CAs
	writeCAFile("ca1", "ca1", "ca1", ca1home, rootPort, t)
	writeCAFile("ca1", "ca2", "ca2", ca2home, rootPort, t)
	err = intServer.Init(false)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), ca1home)
		assert.Contains(t, err.Error(), ca2home)
	}
	err = rootServer.Stop()
	if err != nil {
		t.Error("Failed to stop server: ", err)
	}

	os.RemoveAll(myTestDir)

	// Negative Case - same subject distinguished name from two intermediate CAs sent to the same root CA
	// Create ca1.yaml and ca2.yaml for the intermediate server CAs
	rootServer = TestGetServer(rootPort, path.Join(myTestDir, "root"), "", -1, t) // reset server from last run above
	rootServer.Config.CAcount = 2
	err = rootServer.Start()
	if err != nil {
		t.Fatalf("Failed to start root CA: %s", err)
	}
	writeCAFile("ca1", "ca1", "ca1", ca1home, rootPort, t)
	writeCAFile("ca2", "ca1", "ca2", ca2home, rootPort, t)
	err = intServer.Init(false)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "Both issuer and subject distinguished name are already in use")
	}
	err = rootServer.Stop()
	if err != nil {
		t.Error("Failed to stop server: ", err)
	}
	os.RemoveAll(myTestDir)

	// Positive Case - same subject distinguished names from two intermediate CAs sent to two different root CAs
	rootServer = TestGetServer(rootPort, path.Join(myTestDir, "root"), "", -1, t) // reset server from last run above
	rootServer.Config.CAcount = 2
	err = rootServer.Start()
	if err != nil {
		t.Fatalf("Failed to start root CA: %s", err)
	}
	writeCAFile("ca1", "ca1", "ca1", ca1home, rootPort, t)
	writeCAFile("ca2", "ca2", "ca2", ca2home, rootPort, t)
	// Init the intermediate server
	err = intServer.Init(false)
	if err != nil {
		t.Fatalf("Failed to initialize intermediate server: %s", err)
	}
	err = rootServer.Stop()
	if err != nil {
		t.Error("Failed to stop server: ", err)
	}
}

func TestSRVMaxEnrollmentInfinite(t *testing.T) {
	os.RemoveAll(rootDir)
	t.Log("Test max enrollment infinite")
	// Starting server/ca with infinite enrollments
	srv := TestGetServer(rootPort, rootDir, "", -1, t)
	err := srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	client := getRootClient()
	id, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Error("Enrollment failed, error: ", err)
	}
	id.Identity.Store()
	// Names of users are of the form:
	//    me_<client's max enrollment setting>_<server's max enrollment setting>
	// where "me" stands for "max enrollments"

	// Registering user with missing max enrollment value
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:        "me_missing_-1",
		Type:        "client",
		Affiliation: "org2",
	})
	if err != nil {
		t.Errorf("Failed to register me_missing_-1, error: %s", err)
	}

	// Registering user with infinite max enrollments (-1)
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_-1_-1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: -1,
	})
	if err != nil {
		t.Errorf("Failed to register me_-1_-1, error: %s", err)
	}

	// Registering user with zero max enrollments, will take value of CA's max enrollment
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_0_-1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 0,
	})
	if err != nil {
		t.Errorf("Failed to register me_0_-1, error: %s", err)
	}

	// Registering user with 1000 max enrollments
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_1000_-1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 1000,
	})
	if err != nil {
		t.Errorf("Failed to register me_1000_-1, error: %s", err)
	}
	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
	os.RemoveAll(rootDir)
}

func TestSRVMaxEnrollmentDisabled(t *testing.T) {
	os.RemoveAll(rootDir)
	t.Log("Test max enrollment disabled")
	// Starting server/ca with infinite enrollments
	srv := TestGetServer(rootPort, rootDir, "", -1, t)
	err := srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	client := getRootClient()
	id, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Errorf("Enrollment failed: %s", err)
	}
	// Disable enrollment
	srv.CA.Config.Registry.MaxEnrollments = 0
	// Make sure both registration and enrollment fail
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:        "me_0_0",
		Type:        "client",
		Affiliation: "org2",
	})
	if err == nil {
		t.Error("Registration should have failed but didn't")
	}
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err == nil {
		t.Error("Enrollment should have failed but didn't")
	}
	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
	os.RemoveAll(rootDir)
}

func TestSRVMaxEnrollmentLimited(t *testing.T) {
	os.RemoveAll(rootDir)
	t.Log("Test max enrollment limited")
	// Starting server/ca with max enrollments of 1
	srv := TestGetServer(rootPort, rootDir, "", 1, t)
	err := srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	client := getRootClient()
	id, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Error("Enrollment failed, error: ", err)
	}
	id.Identity.Store()
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err == nil {
		t.Error("Enrollments should have been limited to 1 but allowed 2")
	}
	// Registering user with missing max enrollment value
	// Names of users are of the form:
	//    me_<client's max enrollment setting>_<server's max enrollment setting>
	// where "me" stands for "max enrollments"
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_-1_1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: -1,
	})
	if err == nil {
		t.Error("Should have failed to register infinite but didn't")
	}
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_0_1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 0,
	})
	if err != nil {
		t.Errorf("Failed to register me_0_1, error: %s", err)
	}
	user, err := srv.CA.DBAccessor().GetUserInfo("me_0_1")
	if err != nil {
		t.Errorf("Failed to find user 'me_0_1,' in database")
	}
	if user.MaxEnrollments != 1 {
		t.Error("Failed to correctly set max enrollment value for a user registering with max enrollment of 0")
	}
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_1_1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 1,
	})
	if err != nil {
		t.Errorf("Failed to register me_1_1, error: %s", err)
	}
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_2_1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 2,
	})
	if err == nil {
		t.Error("Should have failed to register me_2_1 but didn't")
	}
	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
	os.RemoveAll(rootDir)
}

// Get certificate using the TLS profile on the server to retrieve a certificate to be used for TLS connection
func TestTLSCertIssuance(t *testing.T) {
	testDir := "tlsTestDir"
	os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)
	srv := TestGetServer(rootPort, testDir, "", -1, t)
	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}
	defer srv.Stop()
	client := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", rootPort)},
		HomeDir: testDir,
	}
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:    "admin",
		Secret:  "adminpw",
		Profile: "tls",
		CSR:     &api.CSRInfo{Hosts: []string{"localhost"}},
	})
	if err != nil {
		t.Fatalf("Failed to enroll: %s", err)
	}
	tlsCertBytes := eresp.Identity.GetECert().Cert()
	cert, err := util.GetX509CertificateFromPEM(tlsCertBytes)
	if err != nil {
		t.Fatalf("Failed to get certificate: %s", err)
	}
	// Check if the certificate has correct key usages
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 || cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
		t.Fatal("Certificate does not have correct extended key usage. Should have Digital Signature, Key Encipherment, and Key Agreement")
	}
	// Check if the certificate has correct extended key usages
	clientAuth := false
	serverAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !clientAuth || !serverAuth {
		t.Fatal("Certificate does not have correct extended key usage. Should have ExtKeyUsageServerAuth and ExtKeyUsageClientAuth")
	}
	err = srv.Stop()
	if err != nil {
		t.Fatalf("Server stop failed: %s", err)
	}
	// Write the TLS certificate to disk
	os.MkdirAll(testDir, 0755)
	tlsCertFile := path.Join(testDir, "tls-cert.pem")
	err = util.WriteFile(tlsCertFile, tlsCertBytes, 0644)
	if err != nil {
		t.Fatalf("Failed to write TLS certificate file: %s", err)
	}
	// Get a new server with TLS enabled
	srv = TestGetServer2(false, rootPort, testDir, "", -1, t)
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "tls-cert.pem"
	// Start the server
	err = srv.Start()
	if err != nil {
		t.Fatalf("TLS server start failed: %s", err)
	}
	// Connect to the server over TLS
	cfg := &ClientConfig{URL: fmt.Sprintf("https://localhost:%d", rootPort)}
	cfg.TLS.Enabled = true
	cfg.TLS.CertFiles = []string{"ca-cert.pem"}
	client = &Client{Config: cfg, HomeDir: testDir}
	eresp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Fatalf("Failed to enroll over TLS: %s", err)
	}
	err = srv.Stop()
	if err != nil {
		t.Fatalf("Stop of TLS server failed: %s", err)
	}
}

// Configure server to start server with no client authentication required
func testNoClientCert(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv = getTLSConfig(srv, "NoClientCert", []string{})

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: libtls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
		},
	}

	rawURL := fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort)

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll over TLS with no client authentication required: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

// Configure server to start with no client authentication required
// Root2.pem does not exists, server should still start because no client auth is requred
func testInvalidRootCertWithNoClientAuth(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv = getTLSConfig(srv, "NoClientCert", []string{"../testdata/root.pem", "../testdata/root2.pem"})

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

// Configure server to start with client authentication required
// Root2.pem does not exists, server should fail to start
func testInvalidRootCertWithClientAuth(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv = getTLSConfig(srv, "RequireAndVerifyClientCert", []string{"../testdata/root.pem", "../testdata/root2.pem"})

	err := srv.Start()
	if err == nil {
		t.Error("Root2.pem does not exists, server should have failed to start")
	}
}

// Configure server to start with client authentication required
func testClientAuth(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv = getTLSConfig(srv, "RequireAndVerifyClientCert", []string{"../testdata/root.pem"})

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: libtls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
		},
	}

	rawURL := fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort)

	// Enrolling without any client certificate and key information set
	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err == nil {
		t.Errorf("Client Auth Type: RequireAndVerifyClientCert, should have failed as no client cert was provided")
	}

	// Client created with certificate and key for TLS
	clientConfig = &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: libtls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
			Client: libtls.KeyCertFiles{
				KeyFile:  "../testdata/tls_client-key.pem",
				CertFile: "../testdata/tls_client-cert.pem",
			},
		},
	}

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Client Auth Type: RequireAndVerifyClientCert, failed to enroll over TLS with client certificate provided")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func testIntermediateServer(idx int, t *testing.T) {
	// Init the intermediate server
	intermediateServer := TestGetIntermediateServer(idx, t)
	if intermediateServer == nil {
		return
	}
	err := intermediateServer.Init(true)
	if err != nil {
		t.Fatalf("Intermediate server init failed: %s", err)
	}
	// Verify that the duration of the newly created intermediate certificate is 5 years
	d, err := util.GetCertificateDurationFromFile(path.Join(intermediateServer.HomeDir, "ca-cert.pem"))
	assert.NoError(t, err)
	assert.True(t, d.Hours() == 43800, fmt.Sprintf("Expecting 43800 but found %f", d.Hours()))
	// Start it
	err = intermediateServer.Start()
	if err != nil {
		t.Fatalf("Intermediate server start failed: %s", err)
	}
	// Test enroll against intermediate (covering basic auth)
	c := getTestClient(intermediateServer.Config.Port)
	resp, err := c.Enroll(&api.EnrollmentRequest{Name: "admin", Secret: "adminpw"})
	if err != nil {
		t.Fatalf("Failed to enroll with intermediate server: %s", err)
	}
	// Test reenroll against intermediate (covering token auth)
	_, err = resp.Identity.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Fatalf("Failed to reenroll with intermediate server: %s", err)
	}
	// Stop it
	intermediateServer.Stop()
}

func TestUnmarshalConfig(t *testing.T) {
	cfg := &ServerConfig{}
	cfgFile := "../testdata/testviperunmarshal.yaml"
	err := UnmarshalConfig(cfg, viper.GetViper(), cfgFile, true, true)
	if err != nil {
		t.Errorf("UnmarshalConfig workaround=true failed: %s", err)
	}
	err = UnmarshalConfig(cfg, viper.GetViper(), cfgFile, true, false)
	if err != nil {
		t.Errorf("UnmarshalConfig workaround=false failed: %s", err)
	}
	err = UnmarshalConfig(cfg, viper.GetViper(), "foo.yaml", true, false)
	if err == nil {
		t.Error("UnmarshalConfig invalid file passed but should have failed")
	}
}

// TestSqliteLocking tests to ensure that "database is locked"
// error does not occur when multiple requests are sent at the
// same time.
// This test assumes that sqlite is the database used in the tests
func TestSRVSqliteLocking(t *testing.T) {
	// Start the server
	server := TestGetServer(rootPort, rootDir, "", -1, t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	defer server.Stop()

	// Enroll bootstrap user
	client := getRootClient()
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Fatalf("Failed to enroll bootstrap user: %s", err)
	}
	admin := eresp.Identity
	errs := make(chan error)
	users := 30
	// Register users
	for i := 0; i < users; i++ {
		n := "user" + strconv.Itoa(i)
		go func(admin *Identity, name string) {
			_, err := admin.Register(&api.RegistrationRequest{
				Name:        name,
				Type:        "user",
				Affiliation: "hyperledger.fabric.security",
			})
			errs <- err
		}(admin, n)
	}
	for i := 0; ; {
		err = <-errs
		// Should not see "database is locked" error
		if err != nil && strings.Contains(err.Error(), "database is locked") {
			t.Fatalf("Failed to register: %s", err)
		}
		// If we have heard from all the go routines, break to exit the test
		if i++; i == users {
			break
		}
	}
}

func TestSRVNewUserRegistryMySQL(t *testing.T) {
	datasource := ""

	// Test with no cert files specified
	tlsConfig := &libtls.ClientTLSConfig{
		Enabled: true,
	}
	csp := util.GetDefaultBCCSP()
	_, _, err := dbutil.NewUserRegistryMySQL(datasource, tlsConfig, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No TLS certificate files were provided")

	// Test with with a file that does not exist
	tlsConfig = &libtls.ClientTLSConfig{
		Enabled:   true,
		CertFiles: []string{"doesnotexit.pem"},
	}
	_, _, err = dbutil.NewUserRegistryMySQL(datasource, tlsConfig, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")

	// Test with a file that is not of appropriate format
	tlsConfig = &libtls.ClientTLSConfig{
		Enabled:   true,
		CertFiles: []string{"../testdata/empty.json"},
	}
	_, _, err = dbutil.NewUserRegistryMySQL(datasource, tlsConfig, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to process certificate from file")

	// Test with a file that does not have read permissions
	err = os.Chmod("../testdata/root.pem", 0000)
	if err != nil {
		fmt.Println(err)
	}

	tlsConfig = &libtls.ClientTLSConfig{
		Enabled:   true,
		CertFiles: []string{"../testdata/root.pem"},
	}
	_, _, err = dbutil.NewUserRegistryMySQL(datasource, tlsConfig, csp)
	assert.Error(t, err)
	if err != nil {
		t.Logf("%s", err.Error())
	}
	assert.Contains(t, err.Error(), "denied")

	err = os.Chmod("../testdata/root.pem", 0644)
	if err != nil {
		fmt.Println(err)
	}
}

func TestCSRInputLengthCheck(t *testing.T) {
	t.Log("Testing CSR input length check")
	os.RemoveAll("../testdata/msp/")
	os.RemoveAll(rootDir)
	defer os.RemoveAll("../testdata/msp/")
	defer os.RemoveAll(rootDir)

	server := TestGetServer(rootPort, rootDir, "", -1, t)
	if server == nil {
		return
	}
	longCN := randSeq(65)
	err := server.RegisterBootstrapUser(longCN, "pass", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	defer server.Stop()

	// Passing case: all value are of appropriate length
	client := getRootClient()
	csr1 := api.CSRInfo{
		CN: "test",
		Names: []csr.Name{
			csr.Name{
				C:  "US",
				ST: "North Carolina",
				L:  "Raleigh",
				O:  "Hyperledger",
				OU: "Fabric",
			},
			csr.Name{
				C: "CA",
			},
		},
		SerialNumber: "123abc",
	}
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CSR:    &csr1,
	})
	if err != nil {
		t.Error("Failed to enroll user in passing case: ", err)
	}

	// Failing case: CN is greater than 64 characters
	badCSR := &api.CSRInfo{
		CN: longCN,
	}
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   longCN,
		Secret: "pass",
		CSR:    badCSR,
	})
	if assert.Error(t, err, fmt.Sprint("Number of characters for CN is greater than the maximum limit, should have resulted in an error")) {
		assert.Contains(t, err.Error(), "CN")
	}

	// CSRs that test failing cases for other fields in the CSR
	badCSRs := map[string]*api.CSRInfo{
		"country": &api.CSRInfo{
			Names: []csr.Name{
				csr.Name{
					C: randSeq(3),
				},
			},
		},
		"locality": &api.CSRInfo{
			Names: []csr.Name{
				csr.Name{
					L: randSeq(129),
				},
			},
		},
		"state": &api.CSRInfo{
			Names: []csr.Name{
				csr.Name{
					ST: randSeq(129),
				},
			},
		},
		"organization": &api.CSRInfo{
			Names: []csr.Name{
				csr.Name{
					O: randSeq(65),
				},
			},
		},
		"organizational unit": &api.CSRInfo{
			Names: []csr.Name{
				csr.Name{
					OU: randSeq(65),
				},
			},
		},
		"serial number": &api.CSRInfo{
			SerialNumber: randSeq(65),
		},
	}

	for name, badCSR := range badCSRs {
		_, err = client.Enroll(&api.EnrollmentRequest{
			Name:   "admin",
			Secret: "adminpw",
			CSR:    badCSR,
		})
		if assert.Error(t, err, fmt.Sprintf("Number of characters for '%s' is greater than the maximum limit, should have resulted in an error", name)) {
			assert.Contains(t, err.Error(), name)
		}
	}
}

func TestEnd(t *testing.T) {
	TestSRVServerClean(t)
}

func cleanMultiCADir() {
	caFolder := "../testdata/ca"
	toplevelFolders := []string{"intermediateca", "rootca"}
	nestedFolders := []string{"ca1", "ca2", "ca3"}
	removeFiles := []string{"ca-cert.pem", "ca-key.pem", "fabric-ca-server.db", "fabric-ca2-server.db", "ca-chain.pem"}

	for _, topFolder := range toplevelFolders {
		for _, nestedFolder := range nestedFolders {
			path := filepath.Join(caFolder, topFolder, nestedFolder)
			for _, file := range removeFiles {
				os.Remove(filepath.Join(path, file))
			}
			os.RemoveAll(filepath.Join(path, "msp"))
		}
	}
	os.RemoveAll("../testdata/ca/intermediateca/ca1/msp")
	os.RemoveAll("multica")
}

func getRootServerURL() string {
	return fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)
}

func getRootServer(t *testing.T) *Server {
	return getServer(rootPort, rootDir, "", -1, t)
}

func getIntermediateServer(idx int, t *testing.T) *Server {
	return getServer(
		intermediatePort,
		path.Join(intermediateDir, strconv.Itoa(idx)),
		getRootServerURL(),
		-1,
		t)
}

func getServer(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	if home != testdataDir {
		os.RemoveAll(home)
	}
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2": nil,
	}

	srv := &Server{
		Config: &ServerConfig{
			Port:  port,
			Debug: true,
		},
		CA: CA{
			Config: &CAConfig{
				Intermediate: IntermediateCA{
					ParentServer: ParentServer{
						URL: parentURL,
					},
				},
				Affiliations: affiliations,
				Registry: CAConfigRegistry{
					MaxEnrollments: maxEnroll,
				},
			},
		},
		HomeDir: home,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	// Error case of empty bootstrap data
	err = srv.RegisterBootstrapUser("admin", "", "")
	t.Logf("Empty bootstrap id: %s", err)
	if err == nil {
		t.Errorf("register bootstrap user should have failed")
		return nil
	}
	return srv
}

func getRootClient() *Client {
	return getTestClient(rootPort)
}

func getIntermediateClient() *Client {
	return getTestClient(intermediatePort)
}

func getTestClient(port int) *Client {
	return &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: testdataDir,
	}
}

func getTLSConfig(srv *Server, clientAuthType string, clientRootCerts []string) *Server {
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "../testdata/tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "../testdata/tls_server-key.pem"
	srv.Config.TLS.ClientAuth.Type = clientAuthType
	srv.Config.TLS.ClientAuth.CertFiles = clientRootCerts

	return srv
}

func testRegistration(admin *Identity, t *testing.T) {
	name := "testRegistrationUser1"
	topAffiliation := "hyperledger"
	midAffiliation := "hyperledger.fabric"
	botAffiliation := "hyperledger.fabric.security"
	_, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: midAffiliation,
		Attributes:  makeAttrs(t, "hf.Registrar.Roles=user", "hf.Registrar.DelegateRoles=user,peer"),
	})
	if err == nil {
		t.Error("Should have failed to register delegate roles which exceed roles")
	}
	id1, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: midAffiliation,
		Attributes:  makeAttrs(t, "hf.Registrar.Roles=user,peer", "hf.Registrar.DelegateRoles=user"),
	})
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = id1.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: botAffiliation,
		Attributes:  makeAttrs(t, "hf.Registrar.Roles=peer"),
	})
	if err == nil {
		t.Error("ID1 should not be allowed to delegate peer registration to another identity")
	}
	_, err = id1.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: topAffiliation,
	})
	if err == nil {
		t.Error("ID1 should not be allowed to registrar outside of its affiliation hierarchy")
	}
	name = "testRegistrationUser2"
	id2, err := id1.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: botAffiliation,
	})
	if err != nil {
		t.Fatalf("ID1 failed to register %s: %s", name, err)
	}
	name = "testRegistrationUser3"
	_, err = id2.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: botAffiliation,
	})
	if err == nil {
		t.Error("ID2 should not be allowed to register")
	}
}

func makeAttrs(t *testing.T, args ...string) []api.Attribute {
	attrs := make([]api.Attribute, len(args))
	for idx, attr := range args {
		eles := strings.Split(attr, "=")
		if len(eles) != 2 {
			t.Fatalf("Not two elements in %s", attr)
		}
		attrs[idx].Name = eles[0]
		attrs[idx].Value = eles[1]
	}
	return attrs
}

func writeCAFile(name, parentcaname, filename, home string, port int, t *testing.T) {
	contents := fmt.Sprintf(`
ca:
   name: %s
intermediate:
   parentserver:
      url: http://admin:adminpw@localhost:%d
      caname: %s
`, name, port, parentcaname)
	os.MkdirAll(home, 0755)
	fpath := path.Join(home, fmt.Sprintf("%s.yaml", filename))
	err := ioutil.WriteFile(fpath, []byte(contents), 0644)
	if err != nil {
		t.Fatalf("Failed to create ca1.yaml: %s", err)
	}
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func testBadCryptoData(t *testing.T, s *Server, testData []string) {
	config := []string{"ca/rootca/ca1/fabric-ca-server-config.yaml"}
	sCert := "../testdata/ca/rootca/ca1/ca-cert.pem"
	sKey := "../testdata/ca/rootca/ca1/ca-key.pem"
	// Starting server with expired certificate
	err := os.Link(testData[0], sCert)
	if err != nil {
		t.Errorf("symlink expired cert to %s failed:  %v", testData[0], err)
	}
	err = os.Link(testData[1], sKey)
	if err != nil {
		t.Errorf("symlink key to %s failed:  %v", testData[1], err)
	}
	s.Config.CAfiles = config
	err = s.Start()
	t.Logf("srvStart ERROR %v", err)
	if err == nil {
		t.Errorf("Should have failed to start server, %s", testData[2])
	}
	err = os.Remove(sCert)
	err = os.Remove(sKey)
}

func TestSRVServerClean(t *testing.T) {
	os.Remove("../testdata/ca-cert.pem")
	os.Remove("../testdata/ca-key.pem")
	os.Remove("../testdata/fabric-ca-server.db")
	os.RemoveAll(rootDir)
	os.RemoveAll(intermediateDir)
	os.RemoveAll("multica")
	os.RemoveAll(serversDir)
	os.RemoveAll("../testdata/msp")
	os.RemoveAll("msp")
	os.RemoveAll("../util/msp")
	cleanMultiCADir()
}
