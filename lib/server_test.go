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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
)

const (
	rootPort         = 7055
	rootDir          = "rootDir"
	intermediatePort = 7056
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
)

func TestServerInit(t *testing.T) {
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
}

func TestRootServer(t *testing.T) {
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
	// Register user1
	rr, err = admin.Register(&api.RegistrationRequest{
		Name:        "user1",
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
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
	recs, err = server.CertDBAccessor().GetCertificatesByID("admin")
	if err != nil {
		t.Errorf("Could not get admin's certs from DB: %s", err)
	}
	if len(recs) != 1 {
		t.Errorf("Admin should have 1 cert in DB but found %d", len(recs))
	}
	// User1 should not be allowed to register
	_, err = user1.Register(&api.RegistrationRequest{
		Name:        "user2",
		Type:        "user",
		Affiliation: "hyperledger.fabric-ca",
	})
	if err == nil {
		t.Errorf("Failed to register user1: %s", err)
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
		t.Error("User1 should not be be allowed to revoke admin")
	}
	// User1 get's batch of tcerts
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		t.Fatalf("Failed to get tcerts for user1: %s", err)
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

	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestIntermediateServer(t *testing.T) {
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
	defer rootServer.Stop()

	for idx := 0; idx < 3; idx++ {
		testIntermediateServer(idx, t)
	}

	// Stop both servers
	err = rootServer.Stop()
	if err != nil {
		t.Errorf("Root server stop failed: %s", err)
	}
}
func TestRunningTLSServer(t *testing.T) {
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
		TLS: tls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
			Client: tls.KeyCertFiles{
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

	time.Sleep(1 * time.Second)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestDefaultDatabase(t *testing.T) {
	TestEnd(t)

	srv := TestGetServer(rootPort, testdataDir, "", -1, t)

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	time.Sleep(1 * time.Second)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	exist := util.FileExists("../testdata/fabric-ca-server.db")
	if !exist {
		t.Error("Failed to create default sqlite fabric-ca-server.db")
	}
}

func TestBadAuthHeader(t *testing.T) {
	// Start the server
	server := TestGetRootServer(t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}

	time.Sleep(time.Second)

	invalidTokenAuthorization(t)
	invalidBasicAuthorization(t)

	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

}

func invalidTokenAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)

	req, err := http.NewRequest("POST", "http://localhost:7055/enroll", bytes.NewReader(emptyByte))
	if err != nil {
		t.Error(err)
	}

	CSP := factory.GetDefault()

	cert, err := ioutil.ReadFile("../testdata/ec.pem")
	if err != nil {
		t.Error(err)
	}

	key, err := ioutil.ReadFile("../testdata/ec-key.pem")
	if err != nil {
		t.Error(err)
	}

	token, err := util.CreateToken(CSP, cert, key, emptyByte)
	if err != nil {
		t.Errorf("Failed to add token authorization header: %s", err)
	}

	req.Header.Set("authorization", token)

	err = client.SendReq(req, nil)

	if err.Error() != "Error response from server was: Authorization failure" {
		t.Error("Incorrect auth type set, request should have failed with authorization error")
	}
}

func invalidBasicAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)

	req, err := http.NewRequest("POST", "http://localhost:7055/register", bytes.NewReader(emptyByte))
	if err != nil {
		t.Error(err)
	}

	req.SetBasicAuth("admin", "adminpw")

	err = client.SendReq(req, nil)
	if err.Error() != "Error response from server was: Authorization failure" {
		t.Error("Incorrect auth type set, request should have failed with authorization error")
	}
}

func TestTLSAuthClient(t *testing.T) {
	testNoClientCert(t)
	testInvalidRootCertWithNoClientAuth(t)
	testInvalidRootCertWithClientAuth(t)
	testClientAuth(t)
}

func TestMaxEnrollmentInfinite(t *testing.T) {
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
	// Registering user with missing max enrollment value
	// Names of users are of the form:
	//    me_<client's max enrollment setting>_<server's max enrollment setting>
	// where "me" stands for "max enrollments"
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_-1_-1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: -1,
	})
	if err != nil {
		t.Errorf("Failed to register me_-1_-1, error: %s", err)
	}
	_, err = id.Identity.Register(&api.RegistrationRequest{
		Name:           "me_0_-1",
		Type:           "client",
		Affiliation:    "org2",
		MaxEnrollments: 0,
	})
	if err != nil {
		t.Errorf("Failed to register me_0_-1, error: %s", err)
	}
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

func TestMaxEnrollmentDisabled(t *testing.T) {
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
	srv.Config.Registry.MaxEnrollments = 0
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

func TestMaxEnrollmentLimited(t *testing.T) {
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

// Configure server to start server with no client authentication required
func testNoClientCert(t *testing.T) {
	srv := TestGetServer(rootPort, testdataDir, "", -1, t)
	srv = getTLSConfig(srv, "NoClientCert", []string{})

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	time.Sleep(time.Second)

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: tls.ClientTLSConfig{
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

	time.Sleep(time.Second)

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

	time.Sleep(time.Second)

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: tls.ClientTLSConfig{
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
		TLS: tls.ClientTLSConfig{
			CertFiles: []string{"../testdata/root.pem"},
			Client: tls.KeyCertFiles{
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
	// Start it
	err = intermediateServer.Start()
	if err != nil {
		t.Fatalf("Intermediate server start failed: %s", err)
	}
	time.Sleep(time.Second)
	// Stop it
	intermediateServer.Stop()
}

func TestEnd(t *testing.T) {
	os.Remove("../testdata/ca-cert.pem")
	os.Remove("../testdata/ca-key.pem")
	os.Remove("../testdata/fabric-ca-server.db")
	os.RemoveAll("../testdata/msp")
	os.RemoveAll(rootDir)
	os.RemoveAll(intermediateDir)
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
