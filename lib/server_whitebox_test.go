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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/gorilla/mux"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/server/metrics"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

const (
	serverPort      = 7060
	affiliationName = "org1"
)

// TestGetAffliation checks if there is one record for the
// affilition 'org1' in the database after starting the server
// two times. This test is to make sure server does not create
// duplicate affiliations in the database every time it is
// started.
func TestGetAffliation(t *testing.T) {
	defer func() {
		err := os.RemoveAll("../testdata/ca-cert.pem")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/fabric-ca-server.db")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()
	// Start the server at an available port (using port 0 will make OS to
	// pick an available port)
	srv := getServer(serverPort, testdataDir, "", -1, t)

	err := srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	err = srv.Stop()
	if err != nil {
		t.Fatalf("Server stop failed: %v", err)
	}

	err = srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	defer func() {
		err = srv.Stop()
		if err != nil {
			t.Errorf("Failed to stop server: %s", err)
		}
	}()

	afs := []AffiliationRecord{}
	err = srv.db.Select(&afs, srv.db.Rebind(getAffiliationQuery), affiliationName)
	t.Logf("Retrieved %+v for the affiliation %s", afs, affiliationName)
	if err != nil {
		t.Fatalf("Failed to get affiliation %s: %v", affiliationName, err)
	}
	if len(afs) != 1 {
		t.Fatalf("Found 0 or more than one record for the affiliation %s in the database, expected 1 record", affiliationName)
	}
}

func TestServerLogLevel(t *testing.T) {
	var err error

	srv := TestGetRootServer(t)
	srv.Config.Debug = false
	srv.Config.LogLevel = "info"
	err = srv.Init(false)
	util.FatalError(t, err, "Failed to init server with 'info' log level")
	assert.Equal(t, log.Level, log.LevelInfo)

	srv.Config.LogLevel = "Debug"
	err = srv.Init(false)
	util.FatalError(t, err, "Failed to init server 'debug' log level")
	assert.Equal(t, log.Level, log.LevelDebug)

	srv.Config.LogLevel = "warning"
	err = srv.Init(false)
	util.FatalError(t, err, "Failed to init server with 'warning' log level")
	assert.Equal(t, log.Level, log.LevelWarning)

	srv.Config.LogLevel = "critical"
	err = srv.Init(false)
	util.FatalError(t, err, "Failed to init server with 'critical' log level")
	assert.Equal(t, log.Level, log.LevelCritical)

	srv.Config.LogLevel = "fatal"
	err = srv.Init(false)
	util.FatalError(t, err, "Failed to init server with 'fatal' log level")
	assert.Equal(t, log.Level, log.LevelFatal)

	srv.Config.Debug = true
	err = srv.Init(false)
	assert.Error(t, err, "Should fail, can't specify a log level and set debug true at same time")
}

func TestServerMetrics(t *testing.T) {
	gt := NewGomegaWithT(t)

	se := &serverEndpoint{
		Path: "/test",
	}

	router := mux.NewRouter()
	router.Handle(se.Path, se).Name(se.Path)

	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	fakeHist := &metricsfakes.Histogram{}
	fakeHist.WithReturns(fakeHist)
	server := &Server{
		CA: CA{
			Config: &CAConfig{
				CA: CAInfo{
					Name: "ca1",
				},
			},
		},
		Metrics: metrics.Metrics{
			APICounter:  fakeCounter,
			APIDuration: fakeHist,
		},
		mux: router,
	}

	server.mux.Use(server.middleware)
	se.Server = server

	req, err := http.NewRequest("GET", "/test", nil)
	gt.Expect(err).NotTo(HaveOccurred())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	gt.Expect(fakeCounter.AddCallCount()).To(Equal(1))
	gt.Expect(fakeCounter.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeCounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test", "status_code", "405"}))

	gt.Expect(fakeHist.ObserveCallCount()).To(Equal(1))
	gt.Expect(fakeHist.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeHist.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test", "status_code", "405"}))
}

func TestServerHealthCheck(t *testing.T) {
	srv := TestGetRootServer(t)

	os.Mkdir("./.tmpDir", 0755)

	dataSource := "./.tmpDir/sqlite.db"
	srv.CA.Config.DB.Datasource = dataSource
	defer os.RemoveAll("./.tmpDir")

	db, err := sqlx.Open("sqlite3", dataSource)
	assert.NoError(t, err)

	srv.CA.db = &dbutil.DB{DB: db, IsDBInitialized: false}

	err = srv.HealthCheck(context.Background())
	assert.NoError(t, err)

	err = srv.db.Close()
	assert.NoError(t, err)

	err = srv.HealthCheck(context.Background())
	assert.EqualError(t, err, "sql: database is closed")
}
