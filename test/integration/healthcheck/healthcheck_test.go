/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package healthcheck

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/hyperledger/fabric-ca/integration/runner"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-lib-go/healthz"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheck(t *testing.T) {
	server := lib.TestGetRootServer(t)
	defer server.Stop()

	server.Config.Operations.ListenAddress = "127.0.0.1:7055"

	err := server.Start()
	assert.NoError(t, err)

	c := &http.Client{}
	healthURL := "http://127.0.0.1:7055/healthz"

	respCode, healthStatus := DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusOK, respCode)
	assert.Equal(t, "OK", healthStatus.Status)

	err = server.GetDB().Close()
	assert.NoError(t, err)

	respCode, healthStatus = DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusServiceUnavailable, respCode)
	assert.Equal(t, "server", healthStatus.FailedChecks[0].Component)
	assert.Equal(t, "sql: database is closed", healthStatus.FailedChecks[0].Reason)
}

func TestHealthCheckWithPostgres(t *testing.T) {
	server := lib.TestGetRootServer(t)
	defer server.Stop()

	server.Config.Operations.ListenAddress = "127.0.0.1:7055"
	server.CA.Config.DB.Type = "postgres"

	postgresDB := &runner.PostgresDB{}
	err := postgresDB.Start()
	assert.NoError(t, err)
	defer postgresDB.Stop()

	dataSource := fmt.Sprintf("host=%s port=%d user=postgres dbname=postgres sslmode=disable", postgresDB.HostIP, postgresDB.HostPort)
	server.CA.Config.DB.Datasource = dataSource

	err = server.Start()
	assert.NoError(t, err)

	c := &http.Client{}
	healthURL := "http://127.0.0.1:7055/healthz"

	respCode, healthStatus := DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusOK, respCode)
	assert.Equal(t, "OK", healthStatus.Status)

	err = server.GetDB().Close()
	assert.NoError(t, err)

	respCode, healthStatus = DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusServiceUnavailable, respCode)
	assert.Equal(t, "server", healthStatus.FailedChecks[0].Component)
	assert.Equal(t, "sql: database is closed", healthStatus.FailedChecks[0].Reason)
}

func TestHealthCheckWithMySQL(t *testing.T) {
	server := lib.TestGetRootServer(t)
	defer server.Stop()

	server.Config.Operations.ListenAddress = "127.0.0.1:7055"
	server.CA.Config.DB.Type = "mysql"

	mysql := &runner.MySQL{}

	err := mysql.Start()
	assert.NoError(t, err)
	defer mysql.Stop()

	connStr := fmt.Sprintf("root:@(%s:%d)/mysql", mysql.HostIP, mysql.HostPort)
	server.CA.Config.DB.Datasource = connStr

	err = server.Start()
	assert.NoError(t, err)

	c := &http.Client{}
	healthURL := "http://127.0.0.1:7055/healthz"

	respCode, healthStatus := DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusOK, respCode)
	assert.Equal(t, "OK", healthStatus.Status)

	err = server.GetDB().Close()
	assert.NoError(t, err)

	respCode, healthStatus = DoHealthCheck(t, c, healthURL)
	assert.Equal(t, http.StatusServiceUnavailable, respCode)
	assert.Equal(t, "server", healthStatus.FailedChecks[0].Component)
	assert.Equal(t, "sql: database is closed", healthStatus.FailedChecks[0].Reason)
}

func DoHealthCheck(t *testing.T, client *http.Client, url string) (int, healthz.HealthStatus) {
	resp, err := client.Get(url)
	assert.NoError(t, err)

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	resp.Body.Close()

	var healthStatus healthz.HealthStatus
	err = json.Unmarshal(bodyBytes, &healthStatus)
	assert.NoError(t, err)

	return resp.StatusCode, healthStatus
}
