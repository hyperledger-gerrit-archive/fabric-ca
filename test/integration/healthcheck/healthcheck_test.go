/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package healthcheck

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/server/operations"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheckEndpoint(t *testing.T) {
	server := operations.NewSystem(operations.Options{ListenAddress: "127.0.0.1:0"})

	err := server.Start()
	assert.NoError(t, err)

	_, port, err := net.SplitHostPort(server.Addr())
	assert.NoError(t, err)

	healthURL := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	client := &http.Client{}

	resp, err := client.Get(healthURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = server.Stop()
	assert.NoError(t, err)

	errMsg := fmt.Sprintf(
		"Get http://127.0.0.1:%s/healthz: dial tcp 127.0.0.1:%s: connect: connection refused",
		port, port)

	resp, err = client.Get(healthURL)
	assert.Nil(t, resp)
	assert.Equal(t, errMsg, err.Error())
}
