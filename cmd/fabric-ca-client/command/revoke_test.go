/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
)

func TestRunIdemixRevokeInputError(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	rCmd := newRevokeCmd(cmd)
	err := rCmd.runIdemixRevoke(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Enrollment ID and/or Revocation Handle are required to revoke Idemix credential", "Should have failed")
}

func TestRevokeIdemixError(t *testing.T) {
	cmd := new(mocks.Command)
	rCmd := newRevokeCmd(cmd)
	revoke := new(mocks.Revoke)
	revoke.On("RevokeIdemix", &api.IdemixRevocationRequest{}).Return(nil, errors.New("Failed to revoke idemix credential"))
	_, err := rCmd.revokeIdemix(revoke)
	util.ErrorContains(t, err, "Failed to revoke idemix credential", "Should have failed")
}

func TestRevokeIdemixPass(t *testing.T) {
	cmd := new(mocks.Command)
	rCmd := newRevokeCmd(cmd)
	revoke := new(mocks.Revoke)
	revoke.On("RevokeIdemix", &api.IdemixRevocationRequest{}).Return(&api.IdemixRevocationResponse{}, nil)
	_, err := rCmd.revokeIdemix(revoke)
	assert.NoError(t, err)
}

type mockGoodIdentity struct{}

func (g *mockGoodIdentity) RevokeIdemix(*api.IdemixRevocationRequest) (*api.IdemixRevocationResponse, error) {
	return &api.IdemixRevocationResponse{}, nil
}
