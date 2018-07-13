/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestIdemixRevokeInvalidTokenAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", errors.New("bad credentials"))
	ctx.On("IsBasicAuth").Return(false)
	handler := RevokeRequestHandler{Ctx: ctx}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should fail if token auth credentials are invalid")
}

func TestIdemixRevokeBadReqBody(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)
	ctx.On("IsBasicAuth").Return(false)
	handler := RevokeRequestHandler{Ctx: ctx}
	req := api.RevocationRequest{}
	ctx.On("ReadBody", &req).Return(errors.New("Invalid request body"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if reading body fails")
}
func TestIdemixRevokeGetUserError(t *testing.T) {
	ctx, handler, req := setup(nil)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	ctx.On("GetUser", "foo").Return(nil, errors.New("GetUser error"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if ctx.GetUser fails")
}
func TestIdemixRevokeCanRevokeError(t *testing.T) {
	ctx, handler, req := setup(nil)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	var user spi.User
	user = &lib.DBUser{UserInfo: spi.UserInfo{Name: "foo"}}
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(errors.New("User cannot revoke"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if ctx.CanRevoke fails")
}

func TestIdemixRevokeIDError(t *testing.T) {
	ctx, handler, req := setup(nil)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("Revoke").Return(errors.New("Failed to revoke user"))
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if user.Revoke fails")
}

func TestIdemixRevokeIDRevokeCredsError(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	dbaccessor.On("RevokeCredentialsByID", "foo", 1).Return(nil, errors.New("Failed to update credential state in DB"))
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	user.On("Revoke").Return(nil)
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if it fails to revoke credential in DB")
}

func TestIdemixRevokeIDZeroCreds(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	creds := []CredRecord{}
	dbaccessor.On("RevokeCredentialsByID", "foo", 1).Return(creds, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	user.On("Revoke").Return(nil)
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	rhs, err := handler.HandleRequest()
	assert.NoError(t, err, "Idemix revoke should return not error if the user has no credentials to revoke")
	assert.Equal(t, 0, len(rhs))
}

func TestIdemixRevokeID(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	creds := []CredRecord{}
	creds = append(creds, CredRecord{RevocationHandle: "1", ID: "foo"})
	dbaccessor.On("RevokeCredentialsByID", "foo", 1).Return(creds, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	user.On("Revoke").Return(nil)
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	rhs, err := handler.HandleRequest()
	assert.NoError(t, err, "Idemix revoke should return not error")
	assert.Equal(t, 1, len(rhs))
}

func TestIdemixRevokeRHGetCredError(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	dbaccessor.On("GetCredential", "1").Return(nil, errors.New("Cred not found"))
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if specified RH is not found in DB")
}

func TestIdemixRevokeRHGetCredRevoked(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo", Status: "revoked"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if specified RH is already revoked")
}

func TestIdemixRevokeRHGetCredUserNotSame(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo1"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if specified RH belongs to different user")
}

func TestIdemixRevokeRHGetUserError(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	ctx.On("GetUser", "foo").Return(nil, errors.New("user is not found"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if specified RH belongs to unknown user")
}

func TestIdemixRevokeRHCanRevokeError(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(errors.New("Cannot revoke"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if caller cannot revoke a RH")
}

func TestIdemixRevokeRHRevokeCredError(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	dbaccessor.On("RevokeCredential", "1", 1).Return(errors.New("failed to update status in DB"))
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if it fails to upadate cred status to revoked in DB")
}

func TestIdemixRevokeRH(t *testing.T) {
	dbaccessor := new(mocks.CredDBAccessor)
	cred := &CredRecord{RevocationHandle: "1", ID: "foo"}
	dbaccessor.On("GetCredential", "1").Return(cred, nil)
	dbaccessor.On("RevokeCredential", "1", 1).Return(nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("CredDBAccessor").Return(dbaccessor)
	ctx, handler, req := setup(issuer)
	f := getReadRevokeBodyFunc(t, "foo", "1")
	ctx.On("ReadBody", &req).Return(f)
	user := new(mocks.User)
	user.On("GetName").Return("foo")
	ctx.On("GetUser", "foo").Return(user, nil)
	ctx.On("CanRevoke", user).Return(nil)
	rhs, err := handler.HandleRequest()
	assert.NoError(t, err, "Idemix revoke should return not error")
	assert.Equal(t, 1, len(rhs))
}

func TestIdemixRevokeInvalidReq(t *testing.T) {
	ctx, handler, req := setup(nil)
	f := getReadRevokeBodyFunc(t, "", "")
	ctx.On("ReadBody", &req).Return(f)
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix revoke should return error if either user ID or RH are set in the revocation request")
}

func getReadRevokeBodyFunc(t *testing.T, id, rh string) func(body interface{}) error {
	return func(body interface{}) error {
		revokeReq, _ := body.(*api.RevocationRequest)
		revokeReq.Name = id
		if rh != "" {
			revokeReq.IdemixRH = "1"
		}
		revokeReq.Reason = "keycompromise"
		return nil
	}
}

func setup(issuer *mocks.MyIssuer) (*mocks.ServerRequestCtx, RevokeRequestHandler, api.RevocationRequest) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)
	ctx.On("IsBasicAuth").Return(false)
	handler := RevokeRequestHandler{Ctx: ctx}
	if issuer != nil {
		handler = RevokeRequestHandler{Ctx: ctx, Issuer: issuer}
	}
	req := api.RevocationRequest{}
	return ctx, handler, req
}
