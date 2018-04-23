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

package lib_test

import (
	"testing"

	amcl "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/idemix"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/pkg/errors"
)

func TestIdemixEnrollInvalidBasicAuth(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("", errors.New("bad credentials"))
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}
	_, err := handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should fail if basic auth credentials are invalid")
}

func TestIdemixEnrollInvalidTokenAuth(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", errors.New("bad credentials"))
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: false}
	_, err := handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should fail if token auth credentials are invalid")
}

func TestIdemixEnrollBadReqBody(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(errors.New("Invalid request body"))
	_, err := handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error if reading body fails")
}

func TestIdemixEnrollGetCAError(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ctx.On("GetCA").Return(nil, errors.New("Failure getting CA from context"))
	_, err := handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error if getting CA from context fails")
}

func TestHandleIdemixEnrollForNonce(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ca := &CA{}
	ctx.On("GetCA").Return(ca, nil)
	_, err := handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceTokenAuth(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: false}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ca := &CA{}
	ctx.On("GetCA").Return(ca, nil)
	_, err := handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForCredentialFail(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}

	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to get nonce")
	}

	issuerCred := NewCAIdemixCredential("../testdata/IdemixPublicKey", "../testdata/IdemixSecretKey")
	ca := &CA{IssuerCred: issuerCred}
	ca.Config = &CAConfig{
		CA: CAInfo{
			Name: "",
		},
	}
	f := getReadBodyFunc(t, nonce)
	req := api.IdemixEnrollmentRequestNet{}
	ctx.On("ReadBody", &req).Return(f)
	ctx.On("GetCA").Return(ca, nil)
	_, err = handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error because issuerCredential has not been loaded from disk")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to get issuer key for the CA")
	}

	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ctx.On("GetCaller").Return(nil, errors.New("Error when getting caller of the request"))
	_, err = handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error because ctx.GetCaller returned error")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to determine the caller of the request")
	}
}

func TestHandleIdemixEnrollForCredentialSuccess(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true}

	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to get nonce")
	}

	issuerCred := NewCAIdemixCredential("../testdata/IdemixPublicKey", "../testdata/IdemixSecretKey")
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})
	ca.On("IssuerCredential").Return(issuerCred)
	ca.On("FillCAInfo", &ServerInfoResponseNet{}).Return(nil)
	f := getReadBodyFunc(t, nonce)
	req := api.IdemixEnrollmentRequestNet{}
	ctx.On("ReadBody", &req).Return(f)
	ctx.On("GetCA").Return(ca, nil)
	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "Role").Return(&api.Attribute{Name: "isAdmin", Value: "true"}, nil)
	caller.On("LoginComplete").Return(nil)
	ctx.On("GetCaller").Return(caller, nil)
	_, err = handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return error because ctx.GetCaller returned error")
}

func getReadBodyFunc(t *testing.T, nonce *amcl.BIG) func(body interface{}) error {
	return func(body interface{}) error {
		enrollReq, _ := body.(*api.IdemixEnrollmentRequestNet)
		var err error
		enrollReq.CredRequest, _, _, err = newIdemixCredentialRequest(t, nonce)
		return err
	}
}

func newIdemixCredentialRequest(t *testing.T, nonce *amcl.BIG) (*idemix.CredRequest, *amcl.BIG, *amcl.BIG, error) {
	issuerCred := NewCAIdemixCredential("../testdata/IdemixPublicKey", "../testdata/IdemixSecretKey")
	err := issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, err := issuerCred.GetIssuerKey()
	if err != nil {
		t.Fatalf("Issuer credential returned error while getting issuer key")
	}
	rng, err := idemix.GetRand()
	if err != nil {
		return nil, nil, nil, err
	}
	sk := idemix.RandModOrder(rng)
	randCred := idemix.RandModOrder(rng)

	return idemix.NewCredRequest(sk, randCred, nonce, ik.IPk, rng), sk, randCred, nil
}
