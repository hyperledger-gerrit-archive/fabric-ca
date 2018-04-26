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

	proto "github.com/golang/protobuf/proto"
	amcl "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/idemix"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
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

func TestHandleIdemixEnrollForNonceError(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := new(mocks.IdemixLib)
	idemixlib.On("GetRand").Return(nil, errors.New("Failed to generate random number"))
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true, IdmxLib: idemixlib}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ca := &CA{}
	ctx.On("GetCA").Return(ca, nil)
	_, err := handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return an error if there is an error generating random number")
}

func TestHandleIdemixEnrollForNonce(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := new(mocks.IdemixLib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true, IdmxLib: idemixlib}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ca := &CA{}
	ctx.On("GetCA").Return(ca, nil)
	_, err = handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceTokenAuth(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.IdemixLib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: false, IdmxLib: idemixlib}

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	ca := &CA{}
	ctx.On("GetCA").Return(ca, nil)
	_, err = handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForCredentialError(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := new(mocks.IdemixLib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true, IdmxLib: idemixlib}

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

	credReq, _, _, err := newIdemixCredentialRequest(t, nonce)
	f := getReadBodyFunc(t, credReq)
	req := api.IdemixEnrollmentRequestNet{}
	ctx.On("ReadBody", &req).Return(f)
	ctx.On("GetCA").Return(ca, nil)
	_, err = handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error if IssuerCredential has not been loaded from disk")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to get issuer key for the CA")
	}

	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ctx.On("GetCaller").Return(nil, errors.New("Error when getting caller of the request"))
	_, err = handler.HandleIdemixEnroll()
	assert.Error(t, err, "Idemix enroll should return error if ctx.GetCaller returns error")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to determine the caller of the request")
	}
}

func TestHandleIdemixEnrollForCredentialSuccess(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	idemixlib := new(mocks.IdemixLib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true, IdmxLib: idemixlib}
	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to get nonce")
	}

	issuerCred := NewCAIdemixCredential("../testdata/IdemixPublicKey", "../testdata/IdemixSecretKey")
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := RevocationHandle(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(&rh, nil)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "isAdmin").Return(&api.Attribute{Name: "isAdmin", Value: "true"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, _, err := newIdemixCredentialRequest(t, nonce)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.IPk, &rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}
	cred, err := idemix.NewCredential(ik, credReq, attrs, rnd)
	if err != nil {
		t.Fatalf("Failed to create credential")
	}
	idemixlib.On("NewCredential", ik, credReq, attrs, rnd).Return(cred, nil)

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential", IdemixCredRecord{RevocationHandle: 1, CALabel: "", ID: "foo", Status: "good", Cred: b64CredBytes}).Return(nil)

	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})
	ca.On("IssuerCredential").Return(issuerCred)
	ca.On("FillCAInfo", &ServerInfoResponseNet{}).Return(nil)
	ca.On("RevocationComponent").Return(ra)
	ca.On("CredDBAccessor").Return(credAccessor, nil)

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(ca, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleIdemixEnroll()
	assert.NoError(t, err, "Idemix enroll should return error because ctx.GetCaller returned error")
}

func TestGetAttributeValues(t *testing.T) {
	ctx := new(mocks.IdemixServerRequestCtx)
	idemixlib := new(mocks.IdemixLib)
	handler := IdemixEnrollRequestHandler{Ctx: ctx, IsBasicAuth: true, IdmxLib: idemixlib}

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "isAdmin").Return(&api.Attribute{Name: "isAdmin", Value: "true"}, nil)
	caller.On("GetAttribute", "type").Return(&api.Attribute{Name: "type", Value: "client"}, nil)
	caller.On("LoginComplete").Return(nil)

	rh := RevocationHandle(1)

	ipk := idemix.IssuerPublicKey{AttributeNames: []string{"OU", "isAdmin", "enrollmentID", "revocationHandle", "type"}}
	_, _, err := handler.GetAttributeValues(caller, &ipk, &rh)
	assert.NoError(t, err)
}

func getB64EncodedCred(cred *idemix.Credential) (string, error) {
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return "", errors.New("Failed to marshal credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)
	return b64CredBytes, nil
}

func getReadBodyFunc(t *testing.T, credReq *idemix.CredRequest) func(body interface{}) error {
	return func(body interface{}) error {
		enrollReq, _ := body.(*api.IdemixEnrollmentRequestNet)
		if credReq == nil {
			return errors.New("Error reading the body")
		}
		enrollReq.CredRequest = credReq
		return nil
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
