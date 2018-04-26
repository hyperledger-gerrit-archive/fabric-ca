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

package lib

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	amcl "github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	mspprotos "github.com/hyperledger/fabric/protos/msp"
	"github.com/pkg/errors"
)

// IdemixEnrollmentResponseNet is the idemix enrollment response from the server
type IdemixEnrollmentResponseNet struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]string
	// Base64 encoding of Credential Revocation list
	//CRL string
	// Base64 encoding of the issuer nonce
	Nonce string
	// The server information
	ServerInfo ServerInfoResponseNet
}

// IdemixServerRequestCtx is the server request context that Idemix enroll expects
type IdemixServerRequestCtx interface {
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCA() (IdemixCA, error)
	GetCaller() (spi.User, error)
	ReadBody(body interface{}) error
}

// IdemixCA is the CA that Idemix enroll expects
type IdemixCA interface {
	FabricCA
	GetIdemixRand() *amcl.RAND
	IssuerCredential() IssuerCredential
	RevocationComponent() RevocationAuthority
	CredDBAccessor() IdemixCredDBAccessor
}

// IdemixLib represents idemix library
type IdemixLib interface {
	NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (*idemix.Credential, error)
	GetRand() (*amcl.RAND, error)
	RandModOrder(rng *amcl.RAND) *fp256bn.BIG
}

type idemixLibrary struct{}

type idemixServerRequestCtxAdapter struct {
	ctx *serverRequestContext
}

// IdemixEnrollRequestHandler is the handler for Idemix enroll request
type IdemixEnrollRequestHandler struct {
	IsBasicAuth  bool
	Ctx          IdemixServerRequestCtx
	EnrollmentID string
	CA           IdemixCA
	IdmxLib      IdemixLib
}

func newIdemixEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   handleIdemixEnrollReq,
		Server:    s,
		successRC: 201,
	}
}

// HandleReq handles an Idemix enroll request, guarded by basic/token authentication
func handleIdemixEnrollReq(ctx *serverRequestContext) (interface{}, error) {
	_, _, isBasicAuth := ctx.req.BasicAuth()
	handler := IdemixEnrollRequestHandler{
		Ctx:         &idemixServerRequestCtxAdapter{ctx},
		IsBasicAuth: isBasicAuth,
		IdmxLib:     &idemixLibrary{},
	}

	resp, err := handler.HandleIdemixEnroll()
	if err != nil {
		log.Errorf("Error processing the /idemix/credential request: %s", err.Error())
		return nil, err
	}
	return resp, nil
}

// HandleIdemixEnroll handles processing for Idemix enroll
func (h *IdemixEnrollRequestHandler) HandleIdemixEnroll() (interface{}, error) {
	err := h.Authenticate()
	if err != nil {
		return nil, err
	}

	var req api.IdemixEnrollmentRequestNet
	err = h.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	// Get the targeted CA
	h.CA, err = h.Ctx.GetCA()
	if err != nil {
		return nil, err
	}

	if req.CredRequest == nil {
		nonce := h.GenerateNonce()

		// TODO: store the nonce so it can be validated later

		resp := IdemixEnrollmentResponseNet{
			Nonce: util.B64Encode(idemix.BigToBytes(nonce)),
		}
		return resp, nil
	}

	ik, err := h.CA.IssuerCredential().GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get Idemix issuer key for the CA %s: %s", h.CA.GetConfig().CA.Name, err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get Idemix issuer key for the CA: %s",
			h.CA.GetConfig().CA.Name))
	}

	caller, err := h.Ctx.GetCaller()
	if err != nil {
		log.Errorf("Failed to get caller of the request: %s", err.Error())
		return nil, err
	}

	// TODO: validate issuer nonce

	// Check the if credential request is valid
	err = req.CredRequest.Check(ik.GetIPk())
	if err != nil {
		log.Errorf("Invalid Idemix credential request: %s", err.Error())
		return nil, newHTTPErr(400, ErrBadCredRequest, "Invalid Idemix credential request: %s", err)
	}

	// Get revocation handle for the credential
	rh, err := h.CA.RevocationComponent().GetNewRevocationHandle()
	if err != nil {
		return nil, err
	}

	// Get attributes for the identity
	attrMap, attrs, err := h.GetAttributeValues(caller, ik.GetIPk(), rh)
	if err != nil {
		return nil, err
	}

	cred, err := h.IdmxLib.NewCredential(ik, req.CredRequest, attrs, h.CA.GetIdemixRand())
	if err != nil {
		log.Errorf("CA '%s' failed to create new Idemix credential for identity '%s': %s",
			h.CA.GetConfig().CA.Name, h.EnrollmentID, err.Error())
		return nil, errors.New("Failed to create new Idemix credential")
	}
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, errors.New("Failed to marshal Idemix credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)

	// Store the credential in the database
	err = h.CA.CredDBAccessor().InsertCredential(IdemixCredRecord{
		CALabel:          h.CA.GetConfig().CA.Name,
		ID:               caller.GetName(),
		Status:           "good",
		Cred:             b64CredBytes,
		RevocationHandle: int(*rh),
	})
	if err != nil {
		log.Errorf("Failed to store the Idemix credential for identity '%s' in the database: %s", caller.GetName(), err.Error())
		return nil, errors.New("Failed to store the Idemix credential")
	}

	// TODO: Get CRL from revocation authority of the CA

	resp := IdemixEnrollmentResponseNet{
		Credential: b64CredBytes,
		Attrs:      attrMap,
	}
	err = h.CA.FillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}

	if h.IsBasicAuth {
		err = caller.LoginComplete()
		if err != nil {
			return nil, err
		}
	}

	// Success
	return resp, nil
}

// Authenticate authenticates the Idemix enroll request
func (h *IdemixEnrollRequestHandler) Authenticate() error {
	var err error
	if h.IsBasicAuth {
		h.EnrollmentID, err = h.Ctx.BasicAuthentication()
		if err != nil {
			return err
		}
	} else {
		h.EnrollmentID, err = h.Ctx.TokenAuthentication()
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateNonce generates a nonce for an Idemix enroll request
func (h *IdemixEnrollRequestHandler) GenerateNonce() *fp256bn.BIG {
	return h.IdmxLib.RandModOrder(h.CA.GetIdemixRand())
}

// GetAttributeValues returns attribute values of the caller of Idemix enroll request
func (h *IdemixEnrollRequestHandler) GetAttributeValues(caller spi.User, ipk *idemix.IssuerPublicKey,
	rh *RevocationHandle) (map[string]string, []*fp256bn.BIG, error) {
	rc := []*fp256bn.BIG{}
	attrMap := make(map[string]string)
	for _, attrName := range ipk.AttributeNames {
		if attrName == "EnrollmentID" {
			idBytes := []byte(caller.GetName())
			rc = append(rc, idemix.HashModOrder(idBytes))
			attrMap[attrName] = caller.GetName()
		} else if attrName == "OU" {
			ou := []string{}
			for _, aff := range caller.GetAffiliationPath() {
				ou = append(ou, aff)
			}
			ouVal := strings.Join(ou, ".")
			ouBytes := []byte(ouVal)
			rc = append(rc, idemix.HashModOrder(ouBytes))
			attrMap[attrName] = ouVal
		} else if attrName == "RevocationHandle" {
			rhi := int(*rh)
			rc = append(rc, fp256bn.NewBIGint(rhi))
			attrMap[attrName] = strconv.Itoa(rhi)
		} else if attrName == "Role" {
			isAdmin := false
			attrObj, err := caller.GetAttribute("isAdmin")
			if err == nil {
				isAdmin, err = strconv.ParseBool(attrObj.GetValue())
			}
			role := mspprotos.MSPRole_MEMBER
			if isAdmin {
				role = mspprotos.MSPRole_ADMIN
			}
			rc = append(rc, fp256bn.NewBIGint(int(role)))
			attrMap[attrName] = strconv.FormatBool(isAdmin)
		} else {
			attrObj, err := caller.GetAttribute(attrName)
			if err != nil {
				log.Errorf("Failed to get attribute %s for user %s: %s", attrName, caller.GetName(), err.Error())
			} else {
				attrBytes := []byte(attrObj.GetValue())
				rc = append(rc, idemix.HashModOrder(attrBytes))
				attrMap[attrName] = attrObj.GetValue()
			}
		}
	}
	return attrMap, rc, nil
}

func (a *idemixServerRequestCtxAdapter) BasicAuthentication() (string, error) {
	return a.ctx.BasicAuthentication()
}
func (a *idemixServerRequestCtxAdapter) TokenAuthentication() (string, error) {
	return a.ctx.TokenAuthentication()
}
func (a *idemixServerRequestCtxAdapter) GetCA() (IdemixCA, error) {
	return a.ctx.GetCA()
}
func (a *idemixServerRequestCtxAdapter) GetCaller() (spi.User, error) {
	return a.ctx.GetCaller()
}
func (a *idemixServerRequestCtxAdapter) ReadBody(body interface{}) error {
	return a.ctx.ReadBody(body)
}

func (i *idemixLibrary) GetRand() (*amcl.RAND, error) {
	return idemix.GetRand()
}
func (i *idemixLibrary) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (*idemix.Credential, error) {
	return idemix.NewCredential(key, m, attrs, rng)
}
func (i *idemixLibrary) RandModOrder(rng *amcl.RAND) *fp256bn.BIG {
	return idemix.RandModOrder(rng)
}
