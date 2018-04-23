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
	amcl "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// RevocationHandle is the identifier of the credential using which a user can
// prove to the verifier that his/her credential is not revoked with a zero knowledge
// proof
type RevocationHandle int

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
	IssuerCredential() IssuerCredential
	GetConfig() *CAConfig
	FillCAInfo(resp *ServerInfoResponseNet) error
}

type idemixServerRequestCtxAdapter struct {
	ctx *serverRequestContext
}

// IdemixEnrollRequestHandler is the handler for Idemix enroll request
type IdemixEnrollRequestHandler struct {
	IsBasicAuth  bool
	Ctx          IdemixServerRequestCtx
	EnrollmentID string
	CA           IdemixCA
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
	handler := IdemixEnrollRequestHandler{Ctx: &idemixServerRequestCtxAdapter{ctx}, IsBasicAuth: isBasicAuth}

	resp, err := handler.HandleIdemixEnroll()
	if err != nil {
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
		nonce, err := h.GenerateNonce()
		if err != nil {
			return nil, err
		}

		// TODO: store the nonce so it can be validated later

		resp := IdemixEnrollmentResponseNet{
			Nonce: util.B64Encode(idemix.BigToBytes(nonce)),
		}
		return resp, nil
	}

	ik, err := h.CA.IssuerCredential().GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get issuer key for the CA %s: %s", h.CA.GetConfig().CA.Name, err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get issuer key for the CA: %s", h.CA.GetConfig().CA.Name))
	}

	caller, err := h.Ctx.GetCaller()
	if err != nil {
		log.Errorf("Failed to get caller of the request: %s", err.Error())
		return nil, errors.New("Failed to determine the caller of the request")
	}

	// TODO: validate issuer nonce

	// Check the if credential request is valid
	err = req.CredRequest.Check(ik.GetIPk())
	if err != nil {
		log.Errorf("Invalid credential request : %s", err.Error())
		return nil, errors.New("Invalid credential request")
	}

	rng, err := idemix.GetRand()
	if err != nil {
		log.Errorf("Error getting rng: \"%s\"", err)
		return nil, err
	}

	// TODO: Get revocation handle for the credential
	rh := RevocationHandle(1)

	// Get attributes for the identity
	attrMap, attrs, err := h.GetAttributeValues(caller, ik.GetIPk(), &rh)
	if err != nil {
		return nil, err
	}

	cred, err := idemix.NewCredential(ik, req.CredRequest, attrs, rng)
	if err != nil {
		log.Errorf("CA %s failed to create new credential for identity %s: %s", h.CA.GetConfig().CA.Name, h.EnrollmentID, err.Error())
		return nil, errors.New("Failed to create new credential")
	}
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, errors.New("Failed to marshal credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)

	// TODO: Store the credential in the database

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

// GenerateNonce generates a nonce for this Idemix enroll request
func (h *IdemixEnrollRequestHandler) GenerateNonce() (*amcl.BIG, error) {
	rng, err := idemix.GetRand()
	if err != nil {
		return nil, errors.Wrapf(err, "Error generating nonce")
	}
	nonce := idemix.RandModOrder(rng)
	return nonce, nil
}

// GetAttributeValues returns attribute values of the caller of Idemix enroll request
func (h *IdemixEnrollRequestHandler) GetAttributeValues(caller spi.User, ipk *idemix.IssuerPublicKey,
	rh *RevocationHandle) (map[string]string, []*amcl.BIG, error) {
	rc := []*amcl.BIG{}
	attrMap := make(map[string]string)
	fmt.Println(ipk.AttributeNames)
	for _, attrName := range ipk.AttributeNames {
		if attrName == "enrollmentID" {
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
		} else if attrName == "revocationHandle" {
			rhi := int(*rh)
			rhBytes := idemix.BigToBytes(amcl.NewBIGint(rhi))
			rc = append(rc, idemix.HashModOrder(rhBytes))
			attrMap[attrName] = strconv.Itoa(rhi)
		} else if attrName == "isAdmin" {
			isAdmin := false
			attrObj, err := caller.GetAttribute(attrName)
			if err == nil {
				isAdmin, err = strconv.ParseBool(attrObj.GetValue())
			}
			isAdminVal := strconv.FormatBool(isAdmin)
			isAdminBytes := []byte(isAdminVal)
			rc = append(rc, idemix.HashModOrder(isAdminBytes))
			attrMap[attrName] = isAdminVal
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
