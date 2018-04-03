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
	"strings"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	amcl "github.com/milagro-crypto/amcl/version3/go/amcl/FP256BN"
	"github.com/pkg/errors"
)

// The enrollment response from the server
type idemixEnrollmentResponseNet struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Base64 encoding of  Credential Revocation list
	CRL string
	// Base64 encoding of the issuer nonce
	Nonce string
	// The server information
	ServerInfo serverInfoResponseNet
}

func newIdemixEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   idemixEnrollHandler,
		Server:    s,
		successRC: 201,
	}
}

// Handle an enroll request, guarded by basic authentication
func idemixEnrollHandler(ctx *serverRequestContext) (interface{}, error) {
	_, _, isBasicAuth := ctx.req.BasicAuth()
	var err error
	var id string
	if isBasicAuth {
		id, err = ctx.BasicAuthentication()
		if err != nil {
			return nil, err
		}
	} else {
		id, err = ctx.TokenAuthentication()
		if err != nil {
			return nil, err
		}
	}

	resp, err := handleIdemixEnroll(ctx, id)
	if err != nil {
		return nil, err
	}
	err = ctx.ui.LoginComplete()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Handle the common processing for enroll
func handleIdemixEnroll(ctx *serverRequestContext, id string) (interface{}, error) {
	var req api.IdemixEnrollmentRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	// Get the targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	if req.CredRequest == nil {
		nonce, err := ca.generateNonce()
		if err != nil {
			return nil, err
		}
		// TODO: store the nonce so it can be validated later
		resp := idemixEnrollmentResponseNet{
			Nonce: util.B64Encode(idemix.BigToBytes(nonce)),
		}
		return resp, nil
	}

	ik, err := ca.GetIssuerCredential().GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get issuer key for the CA %s: %s", ca.Config.CA.Name, err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get issuer key for the CA: %s", ca.Config.CA.Name))
	}

	caller, err := ctx.GetCaller()
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

	// Get attributes for the identity
	attrs, err := getAttributeValues(ca, caller, ik.GetIPk())
	if err != nil {
		return nil, err
	}

	cred, err := idemix.NewCredential(ik, req.CredRequest, attrs, rng)
	if err != nil {
		log.Errorf("CA %s failed to create new credential for identity %s: %s", ca.Config.CA.Name, id, err.Error())
		return nil, errors.New("Failed to create new credential")
	}
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, errors.New("Failed to marshal credential to bytes")
	}

	// TODO: Store the credential in the database

	// TODO: Get CRL from revocation authority of the CA

	resp := idemixEnrollmentResponseNet{
		Credential: util.B64Encode(credBytes),
		CRL:        "", // TODO
	}
	err = ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}

	// Success
	return resp, nil
}

func getAttributeValues(ca *CA, caller spi.User, ipk *idemix.IssuerPublicKey) ([]*amcl.BIG, error) {
	rc := []*amcl.BIG{}
	for _, attr := range ipk.AttributeNames {
		if attr == "enrollmentID" {
			idBytes := []byte(caller.GetName())
			rc = append(rc, idemix.HashModOrder(idBytes))
		} else if attr == "OU" {
			ou := []string{}
			for _, aff := range caller.GetAffiliationPath() {
				ou = append(ou, aff)
			}
			ouBytes := []byte(strings.Join(ou, "."))
			rc = append(rc, idemix.HashModOrder(ouBytes))
		} else if attr == "revocationHandle" {
			// TODO: Get revocation handle from the revocation authority of the CA
			rh := ""
			rhBytes := []byte(rh)
			rc = append(rc, idemix.HashModOrder(rhBytes))
		} else {
			attrObj, err := caller.GetAttribute(attr)
			if err != nil {
				log.Errorf("Failed to get attribute %s for user %s: %s", attr, caller.GetName(), err.Error())
			} else {
				attrBytes := []byte(attrObj.GetValue())
				rc = append(rc, idemix.HashModOrder(attrBytes))
			}
		}
	}
	return rc, nil
}
