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
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

var (
	// The X.509 BasicConstraints object identifier (RFC 5280, 4.2.1.9)
	basicConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 19}
)

// The enrollment response from the server
type enrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string
	// The server information
	ServerInfo serverInfoResponseNet
}

// Handle an enroll request, guarded by basic authentication
func enrollHandler(ctx *serverContext) (interface{}, error) {
	id, err := ctx.BasicAuthentication()
	if err != nil {
		return nil, err
	}
	return handleEnroll(ctx, id)
}

// Handle a reenroll request, guarded by token authentication
func reenrollHandler(ctx *serverContext) (interface{}, error) {
	// Authenticate the caller
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	return handleEnroll(ctx, id)
}

// Handle the common processing for enroll and reenroll
func handleEnroll(ctx *serverContext, id string) (interface{}, error) {
	var req api.EnrollmentRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Get the targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Authorization the caller, depending on the contents of the
	// CSR (Certificate Signing Request)
	err = csrAuthCheck(id, &req.SignRequest, ca)
	if err != nil {
		return nil, err
	}
	// Sign the certificate
	cert, err := ca.enrollSigner.Sign(req.SignRequest)
	if err != nil {
		return nil, fmt.Errorf("Signing failure: %s", err)
	}
	// Add server info to the response
	resp := &enrollmentResponseNet{Cert: util.B64Encode(cert)}
	err = ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	// Success
	return resp, nil
}

// Make any authorization checks needed, depending on the contents
// of the CSR (Certificate Signing Request).
// In particular, if the request is for an intermediate CA certificate,
// the caller must have the "hf.IntermediateCA" attribute.
func csrAuthCheck(id string, req *signer.SignRequest, ca *CA) error {
	// Decode and parse the request into a CSR so we can make checks
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}
	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	// Check the CSR for the X.509 BasicConstraints extension (RFC 5280, 4.2.1.9)
	for _, val := range csrReq.Extensions {
		if val.Id.Equal(basicConstraintsOID) {
			var constraints csr.BasicConstraints
			var rest []byte
			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return newErr(ErrBadCSR, 400, "Failed parsing CSR constraints: %s", err)
			} else if len(rest) != 0 {
				return newErr(ErrBadCSR, 400, "Trailing data after X.509 BasicConstraints")
			}
			if constraints.IsCA {
				log.Debug("CSR request received for an intermediate CA")
				// This is a request for a CA certificate, so make sure the caller
				// has the 'hf.IntermediateCA' attribute
				return ca.userHasAttribute(id, "hf.IntermediateCA")
			}
		}
	}
	log.Debug("CSR request received")
	return nil
}
