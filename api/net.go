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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/lib/tcert"
)

/*
 * This file contains the structure definitions for the request
 * and responses which flow over the network between a fabric-ca client
 * and the fabric-ca server.
 */

// RegistrationRequestNet is the registration request for a new identity
type RegistrationRequestNet struct {
	RegistrationRequest
}

// RegistrationResponseNet is a registration response
type RegistrationResponseNet struct {
	RegistrationResponse
}

// EnrollmentRequestNet is a request to enroll an identity
type EnrollmentRequestNet struct {
	signer.SignRequest
	CAName   string
	AttrReqs []*AttributeRequest
}

// ReenrollmentRequestNet is a request to reenroll an identity.
// This is useful to renew a certificate before it has expired.
type ReenrollmentRequestNet struct {
	signer.SignRequest
	CAName   string
	AttrReqs []*AttributeRequest
}

// RevocationRequestNet is a revocation request which flows over the network
// to the fabric-ca server.
// To revoke a single certificate, both the Serial and AKI fields must be set;
// otherwise, to revoke all certificates and the identity associated with an enrollment ID,
// the Name field must be set to an existing enrollment ID.
// A RevocationRequest can only be performed by a user with the "hf.Revoker" attribute.
type RevocationRequestNet struct {
	RevocationRequest
}

// GetTCertBatchRequestNet is a network request for a batch of transaction certificates
type GetTCertBatchRequestNet struct {
	GetTCertBatchRequest
	// KeySigs is an optional array of public keys and corresponding signatures.
	// If not set, the server generates it's own keys based on a key derivation function
	// which cryptographically relates the TCerts to an ECert.
	KeySigs []KeySig `json:"key_sigs,omitempty"`
}

// GetTCertBatchResponseNet is the network response for a batch of transaction certificates
type GetTCertBatchResponseNet struct {
	tcert.GetBatchResponse
}

// KeySig is a public key, signature, and signature algorithm tuple
type KeySig struct {
	// Key is a public key
	Key []byte `json:"key"`
	// Sig is a signature over the PublicKey
	Sig []byte `json:"sig"`
	// Alg is the signature algorithm
	Alg string `json:"alg"`
}

// SendResultWithError sends response back with both a result and errors
func SendResultWithError(w http.ResponseWriter, result interface{}, message string, rcode int, scode int) error {
	response := &api.Response{
		Success: false,
		Result:  result,
		Errors: []api.ResponseMessage{
			api.ResponseMessage{
				Code:    rcode,
				Message: message,
			},
		},
		Messages: []api.ResponseMessage{},
	}

	jsonMessage, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Failed to marshal error to JSON: %v", err)
		return err
	}
	msg := string(jsonMessage)
	http.Error(w, msg, scode)

	return nil
}
