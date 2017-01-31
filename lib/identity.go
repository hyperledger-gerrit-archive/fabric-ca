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
	"errors"
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
)

func newIdentity(client *Client, name string, key []byte, cert []byte) *Identity {
	id := new(Identity)
	id.name = name
	id.ecert = newSigner(key, cert, id)
	id.client = client
	return id
}

// Identity is fabric-ca's implementation of an identity
type Identity struct {
	name   string
	ecert  *Signer
	client *Client
	CSP    bccsp.BCCSP
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.name
}

// GetECert returns the enrollment certificate signer for this identity
func (i *Identity) GetECert() *Signer {
	return i.ecert
}

// GetTCertBatch returns a batch of TCerts for this identity
// 	Added support for TCert Generation witout Key Derivation
// In TCert generation without Key Derivation , client generates Key pair and
// sends batch of signed public key to the Fabric ca
// server which sends back Fabric-ca certificates to client
// Different approaches for TCert generation have been discussed on    //https://jira.hyperledger.org/secure/attachment/10360/mserv-TCertOptions-v3(1).md.
// Look for section : Approach 2
func (i *Identity) GetTCertBatch(req *api.GetTCertBatchRequest) ([]*Signer, error) {

	batchRequestNet := new(api.GetTCertBatchRequestNet)

	if req.DisableKeyDerivation == true {

		//Call GetKeySigBatch method
		keySigs, error := tcert.GetKeySigBatch(i.CSP, req, "SHA2_256")
		if error != nil {
			return nil, fmt.Errorf("GetKeySigBatch failed with error : %s", error)
		}
		//populate req object with GetTCertBatchRequestNet
		batchRequestNet.KeySigs = keySigs

	}

	batchRequestNet.GetTCertBatchRequest = *req

	reqBody, err := util.Marshal(batchRequestNet, "GetTCertBatchRequest")
	if err != nil {
		return nil, err
	}
	_, err2 := i.Post("tcert", reqBody)
	if err2 != nil {
		return nil, err2
	}
	// Ignore the contents of the response for now.  They will be processed in the future when we need to
	// support the Go SDK.   We currently have Node and Java SDKs which process this and they are the
	// priority.
	return nil, nil
}

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	var reqBody []byte
	var secret string
	var resp interface{}

	log.Debugf("Register %+v", req)
	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}
	if req.Group == "" {
		return nil, errors.New("Register was called without a Group set")
	}

	reqBody, err = util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	// Send a post to the "register" endpoint with req as body
	resp, err = i.Post("register", reqBody)
	if err != nil {
		return nil, err
	}

	switch resp.(type) {
	case string:
		secret = resp.(string)
	case map[string]interface{}:
		secret = resp.(map[string]interface{})["credential"].(string)
	default:
		return nil, fmt.Errorf("Response is neither string nor map: %+v", resp)
	}

	log.Debug("The register request completely successfully")
	return &api.RegistrationResponse{Secret: secret}, nil
}

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*Identity, error) {
	log.Debugf("Reenrolling %s", req)

	csrPEM, key, err := i.client.GenCSR(req.CSR, i.GetName())
	if err != nil {
		return nil, err
	}

	// Get the body of the request
	sreq := signer.SignRequest{
		Hosts:   signer.SplitHosts(req.Hosts),
		Request: string(csrPEM),
		Profile: req.Profile,
		Label:   req.Label,
	}
	body, err := util.Marshal(sreq, "SignRequest")
	if err != nil {
		return nil, err
	}

	result, err := i.Post("reenroll", body)
	if err != nil {
		return nil, err
	}

	return i.client.newIdentityFromResponse(result, i.GetName(), key)
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *api.RevocationRequest) error {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return err
	}
	_, err = i.Post("revoke", reqBody)
	if err != nil {
		return err
	}
	log.Debugf("Successfully revoked %+v", req)
	return nil
}

// RevokeSelf revokes the current identity and all certificates
func (i *Identity) RevokeSelf() error {
	name := i.GetName()
	log.Debugf("RevokeSelf %s", name)
	req := &api.RevocationRequest{
		Name: name,
	}
	return i.Revoke(req)
}

// Store writes my identity info to disk
func (i *Identity) Store() error {
	if i.client == nil {
		return fmt.Errorf("An identity with no client may not be stored")
	}
	return i.client.StoreMyIdentity(i.ecert.key, i.ecert.cert)
}

// Post sends arbtrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte) (interface{}, error) {
	req, err := i.client.NewPost(endpoint, reqBody)
	if err != nil {
		return nil, err
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return nil, err
	}
	return i.client.SendPost(req)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("adding token-based authorization header")
	cert := i.ecert.cert
	key := i.ecert.key
	if i.CSP == nil {
		csp, error := getDefaultBCCSPInstance()
		if error != nil {
			return fmt.Errorf("Default BCCSP instance failed with error : %s", error)
		}
		i.CSP = csp
	}
	token, err := util.CreateToken(i.CSP, cert, key, body)
	if err != nil {
		return fmt.Errorf("Failed to add token authorization header: %s", err)
	}
	req.Header.Set("authorization", token)
	return nil
}

func getDefaultBCCSPInstance() (bccsp.BCCSP, error) {
	defaultBccsp, bccspError := factory.GetDefault()
	if bccspError != nil {
		return nil, fmt.Errorf("BCCSP initialiazation failed with error : %s", bccspError)
	}
	if defaultBccsp == nil {
		return nil, errors.New("Cannot get default instance of BCCSP")
	}

	return defaultBccsp, nil
}
