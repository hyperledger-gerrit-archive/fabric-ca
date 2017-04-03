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

func newIdentity(client *Client, name string, key bccsp.Key, cert []byte) *Identity {
	id := new(Identity)
	id.name = name
	id.ecert = newSigner(key, cert, id)
	id.client = client
	if client != nil {
		id.csp = client.csp
	} else {
		id.csp = factory.GetDefault()
	}
	return id
}

// Identity is fabric-ca's implementation of an identity
type Identity struct {
	name   string
	ecert  *Signer
	client *Client
	csp    bccsp.BCCSP
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.name
}

// GetECert returns the enrollment certificate signer for this identity
func (i *Identity) GetECert() *Signer {
	return i.ecert
}

// NewTCertFactory constructs a transaction certificate factory from which you can
// get multiple anonymous and unlinkable signers for this identity
func (i *Identity) NewTCertFactory(req *api.GetTCertFactoryRequest) (*TCertFactory, error) {
	if req == nil {
		return nil, errors.New("nil request to GetTCertBatch")
	}
	tf := &TCertFactory{identity: i, req: req, csp: i.csp}
	err := tf.init()
	if err != nil {
		return nil, err
	}
	return tf, nil
}

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	log.Debugf("Register %+v", &req)
	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}
	if req.Affiliation == "" {
		return nil, errors.New("Registration request does not have an affiliation")
	}

	reqBody, err := util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	// Send a post to the "register" endpoint with req as body
	resp := &api.RegistrationResponse{}
	err = i.Post("register", reqBody, resp)
	if err != nil {
		return nil, err
	}

	log.Debug("The register request completely successfully")
	return resp, nil
}

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
	log.Debugf("Reenrolling %s", &req)

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
	var result enrollmentResponseNet
	err = i.Post("reenroll", body, &result)
	if err != nil {
		return nil, err
	}
	return i.client.newEnrollmentResponse(&result, i.GetName(), key)
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *api.RevocationRequest) error {
	log.Debugf("Entering identity.Revoke %+v", &req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return err
	}
	err = i.Post("revoke", reqBody, nil)
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
	req := &api.RevocationRequest{Name: name}
	return i.Revoke(req)
}

// Store writes my identity info to disk
func (i *Identity) Store() error {
	if i.client == nil {
		return fmt.Errorf("An identity with no client may not be stored")
	}
	return i.client.StoreMyIdentity(i.ecert.cert)
}

// Post sends arbtrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}) error {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return err
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("adding token-based authorization header")
	cert := i.ecert.cert
	key := i.ecert.key
	token, err := util.CreateToken(i.csp, cert, key, body)
	if err != nil {
		return fmt.Errorf("Failed to add token authorization header: %s", err)
	}
	req.Header.Set("authorization", token)
	return nil
}

// TCertFactory is an object from which you may retrieve multiple TCerts, each
// being anonymous and unlinkable.
type TCertFactory struct {
	identity   *Identity
	csp        bccsp.BCCSP
	selfSigned bool
	req        *api.GetTCertFactoryRequest
	factory    *tcert.Factory
	batch      []tcert.TCert
}

// GetTCert returns a transaction certificate
func (tf *TCertFactory) GetTCert() (*tcert.TCert, error) {
	if tf.selfSigned {
		// Get a self-signed TCert
		return tf.factory.GenTCert()
	}
	// Get a CA-signed TCert
	if len(tf.batch) == 0 {
		err := tf.getBatch()
		if err != nil {
			return nil, err
		}
	}
	tcert := tf.batch[0]
	tf.batch = tf.batch[1:]
	return &tcert, nil
}

// Initialize the TCert factory
func (tf *TCertFactory) init() error {
	if tf.req.SelfSigned {
		return tf.initSelfSigned()
	}
	return nil
}

// Initialize a self-signed TCert batch by getting a single CA-signed
// TCert to get two things: the KDF key and the values of the requested
// attributes.  All else is done locally to self-sign as many TCerts
// as the client wants to create.
func (tf *TCertFactory) initSelfSigned() error {
	tf.selfSigned = true
	req := tf.req
	if req.DisableKeyDerivation {
		return errors.New("SelfSigned and DisableKeyDerivation may not both be true")
	}
	// In order to generate self-signed TCerts, we need to get a single
	// TCert signed by the server with the requested attributes and the KDF
	// key to use in generating the private keys.
	req2 := &api.GetTCertBatchRequestNet{
		GetTCertFactoryRequest: api.GetTCertFactoryRequest{
			AttrNames:      req.AttrNames,
			ValidityPeriod: req.ValidityPeriod,
			PreKey:         req.PreKey,
			Count:          req.Count,
		}}
	resp, err := tf.getBatchFromServer(req2)
	if err != nil {
		return err
	}
	tCert := resp.TCerts[0]
	attrs, err := tCert.GetAttributes()
	if err != nil {
		return err
	}
	err = tf.initFactory(resp.Key)
	if err != nil {
		return err
	}
	tf.factory.SetAttributes(attrs, req.EncryptAttrs)
	return nil
}

// Create and initalize the lib/tcert factory
func (tf *TCertFactory) initFactory(kdfKey []byte) error {
	mgr, err := tcert.NewMgr(tf.csp)
	if err != nil {
		return err
	}
	ecert := tf.identity.GetECert()
	ecertX509, err := ecert.X509Cert()
	if err != nil {
		return err
	}
	tf.factory, err = mgr.NewFactory(ecertX509, kdfKey)
	if err != nil {
		return err
	}
	tf.factory.SetECertPrivateKey(ecert.Key())
	return nil
}

// Get the next batch of TCerts
func (tf *TCertFactory) getBatch() error {
	// Get the batch from the server
	log.Debug("Getting TCert batch from server")
	netReq := &api.GetTCertBatchRequestNet{GetTCertFactoryRequest: *tf.req}
	resp, err := tf.getBatchFromServer(netReq)
	if err != nil {
		return err
	}
	batch := resp.TCerts
	if len(batch) == 0 {
		return errors.New("No transaction certificates were returned by the server")
	}
	err = tf.initFactory(resp.Key)
	if err != nil {
		return err
	}
	// Set the private signer for each TCert, which requires the private key and
	// involves private key derivation.
	for _, tcert := range batch {
		err = tf.factory.SetTCertPrivateSigner(&tcert)
		if err != nil {
			return err
		}
	}
	if tf.batch == nil {
		tf.batch = batch
	} else {
		tf.batch = append(tf.batch, batch...)
	}
	return nil
}

// Get a batch of TCerts from the server
func (tf *TCertFactory) getBatchFromServer(req *api.GetTCertBatchRequestNet) (*api.GetTCertBatchResponseNet, error) {
	reqBody, err := util.Marshal(req, "GetTCertBatchRequest")
	if err != nil {
		return nil, err
	}
	resp := new(api.GetTCertBatchResponseNet)
	err = tf.identity.Post("tcert", reqBody, &resp.GetBatchResponse)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
