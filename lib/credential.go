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
	"encoding/hex"
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/bccsp"
	mspprotos "github.com/hyperledger/fabric/protos/msp"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// CredentialType represents type of a credential
type CredentialType int

// Credential type enumeration
const (
	// X509 credential
	X509 CredentialType = iota
	// Idemix credential
	Idemix
)

// Credential interface
type Credential interface {
	// GetType returns type of this credential
	GetType() CredentialType
	// GetEnrollmentID returns enrollment ID associated with this credential
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	GetEnrollmentID() (string, error)
	// GetVal returns credential value.
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	GetVal() (interface{}, error)
	// Sets the credential value
	SetVal(val interface{}) error
	// Stores the credential value to disk
	Store() error
	// Loads the credential value from disk and sets the value of this credential
	Load() error
	// CreateOAuthToken returns oauth autentication token for that request with
	// specified body
	CreateOAuthToken(reqBody []byte) (string, error)
	// Submits revoke request to the Fabric CA server to revoke this credential
	RevokeSelf() (*api.RevocationResponse, error)
}

type credential struct {
	client *Client
}

type x509Credential struct {
	credential
	certFile string
	keyFile  string
	val      *Signer
}

type idemixCredential struct {
	credential
	signerConfigFile string
	val              *mspprotos.IdemixMSPSignerConfig
}

func newX509Credential(certFile, keyFile string, c *Client) *x509Credential {
	b := credential{client: c}
	return &x509Credential{
		b, certFile, keyFile, nil,
	}
}

func newIdemixCredential(signerConfigFile string, c *Client) *idemixCredential {
	b := credential{client: c}
	return &idemixCredential{
		b, signerConfigFile, nil,
	}
}

func (cred *x509Credential) GetType() CredentialType {
	return X509
}

func (cred *x509Credential) GetVal() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("Credential value is not set")
	}
	return cred.val, nil
}

func (cred *x509Credential) GetEnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("Credential value is not set")
	}
	return cred.val.GetName(), nil
}

func (cred *x509Credential) SetVal(val interface{}) error {
	s, ok := val.(*Signer)
	if !ok {
		return errors.New("The credential value should be of type *Signer for X509 credential")
	}
	cred.val = s
	return nil
}

func (cred *x509Credential) Store() error {
	if cred.val == nil {
		return errors.New("Certificate is not set")
	}
	err := util.WriteFile(cred.certFile, cred.val.Cert(), 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the certificate")
	}
	log.Infof("Stored the certificate at %s", cred.certFile)
	return nil
}

func (cred *x509Credential) Load() error {
	cert, err := util.ReadFile(cred.certFile)
	if err != nil {
		log.Debugf("No certificate found at %s", cred.certFile)
		return err
	}
	csp := cred.getCSP()
	key, _, _, err := util.GetSignerFromCertFile(cred.certFile, csp)
	if err != nil {
		// Fallback: attempt to read out of keyFile and import
		log.Debugf("No key found in the BCCSP keystore, attempting fallback")
		key, err = util.ImportBCCSPKeyFromPEM(cred.keyFile, csp, true)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Could not find the private key in the BCCSP keystore nor in the keyfile %s", cred.keyFile))
		}
	}
	cred.val, err = newSigner(key, cert)
	if err != nil {
		return err
	}
	return nil
}

func (cred *x509Credential) CreateOAuthToken(reqBody []byte) (string, error) {
	return util.CreateToken(cred.getCSP(), cred.val.certBytes, cred.val.key, reqBody)
}

func (cred *x509Credential) RevokeSelf() (*api.RevocationResponse, error) {
	val := cred.val
	if val == nil {
		return nil, errors.New("Credential value is not set")
	}
	serial := util.GetSerialAsHex(val.cert.SerialNumber)
	aki := hex.EncodeToString(val.cert.AuthorityKeyId)
	req := &api.RevocationRequest{
		Serial: serial,
		AKI:    aki,
	}
	name, _ := cred.GetEnrollmentID()
	id := newIdentity(cred.client, name, []Credential{cred})
	return id.Revoke(req)
}

func (cred *x509Credential) getCSP() bccsp.BCCSP {
	if cred.client != nil && cred.client.csp != nil {
		return cred.client.csp
	}
	return util.GetDefaultBCCSP()
}

func (cred *idemixCredential) GetType() CredentialType {
	return Idemix
}

func (cred *idemixCredential) GetVal() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("Credential value is not set")
	}
	return cred.val, nil
}

func (cred *idemixCredential) GetEnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("Credential value is not set")
	}
	return "", errors.New("Not implemented") // TODO
}

func (cred *idemixCredential) SetVal(val interface{}) error {
	s, ok := val.(*mspprotos.IdemixMSPSignerConfig)
	if !ok {
		return errors.New("The credential should be of type *mspprotos.IdemixMSPSignerConfig for idemix Credential")
	}
	cred.val = s
	return nil
}

func (cred *idemixCredential) Store() error {
	signerConfigBytes, err := proto.Marshal(cred.val)
	if err != nil {
		return err
	}
	err = util.WriteFile(cred.signerConfigFile, signerConfigBytes, 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the idmeix credential")
	}
	log.Infof("Stored the idemix credential at %s", cred.signerConfigFile)
	return nil
}

func (cred *idemixCredential) Load() error {
	signerConfigBytes, err := util.ReadFile(cred.signerConfigFile)
	if err != nil {
		log.Debugf("No credential found at %s", cred.signerConfigFile)
		return err
	}
	val := mspprotos.IdemixMSPSignerConfig{}
	err = proto.Unmarshal(signerConfigBytes, &val)
	if err != nil {
		return err
	}
	cred.val = &val
	return nil
}

func (cred *idemixCredential) CreateOAuthToken(reqBody []byte) (string, error) {
	return "", errors.New("Not implemented") //TODO
}

func (cred *idemixCredential) RevokeSelf() (*api.RevocationResponse, error) {
	return nil, errors.New("Not implemented") //TODO
}
