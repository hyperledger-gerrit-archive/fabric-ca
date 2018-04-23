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

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	mspprotos "github.com/hyperledger/fabric/protos/msp"
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
	// Type returns type of this credential
	Type() CredentialType
	// EnrollmentID returns enrollment ID associated with this credential
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	EnrollmentID() (string, error)
	// Val returns credential value.
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	Val() (interface{}, error)
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

// BaseCredential is the base type for all credential types
type BaseCredential struct {
	client *Client
}

// X509Credential represents a X509 credential
type X509Credential struct {
	BaseCredential
	certFile string
	keyFile  string
	val      *Signer
}

// IdemixCredential represents an Idemix credential
type IdemixCredential struct {
	BaseCredential
	signerConfigFile string
	val              *mspprotos.IdemixMSPSignerConfig
}

// NewX509Credential is constructor for X509Credential
func NewX509Credential(certFile, keyFile string, c *Client) *X509Credential {
	b := BaseCredential{client: c}
	return &X509Credential{
		b, certFile, keyFile, nil,
	}
}

// NewIdemixCredential is constructor for IdemixCredential
func NewIdemixCredential(signerConfigFile string, c *Client) *IdemixCredential {
	b := BaseCredential{client: c}
	return &IdemixCredential{
		b, signerConfigFile, nil,
	}
}

// Type returns X509
func (cred *X509Credential) Type() CredentialType {
	return X509
}

// Val returns *Signer associated with this X509 credential
func (cred *X509Credential) Val() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("Credential value is not set")
	}
	return cred.val, nil
}

// EnrollmentID returns enrollment ID of this X509 credential
func (cred *X509Credential) EnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("Credential value is not set")
	}
	return cred.val.GetName(), nil
}

// SetVal sets *Signer for this X509 credential
func (cred *X509Credential) SetVal(val interface{}) error {
	s, ok := val.(*Signer)
	if !ok {
		return errors.New("The credential value should be of type *Signer for X509 credential")
	}
	cred.val = s
	return nil
}

// Load loads the certificate and key from the location specified by
// certFile attribute using the BCCSP of the client. The private key is
// loaded from the location specified by the keyFile attribute, if the
// private key is not found in the keystore managed by BCCSP
func (cred *X509Credential) Load() error {
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
	cred.val, err = NewSigner(key, cert)
	if err != nil {
		return err
	}
	return nil
}

// Store stores the certificate associated with this X509 credential to the location
// specified by certFile attribute
func (cred *X509Credential) Store() error {
	if cred.val == nil {
		return errors.New("Certificate is not set")
	}
	err := util.WriteFile(cred.certFile, cred.val.Cert(), 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the certificate")
	}
	log.Infof("Stored client certificate at %s", cred.certFile)
	return nil
}

// CreateOAuthToken creates oauth token based on this X509 credential
func (cred *X509Credential) CreateOAuthToken(reqBody []byte) (string, error) {
	return util.CreateToken(cred.getCSP(), cred.val.certBytes, cred.val.key, reqBody)
}

// RevokeSelf revokes this X509 credential
func (cred *X509Credential) RevokeSelf() (*api.RevocationResponse, error) {
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
	name, _ := cred.EnrollmentID()
	id := NewIdentity(cred.client, name, []Credential{cred})
	return id.Revoke(req)
}

func (cred *X509Credential) getCSP() bccsp.BCCSP {
	if cred.client != nil && cred.client.csp != nil {
		return cred.client.csp
	}
	return util.GetDefaultBCCSP()
}

// Type returns Idemix
func (cred *IdemixCredential) Type() CredentialType {
	return Idemix
}

// Val returns *mspprotos.IdemixMSPSignerConfig associated with this Idemix credential
func (cred *IdemixCredential) Val() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("Credential value is not set")
	}
	return cred.val, nil
}

// EnrollmentID returns enrollment ID associated with this Idemix credential
func (cred *IdemixCredential) EnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("Credential value is not set")
	}
	return "", errors.New("Not implemented") // TODO
}

// SetVal sets *mspprotos.IdemixMSPSignerConfig for this Idemix credential
func (cred *IdemixCredential) SetVal(val interface{}) error {
	s, ok := val.(*mspprotos.IdemixMSPSignerConfig)
	if !ok {
		return errors.New("The credential should be of type *mspprotos.IdemixMSPSignerConfig for idemix Credential")
	}
	cred.val = s
	return nil
}

// Store stores this Idemix credential to the location specified by the
// signerConfigFile attribute
func (cred *IdemixCredential) Store() error {
	signerConfigBytes, err := proto.Marshal(cred.val)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal SignerConfig")
	}
	err = util.WriteFile(cred.signerConfigFile, signerConfigBytes, 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the Idemix credential")
	}
	log.Infof("Stored the Idemix credential at %s", cred.signerConfigFile)
	return nil
}

// Load loads the Idemix credential from the location specified by the
// signerConfigFile attribute
func (cred *IdemixCredential) Load() error {
	signerConfigBytes, err := util.ReadFile(cred.signerConfigFile)
	if err != nil {
		log.Debugf("No credential found at %s", cred.signerConfigFile)
		return err
	}
	val := mspprotos.IdemixMSPSignerConfig{}
	err = proto.Unmarshal(signerConfigBytes, &val)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Failed to unmarshal SignerConfig bytes from %s", cred.signerConfigFile))
	}
	cred.val = &val
	return nil
}

// CreateOAuthToken creates oauth token based on this Idemix credential
func (cred *IdemixCredential) CreateOAuthToken(reqBody []byte) (string, error) {
	return "", errors.New("Not implemented") // TODO
	// enrollmentID, err := cred.EnrollmentID()
	// if err != nil {
	// 	return "", err
	// }
	// rng, err := idemix.GetRand()
	// if err != nil {
	// 	return "", errors.WithMessage(err, "Failed to get a random number while creating oauth token")
	// }
	// // Get user's secret key
	// sk := amcl.FromBytes(cred.val.GetSk())

	// // Get issuer public key
	// ipk, err := cred.client.getIssuerPubKey()
	// if err != nil {
	// 	return "", errors.WithMessage(err, "Failed to get CA's Idemix public key while creating oauth token")
	// }

	// // Generate a fresh Pseudonym (and a corresponding randomness)
	// nym, randNym := idemix.MakeNym(sk, ipk, rng)

	// nymBytes := []byte{}
	// nym.ToBytes(nymBytes)
	// nym64Encoding := util.B64Encode(nymBytes)
	// body64Encoding := util.B64Encode(reqBody)
	// msg := nym64Encoding + "." + body64Encoding

	// digest, digestError := cred.client.csp.Hash([]byte(msg), &bccsp.SHAOpts{})
	// if digestError != nil {
	// 	return "", errors.WithMessage(digestError, fmt.Sprintf("Failed to create authentication token '%s'", msg))
	// }

	// // a disclosure vector is formed (indicating that all attributes from the credential are revealed)
	// disclosure := []byte{1, 1, 1, 1}

	// var credential *idemix.Credential
	// err = proto.Unmarshal(cred.val.GetCred(), credential)
	// if err != nil {
	// 	errors.Wrapf(err, "Failed to unmarshal Idemix credential while creating oauth token")
	// }
	// sig, err := idemix.NewSignature(credential, sk, nym, randNym, ipk, disclosure, digest, rng)
	// if err != nil {
	// 	errors.Wrapf(err, "Failed to create signature while creating oauth token")
	// }
	// sigBytes, err := proto.Marshal(sig)
	// token := enrollmentID + "." + util.B64Encode(sigBytes)
	// return token, nil
}

// RevokeSelf revokes this Idemix credential
func (cred *IdemixCredential) RevokeSelf() (*api.RevocationResponse, error) {
	return nil, errors.New("Not implemented") //TODO
}
