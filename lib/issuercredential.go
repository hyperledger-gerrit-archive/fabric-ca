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
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// IssuerCredential represents CA's idemix credential
type IssuerCredential interface {
	Load() error
	Store() error
	GetIssuerKey() (*idemix.IssuerKey, error)
	SetIssuerKey(key *idemix.IssuerKey)
}

// CAIdemixCredential represents CA's Idemix public and secret key
type CAIdemixCredential struct {
	pubKeyFile    string
	secretKeyFile string
	issuerKey     *idemix.IssuerKey
}

// NewCAIdemixCredential is the constructor for the CAIdemixCredential
func NewCAIdemixCredential(pubKeyFile, secretKeyFile string) *CAIdemixCredential {
	return &CAIdemixCredential{
		pubKeyFile:    pubKeyFile,
		secretKeyFile: secretKeyFile,
	}
}

// Load loads the CA's idemix public and private key from the location specified
// by pubKeyFile and secretKeyFile attributes, respectively
func (ic *CAIdemixCredential) Load() error {
	pubKeyBytes, err := ioutil.ReadFile(ic.pubKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read CA's Idemix public key")
	}
	if len(pubKeyBytes) == 0 {
		return errors.New("CA's Idemix public key file is empty")
	}
	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal CA's Idemix public key bytes")
	}
	err = pubKey.Check()
	if err != nil {
		return errors.Wrapf(err, "CA Idemix public key check failed")
	}
	privKey, err := ioutil.ReadFile(ic.secretKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read CA's Idemix secret key")
	}
	if len(privKey) == 0 {
		return errors.New("CA's Idemix secret key file is empty")
	}
	ic.issuerKey = &idemix.IssuerKey{
		IPk: pubKey,
		ISk: privKey,
	}
	//TODO: check if issuer key is valid by checking public and secret key pair
	return nil
}

// Store stores the CA's Idemix public and private key to the location
// specified by pubKeyFile and secretKeyFile attributes, respectively
func (ic *CAIdemixCredential) Store() error {
	ik, err := ic.GetIssuerKey()
	if err != nil {
		return err
	}

	ipkBytes, err := proto.Marshal(ik.IPk)
	if err != nil {
		return errors.New("Failed to marshal CA's Idemix public key")
	}

	err = util.WriteFile(ic.pubKeyFile, ipkBytes, 0644)
	if err != nil {
		log.Errorf("Failed to store CA's Idemix public key: %s", err.Error())
		return errors.New("Failed to store CA's Idemix public key")
	}

	err = util.WriteFile(ic.secretKeyFile, ik.ISk, 0644)
	if err != nil {
		log.Errorf("Failed to store CA's Idemix secret key: %s", err.Error())
		return errors.New("Failed to store CA's Idemix secret key")
	}

	log.Infof("The CA's issuer key was successfully stored. The public key is at: %s, secret key is at: %s",
		ic.pubKeyFile, ic.secretKeyFile)
	return nil
}

// GetIssuerKey returns idemix.IssuerKey object that is associated with
// this CAIdemixCredential
func (ic *CAIdemixCredential) GetIssuerKey() (*idemix.IssuerKey, error) {
	if ic.issuerKey == nil {
		return nil, errors.New("CA's Idemix credential is not set")
	}
	return ic.issuerKey, nil
}

// SetIssuerKey sets idemix.IssuerKey object
func (ic *CAIdemixCredential) SetIssuerKey(key *idemix.IssuerKey) {
	ic.issuerKey = key
}
