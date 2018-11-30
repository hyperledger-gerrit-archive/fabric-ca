/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"

	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/idemix/bridge"
	"github.com/hyperledger/fabric/bccsp/idemix/handlers"
	"github.com/hyperledger/fabric/idemix"
)

// Lib represents idemix library
type Lib interface {
	NewIssuerKey(AttributeNames []string) (*bridge.IssuerSecretKey, error)
	NewCredential(key handlers.IssuerSecretKey, credentialRequest *idemix.CredRequest, attrs []bccsp.IdemixAttribute) (*idemix.Credential, error)
	CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (*idemix.CredentialRevocationInformation, error)
	GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error)
	GetRand() *amcl.RAND
	RandModOrder(rng *amcl.RAND) *fp256bn.BIG
}

// libImpl is adapter for idemix library. It implements Lib interface
type libImpl struct{}

// NewLib returns an instance of an object that implements Lib interface
func NewLib() Lib {
	return &libImpl{}
}

func (i *libImpl) GetRand() *amcl.RAND {
	return bridge.NewRandOrPanic()
}

func (i *libImpl) NewCredential(key handlers.IssuerSecretKey, credentialRequest *idemix.CredRequest, attrs []bccsp.IdemixAttribute) (*idemix.Credential, error) {
	cred := bridge.Credential{
		NewRand: bridge.NewRandOrPanic,
	}
	req, err := proto.Marshal(credentialRequest)
	if err != nil {
		return nil, err
	}
	res, err := cred.Sign(key, req, attrs)
	if err != nil {
		return nil, err
	}

	idemixCred := &idemix.Credential{}
	err = proto.Unmarshal(res, idemixCred)
	if err != nil {
		return nil, err
	}
	return idemixCred, nil
}

func (i *libImpl) RandModOrder(rng *amcl.RAND) *fp256bn.BIG {
	return idemix.RandModOrder(rng)
}

func (i *libImpl) NewIssuerKey(AttributeNames []string) (*bridge.IssuerSecretKey, error) {
	issuer := bridge.Issuer{
		NewRand: bridge.NewRandOrPanic,
	}
	sk, err := issuer.NewKey(AttributeNames)
	if err != nil {
		return nil, err
	}
	return sk.(*bridge.IssuerSecretKey), nil
}

func (i *libImpl) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (*idemix.CredentialRevocationInformation, error) {
	revocation := bridge.Revocation{}
	res, err := revocation.Sign(key, unrevokedHandles, epoch, alg)
	if err != nil {
		return nil, err
	}
	cri := &idemix.CredentialRevocationInformation{}
	err = proto.Unmarshal(res, cri)
	if err != nil {
		return nil, err
	}
	return cri, nil
}

func (i *libImpl) GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error) {
	revocation := bridge.Revocation{}
	return revocation.NewKey()
}
