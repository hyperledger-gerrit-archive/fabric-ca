/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"

	"github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// Lib represents idemix library
type Lib interface {
	NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (ik *idemix.IssuerKey, err error)
	NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (cred *idemix.Credential, err error)
	CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*fp256bn.BIG, epoch int, alg idemix.RevocationAlgorithm, rng *amcl.RAND) (cri *idemix.CredentialRevocationInformation, err error)
	GenerateLongTermRevocationKey() (pk *ecdsa.PrivateKey, err error)
	GetRand() (rand *amcl.RAND, err error)
	RandModOrder(rng *amcl.RAND) (big *fp256bn.BIG, err error)
}

// libImpl is adapter for idemix library. It implements Lib interface
type libImpl struct {
	idemix Lib
}

// NewLib returns an instance of an object that implements Lib interface
func NewLib() Lib {
	return &libImpl{
		idemix: &IdemixWrapper{},
	}
}

// NewLibProvider returns an instance of an object that implements Lib interface
func NewLibProvider(idemix Lib) Lib {
	return &libImpl{
		idemix: idemix,
	}
}

func (i *libImpl) GetRand() (rand *amcl.RAND, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.GetRand()
}
func (i *libImpl) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (cred *idemix.Credential, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.NewCredential(key, m, attrs, rng)
}
func (i *libImpl) RandModOrder(rng *amcl.RAND) (big *fp256bn.BIG, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.RandModOrder(rng)
}
func (i *libImpl) NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (ik *idemix.IssuerKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.NewIssuerKey(AttributeNames, rng)
}
func (i *libImpl) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*fp256bn.BIG, epoch int, alg idemix.RevocationAlgorithm, rng *amcl.RAND) (cri *idemix.CredentialRevocationInformation, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.CreateCRI(key, unrevokedHandles, epoch, alg, rng)
}
func (i *libImpl) GenerateLongTermRevocationKey() (pk *ecdsa.PrivateKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return i.idemix.GenerateLongTermRevocationKey()
}

type IdemixWrapper struct{}

func (i *IdemixWrapper) GetRand() (rand *amcl.RAND, err error) {
	return idemix.GetRand()
}
func (i *IdemixWrapper) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (cred *idemix.Credential, err error) {
	return idemix.NewCredential(key, m, attrs, rng)
}
func (i *IdemixWrapper) RandModOrder(rng *amcl.RAND) (big *fp256bn.BIG, err error) {
	return idemix.RandModOrder(rng), nil
}
func (i *IdemixWrapper) NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (ik *idemix.IssuerKey, err error) {
	return idemix.NewIssuerKey(AttributeNames, rng)
}
func (i *IdemixWrapper) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*fp256bn.BIG, epoch int, alg idemix.RevocationAlgorithm, rng *amcl.RAND) (cri *idemix.CredentialRevocationInformation, err error) {
	return idemix.CreateCRI(key, unrevokedHandles, epoch, alg, rng)
}
func (i *IdemixWrapper) GenerateLongTermRevocationKey() (pk *ecdsa.PrivateKey, err error) {
	return idemix.GenerateLongTermRevocationKey()
}
