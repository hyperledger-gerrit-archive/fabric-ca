// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import FP256BN "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
import amcl "github.com/hyperledger/fabric-amcl/amcl"
import bccsp "github.com/hyperledger/fabric/bccsp"
import bridge "github.com/hyperledger/fabric/bccsp/idemix/bridge"
import ecdsa "crypto/ecdsa"
import handlers "github.com/hyperledger/fabric/bccsp/idemix/handlers"
import idemix "github.com/hyperledger/fabric/idemix"
import mock "github.com/stretchr/testify/mock"

// Lib is an autogenerated mock type for the Lib type
type Lib struct {
	mock.Mock
}

// CreateCRI provides a mock function with given fields: key, unrevokedHandles, epoch, alg
func (_m *Lib) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (*idemix.CredentialRevocationInformation, error) {
	ret := _m.Called(key, unrevokedHandles, epoch, alg)

	var r0 *idemix.CredentialRevocationInformation
	if rf, ok := ret.Get(0).(func(*ecdsa.PrivateKey, [][]byte, int, bccsp.RevocationAlgorithm) *idemix.CredentialRevocationInformation); ok {
		r0 = rf(key, unrevokedHandles, epoch, alg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.CredentialRevocationInformation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ecdsa.PrivateKey, [][]byte, int, bccsp.RevocationAlgorithm) error); ok {
		r1 = rf(key, unrevokedHandles, epoch, alg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateLongTermRevocationKey provides a mock function with given fields:
func (_m *Lib) GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error) {
	ret := _m.Called()

	var r0 *ecdsa.PrivateKey
	if rf, ok := ret.Get(0).(func() *ecdsa.PrivateKey); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ecdsa.PrivateKey)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRand provides a mock function with given fields:
func (_m *Lib) GetRand() *amcl.RAND {
	ret := _m.Called()

	var r0 *amcl.RAND
	if rf, ok := ret.Get(0).(func() *amcl.RAND); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*amcl.RAND)
		}
	}

	return r0
}

// NewCredential provides a mock function with given fields: key, credentialRequest, attrs
func (_m *Lib) NewCredential(key handlers.IssuerSecretKey, credentialRequest *idemix.CredRequest, attrs []bccsp.IdemixAttribute) (*idemix.Credential, error) {
	ret := _m.Called(key, credentialRequest, attrs)

	var r0 *idemix.Credential
	if rf, ok := ret.Get(0).(func(handlers.IssuerSecretKey, *idemix.CredRequest, []bccsp.IdemixAttribute) *idemix.Credential); ok {
		r0 = rf(key, credentialRequest, attrs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.Credential)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(handlers.IssuerSecretKey, *idemix.CredRequest, []bccsp.IdemixAttribute) error); ok {
		r1 = rf(key, credentialRequest, attrs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewIssuerKey provides a mock function with given fields: AttributeNames
func (_m *Lib) NewIssuerKey(AttributeNames []string) (*bridge.IssuerSecretKey, error) {
	ret := _m.Called(AttributeNames)

	var r0 *bridge.IssuerSecretKey
	if rf, ok := ret.Get(0).(func([]string) *bridge.IssuerSecretKey); ok {
		r0 = rf(AttributeNames)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*bridge.IssuerSecretKey)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(AttributeNames)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RandModOrder provides a mock function with given fields: rng
func (_m *Lib) RandModOrder(rng *amcl.RAND) *FP256BN.BIG {
	ret := _m.Called(rng)

	var r0 *FP256BN.BIG
	if rf, ok := ret.Get(0).(func(*amcl.RAND) *FP256BN.BIG); ok {
		r0 = rf(rng)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*FP256BN.BIG)
		}
	}

	return r0
}
