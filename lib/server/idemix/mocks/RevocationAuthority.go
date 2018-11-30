// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import ecdsa "crypto/ecdsa"
import idemix "github.com/hyperledger/fabric/idemix"
import mock "github.com/stretchr/testify/mock"

// RevocationAuthority is an autogenerated mock type for the RevocationAuthority type
type RevocationAuthority struct {
	mock.Mock
}

// CreateCRI provides a mock function with given fields:
func (_m *RevocationAuthority) CreateCRI() (*idemix.CredentialRevocationInformation, error) {
	ret := _m.Called()

	var r0 *idemix.CredentialRevocationInformation
	if rf, ok := ret.Get(0).(func() *idemix.CredentialRevocationInformation); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.CredentialRevocationInformation)
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

// Epoch provides a mock function with given fields:
func (_m *RevocationAuthority) Epoch() (int, error) {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNewRevocationHandle provides a mock function with given fields:
func (_m *RevocationAuthority) GetNewRevocationHandle() (int, error) {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PublicKey provides a mock function with given fields:
func (_m *RevocationAuthority) PublicKey() *ecdsa.PublicKey {
	ret := _m.Called()

	var r0 *ecdsa.PublicKey
	if rf, ok := ret.Get(0).(func() *ecdsa.PublicKey); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ecdsa.PublicKey)
		}
	}

	return r0
}
