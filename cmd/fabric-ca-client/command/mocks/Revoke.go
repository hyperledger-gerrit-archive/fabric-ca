// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import api "github.com/hyperledger/fabric-ca/api"

import mock "github.com/stretchr/testify/mock"

// Revoke is an autogenerated mock type for the Revoke type
type Revoke struct {
	mock.Mock
}

// RevokeIdemix provides a mock function with given fields: _a0
func (_m *Revoke) RevokeIdemix(_a0 *api.IdemixRevocationRequest) (*api.IdemixRevocationResponse, error) {
	ret := _m.Called(_a0)

	var r0 *api.IdemixRevocationResponse
	if rf, ok := ret.Get(0).(func(*api.IdemixRevocationRequest) *api.IdemixRevocationResponse); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.IdemixRevocationResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*api.IdemixRevocationRequest) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
