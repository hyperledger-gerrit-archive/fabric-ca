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
// Code generated by mockery v1.0.0

package mocks

import FP256BN "github.com/hyperledger/fabric-amcl/amcl/FP256BN"

import mock "github.com/stretchr/testify/mock"

// NonceManager is an autogenerated mock type for the NonceManager type
type NonceManager struct {
	mock.Mock
}

// CheckNonce provides a mock function with given fields: nonce
func (_m *NonceManager) CheckNonce(nonce *FP256BN.BIG) error {
	ret := _m.Called(nonce)

	var r0 error
	if rf, ok := ret.Get(0).(func(*FP256BN.BIG) error); ok {
		r0 = rf(nonce)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetNonce provides a mock function with given fields:
func (_m *NonceManager) GetNonce() (*FP256BN.BIG, error) {
	ret := _m.Called()

	var r0 *FP256BN.BIG
	if rf, ok := ret.Get(0).(func() *FP256BN.BIG); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*FP256BN.BIG)
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

// SweepExpiredNonces provides a mock function with given fields:
func (_m *NonceManager) SweepExpiredNonces() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
