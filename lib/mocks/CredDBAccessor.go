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
// Code generated by mockery v1.0.0

package mocks

import lib "github.com/hyperledger/fabric-ca/lib"
import mock "github.com/stretchr/testify/mock"

// CredDBAccessor is an autogenerated mock type for the CredDBAccessor type
type CredDBAccessor struct {
	mock.Mock
}

// GetCredential provides a mock function with given fields: revocationHandle
func (_m *CredDBAccessor) GetCredential(revocationHandle string) (*lib.IdemixCredRecord, error) {
	ret := _m.Called(revocationHandle)

	var r0 *lib.IdemixCredRecord
	if rf, ok := ret.Get(0).(func(string) *lib.IdemixCredRecord); ok {
		r0 = rf(revocationHandle)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lib.IdemixCredRecord)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(revocationHandle)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCredentialsByID provides a mock function with given fields: id
func (_m *CredDBAccessor) GetCredentialsByID(id string) ([]lib.IdemixCredRecord, error) {
	ret := _m.Called(id)

	var r0 []lib.IdemixCredRecord
	if rf, ok := ret.Get(0).(func(string) []lib.IdemixCredRecord); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]lib.IdemixCredRecord)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRevokedAndUnexpiredCredentials provides a mock function with given fields:
func (_m *CredDBAccessor) GetRevokedAndUnexpiredCredentials() ([]lib.IdemixCredRecord, error) {
	ret := _m.Called()

	var r0 []lib.IdemixCredRecord
	if rf, ok := ret.Get(0).(func() []lib.IdemixCredRecord); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]lib.IdemixCredRecord)
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

// GetRevokedAndUnexpiredCredentialsByLabel provides a mock function with given fields: label
func (_m *CredDBAccessor) GetRevokedAndUnexpiredCredentialsByLabel(label string) ([]lib.IdemixCredRecord, error) {
	ret := _m.Called(label)

	var r0 []lib.IdemixCredRecord
	if rf, ok := ret.Get(0).(func(string) []lib.IdemixCredRecord); ok {
		r0 = rf(label)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]lib.IdemixCredRecord)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(label)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUnexpiredCredentials provides a mock function with given fields:
func (_m *CredDBAccessor) GetUnexpiredCredentials() ([]lib.IdemixCredRecord, error) {
	ret := _m.Called()

	var r0 []lib.IdemixCredRecord
	if rf, ok := ret.Get(0).(func() []lib.IdemixCredRecord); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]lib.IdemixCredRecord)
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

// InsertCredential provides a mock function with given fields: cr
func (_m *CredDBAccessor) InsertCredential(cr lib.IdemixCredRecord) error {
	ret := _m.Called(cr)

	var r0 error
	if rf, ok := ret.Get(0).(func(lib.IdemixCredRecord) error); ok {
		r0 = rf(cr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RevokeCredential provides a mock function with given fields: revocationHandle, reasonCode
func (_m *CredDBAccessor) RevokeCredential(revocationHandle string, reasonCode int) error {
	ret := _m.Called(revocationHandle, reasonCode)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, int) error); ok {
		r0 = rf(revocationHandle, reasonCode)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
