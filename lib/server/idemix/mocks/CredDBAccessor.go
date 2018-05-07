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

import dbutil "github.com/hyperledger/fabric-ca/lib/dbutil"
import idemix "github.com/hyperledger/fabric-ca/lib/server/idemix"
import mock "github.com/stretchr/testify/mock"

// CredDBAccessor is an autogenerated mock type for the CredDBAccessor type
type CredDBAccessor struct {
	mock.Mock
}

// GetCredential provides a mock function with given fields: revocationHandle
func (_m *CredDBAccessor) GetCredential(revocationHandle string) (*idemix.CredRecord, error) {
	ret := _m.Called(revocationHandle)

	var r0 *idemix.CredRecord
	if rf, ok := ret.Get(0).(func(string) *idemix.CredRecord); ok {
		r0 = rf(revocationHandle)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.CredRecord)
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
func (_m *CredDBAccessor) GetCredentialsByID(id string) ([]idemix.CredRecord, error) {
	ret := _m.Called(id)

	var r0 []idemix.CredRecord
	if rf, ok := ret.Get(0).(func(string) []idemix.CredRecord); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]idemix.CredRecord)
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

// InsertCredential provides a mock function with given fields: cr
func (_m *CredDBAccessor) InsertCredential(cr idemix.CredRecord) error {
	ret := _m.Called(cr)

	var r0 error
	if rf, ok := ret.Get(0).(func(idemix.CredRecord) error); ok {
		r0 = rf(cr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetDB provides a mock function with given fields: db
func (_m *CredDBAccessor) SetDB(db dbutil.FabricCADB) {
	_m.Called(db)
}
