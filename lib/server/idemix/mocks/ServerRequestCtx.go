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

import idemix "github.com/hyperledger/fabric-ca/lib/server/idemix"
import mock "github.com/stretchr/testify/mock"
import spi "github.com/hyperledger/fabric-ca/lib/spi"

// ServerRequestCtx is an autogenerated mock type for the ServerRequestCtx type
type ServerRequestCtx struct {
	mock.Mock
}

// BasicAuthentication provides a mock function with given fields:
func (_m *ServerRequestCtx) BasicAuthentication() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCaller provides a mock function with given fields:
func (_m *ServerRequestCtx) GetCaller() (spi.User, error) {
	ret := _m.Called()

	var r0 spi.User
	if rf, ok := ret.Get(0).(func() spi.User); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(spi.User)
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

// GetIssuer provides a mock function with given fields:
func (_m *ServerRequestCtx) GetIssuer() (idemix.Issuer, error) {
	ret := _m.Called()

	var r0 idemix.Issuer
	if rf, ok := ret.Get(0).(func() idemix.Issuer); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(idemix.Issuer)
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

// IsBasicAuth provides a mock function with given fields:
func (_m *ServerRequestCtx) IsBasicAuth() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ReadBody provides a mock function with given fields: body
func (_m *ServerRequestCtx) ReadBody(body interface{}) error {
	ret := _m.Called(body)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(body)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenAuthentication provides a mock function with given fields:
func (_m *ServerRequestCtx) TokenAuthentication() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
