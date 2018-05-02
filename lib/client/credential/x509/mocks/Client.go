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

import bccsp "github.com/hyperledger/fabric/bccsp"
import credential "github.com/hyperledger/fabric-ca/lib/client/credential"
import mock "github.com/stretchr/testify/mock"
import x509 "github.com/hyperledger/fabric-ca/lib/client/credential/x509"

// Client is an autogenerated mock type for the Client type
type Client struct {
	mock.Mock
}

// GetCSP provides a mock function with given fields:
func (_m *Client) GetCSP() bccsp.BCCSP {
	ret := _m.Called()

	var r0 bccsp.BCCSP
	if rf, ok := ret.Get(0).(func() bccsp.BCCSP); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(bccsp.BCCSP)
		}
	}

	return r0
}

// NewX509Identity provides a mock function with given fields: name, creds
func (_m *Client) NewX509Identity(name string, creds []credential.Credential) x509.Identity {
	ret := _m.Called(name, creds)

	var r0 x509.Identity
	if rf, ok := ret.Get(0).(func(string, []credential.Credential) x509.Identity); ok {
		r0 = rf(name, creds)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(x509.Identity)
		}
	}

	return r0
}
