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

import lib "github.com/hyperledger/fabric-ca/lib"
import mock "github.com/stretchr/testify/mock"
import viper "github.com/spf13/viper"

// Command is an autogenerated mock type for the Command type
type Command struct {
	mock.Mock
}

// ConfigInit provides a mock function with given fields:
func (_m *Command) ConfigInit() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetCfgFileName provides a mock function with given fields:
func (_m *Command) GetCfgFileName() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetClientCfg provides a mock function with given fields:
func (_m *Command) GetClientCfg() *lib.ClientConfig {
	ret := _m.Called()

	var r0 *lib.ClientConfig
	if rf, ok := ret.Get(0).(func() *lib.ClientConfig); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lib.ClientConfig)
		}
	}

	return r0
}

// GetViper provides a mock function with given fields:
func (_m *Command) GetViper() *viper.Viper {
	ret := _m.Called()

	var r0 *viper.Viper
	if rf, ok := ret.Get(0).(func() *viper.Viper); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*viper.Viper)
		}
	}

	return r0
}

// LoadMyIdentity provides a mock function with given fields:
func (_m *Command) LoadMyIdentity() (*lib.Identity, error) {
	ret := _m.Called()

	var r0 *lib.Identity
	if rf, ok := ret.Get(0).(func() *lib.Identity); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lib.Identity)
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
