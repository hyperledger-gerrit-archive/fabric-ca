// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import http "net/http"

import mock "github.com/stretchr/testify/mock"
import server "github.com/hyperledger/fabric-ca/lib/server"
import spi "github.com/hyperledger/fabric-ca/lib/spi"
import sqlx "github.com/jmoiron/sqlx"

// ServerRequestContext is an autogenerated mock type for the ServerRequestContext type
type ServerRequestContext struct {
	mock.Mock
}

// BasicAuthentication provides a mock function with given fields:
func (_m *ServerRequestContext) BasicAuthentication() (string, error) {
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

// CanActOnType provides a mock function with given fields: _a0
func (_m *ServerRequestContext) CanActOnType(_a0 string) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChunksToDeliver provides a mock function with given fields: _a0
func (_m *ServerRequestContext) ChunksToDeliver(_a0 string) (int, error) {
	ret := _m.Called(_a0)

	var r0 int
	if rf, ok := ret.Get(0).(func(string) int); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ContainsAffiliation provides a mock function with given fields: _a0
func (_m *ServerRequestContext) ContainsAffiliation(_a0 string) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetBoolQueryParm provides a mock function with given fields: name
func (_m *ServerRequestContext) GetBoolQueryParm(name string) (bool, error) {
	ret := _m.Called(name)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCaller provides a mock function with given fields:
func (_m *ServerRequestContext) GetCaller() (spi.User, error) {
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

// GetCertificates provides a mock function with given fields: _a0, _a1
func (_m *ServerRequestContext) GetCertificates(_a0 server.CertificateRequest, _a1 string) (*sqlx.Rows, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *sqlx.Rows
	if rf, ok := ret.Get(0).(func(server.CertificateRequest, string) *sqlx.Rows); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*sqlx.Rows)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(server.CertificateRequest, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetQueryParm provides a mock function with given fields: name
func (_m *ServerRequestContext) GetQueryParm(name string) string {
	ret := _m.Called(name)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetReq provides a mock function with given fields:
func (_m *ServerRequestContext) GetReq() *http.Request {
	ret := _m.Called()

	var r0 *http.Request
	if rf, ok := ret.Get(0).(func() *http.Request); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*http.Request)
		}
	}

	return r0
}

// GetResp provides a mock function with given fields:
func (_m *ServerRequestContext) GetResp() http.ResponseWriter {
	ret := _m.Called()

	var r0 http.ResponseWriter
	if rf, ok := ret.Get(0).(func() http.ResponseWriter); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.ResponseWriter)
		}
	}

	return r0
}

// HasRole provides a mock function with given fields: role
func (_m *ServerRequestContext) HasRole(role string) error {
	ret := _m.Called(role)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IsLDAPEnabled provides a mock function with given fields:
func (_m *ServerRequestContext) IsLDAPEnabled() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ReadBody provides a mock function with given fields: _a0
func (_m *ServerRequestContext) ReadBody(_a0 interface{}) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenAuthentication provides a mock function with given fields:
func (_m *ServerRequestContext) TokenAuthentication() (string, error) {
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