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

/*
 * This file defines the user registry interface used by the fabric-ca server.
 */

package spi

import (
	"github.com/hyperledger/fabric-ca/api"
)

// UserInfo contains information about a user
type UserInfo struct {
	Name           string
	Pass           string
	Type           string
	Affiliation    string
	Attributes     []api.Attribute
	State          int
	MaxEnrollments int
}

// User is the SPI for a user
type User interface {
	// Returns the enrollment ID of the user
	GetName() string
	// Return the type of the user
	GetType() string
	// Return the max enrollments of the user
	GetMaxEnrollments() int
	// Login the user with a password
	Login(password string, caMaxEnrollment int) error
	// Get the complete path for the user's affiliation.
	GetAffiliationPath() []string
	// GetAttribute returns the value for an attribute name
	GetAttribute(name string) (*api.Attribute, error)
	// GetAttributes returns the requested attributes
	GetAttributes(attrNames []string) ([]api.Attribute, error)
	// LoginComplete completes the login process by incrementing the state of the user
	LoginComplete() error
	// Revoke will revoke the user, setting the state of the user to be -1
	Revoke() error
}

// UserRegistry is the API for retreiving users and groups
type UserRegistry interface {
	GetUser(id string, attrs []string) (User, error)
	InsertUser(user UserInfo) error
	UpdateUser(user UserInfo) error
	DeleteUser(id string) error
	GetAffiliation(name string) (Affiliation, error)
	InsertAffiliation(name string, prekey string) error
	DeleteAffiliation(name string) error
	GetFilteredUsers(affiliation, types string) ([]User, error)
}
