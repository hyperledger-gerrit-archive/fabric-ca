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

package credential

import "github.com/hyperledger/fabric-ca/api"

// Credential represents an credential of an identity
type Credential interface {
	// Type returns type of this credential
	Type() string
	// EnrollmentID returns enrollment ID associated with this credential
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	EnrollmentID() (string, error)
	// Val returns credential value.
	// Returns an error if the credential value is not set (SetVal is not called)
	// or not loaded from the disk (Load is not called)
	Val() (interface{}, error)
	// Sets the credential value
	SetVal(val interface{}) error
	// Stores the credential value to disk
	Store() error
	// Loads the credential value from disk and sets the value of this credential
	Load() error
	// CreateOAuthToken returns oauth autentication token for that request with
	// specified body
	CreateOAuthToken(reqBody []byte) (string, error)
	// Submits revoke request to the Fabric CA server to revoke this credential
	RevokeSelf() (*api.RevocationResponse, error)
}
