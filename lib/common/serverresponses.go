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

package common

// CAInfoResponseNet is the response to the GET /info request
type CAInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
	// Base64 encoding of idemix issuer public key
	IssuerPublicKey string
	// Version of the server
	Version string
}

// EnrollmentResponseNet is the response to the /enroll request
type EnrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string
	// The server information
	CAInfo CAInfoResponseNet
}

// IdemixEnrollmentResponseNet is the response to the /idemix/credential request
type IdemixEnrollmentResponseNet struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]string
	// Base64 encoding of Credential Revocation list
	//CRL string
	// Base64 encoding of the issuer nonce
	Nonce string
	// The CA information
	CAInfo CAInfoResponseNet
}
