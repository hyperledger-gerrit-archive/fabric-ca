/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// EnrollmentResponse is the idemix enrollment response from the server
type EnrollmentResponse struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]interface{}
	// Base64 encoding of Credential Revocation information
	CRI string
	// Base64 encoding of the issuer nonce
	Nonce string
	// Base64 encoding of the revocation handle
	RevocationHandle string
}

// RevocationResponse represents response from the server for an Idemix revocation request
type RevocationResponse struct {
	// RevokedHandles is an array of revocation handles of the revoked credentials
	RevokedHandles []string
	// Base64 encoding of the CRI
	CRI string
}
