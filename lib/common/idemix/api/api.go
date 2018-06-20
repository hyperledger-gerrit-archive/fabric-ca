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

// RevocationRequest is a revocation request for a single Idemix credential or all Idemix credentials
// associated with an identity.
// To revoke a single credential, revocationHandle must be set;
// otherwise, to revoke all credentials and the identity associated with an enrollment ID,
// the Name field must be set to an existing enrollment ID.
// A IdemixRevocationRequest can only be performed by a user with the "hf.Revoker" attribute.
type RevocationRequest struct {
	// Name of the identity whose credentials should be revoked
	// If this field is omitted, then RevocationHandle must be specified.
	Name string `json:"id,omitempty" opt:"e" help:"Enrollment ID of the identity whose credentials should be revoked"`
	// Revocation handle of the credential to be revoked
	// If this is omitted, then Name must be specified
	RevocationHandle string `json:"revocationhandle,omitempty" opt:"s" help:"Base64 encoding of the revocation handle of the Idemix credential to be revoked"`
	// Reason is the reason for revocation.  See https://godoc.org/golang.org/x/crypto/ocsp for
	// valid values. The default value is 0 (ocsp.Unspecified).
	Reason string `json:"reason,omitempty" opt:"r" help:"Reason for revocation"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
}

// RevocationResponse represents response from the server for an Idemix revocation request
type RevocationResponse struct {
	// RevokedHandles is an array of revocation handles of the revoked credentials
	RevokedHandles []string
	// Base64 encoding of the CRI
	CRI string
}
