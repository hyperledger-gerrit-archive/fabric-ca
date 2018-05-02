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

package api

import (
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/util"
)

// RegistrationRequest for a new identity
type RegistrationRequest struct {
	// Name is the unique name of the identity
	Name string `json:"id" help:"Unique name of the identity"`
	// Type of identity being registered (e.g. "peer, app, user")
	Type string `json:"type" def:"client" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	// Secret is an optional password.  If not specified,
	// a random secret is generated.  In both cases, the secret
	// is returned in the RegistrationResponse.
	Secret string `json:"secret,omitempty" mask:"password" help:"The enrollment secret for the identity being registered"`
	// MaxEnrollments is the maximum number of times the secret can
	// be reused to enroll.
	MaxEnrollments int `json:"max_enrollments,omitempty" help:"The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)"`
	// is returned in the response.
	// The identity's affiliation.
	// For example, an affiliation of "org1.department1" associates the identity with "department1" in "org1".
	Affiliation string `json:"affiliation" help:"The identity's affiliation"`
	// Attributes associated with this identity
	Attributes []Attribute `json:"attrs,omitempty"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
}

func (rr *RegistrationRequest) String() string {
	return util.StructToString(rr)
}

// RegistrationResponse is a registration response
type RegistrationResponse struct {
	// The secret returned from a successful registration response
	Secret string `json:"secret"`
}

// EnrollmentRequest is a request to enroll an identity
type EnrollmentRequest struct {
	// The identity name to enroll
	Name string `json:"name" skip:"true"`
	// The secret returned via Register
	Secret string `json:"secret,omitempty" skip:"true" mask:"password"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
	// AttrReqs are requests for attributes to add to the certificate.
	// Each attribute is added only if the requestor owns the attribute.
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
	// Profile is the name of the signing profile to use in issuing the X509 certificate
	Profile string `json:"profile,omitempty" help:"Name of the signing profile to use in issuing the certificate"`
	// Label is the label to use in HSM operations
	Label string `json:"label,omitempty" help:"Label to use in HSM operations"`
	// CSR is Certificate Signing Request info
	CSR *CSRInfo `json:"csr,omitempty" help:"Certificate Signing Request info"`
	// The type of the enrollment request: x509 or idemix
	// The default is a request for an X509 enrollment certificate
	Type string `def:"x509" help:"The type of enrollment request: 'x509' or 'idemix'"`
}

func (er EnrollmentRequest) String() string {
	return util.StructToString(&er)
}

// ReenrollmentRequest is a request to reenroll an identity.
// This is useful to renew a certificate before it has expired.
type ReenrollmentRequest struct {
	// Profile is the name of the signing profile to use in issuing the certificate
	Profile string `json:"profile,omitempty"`
	// Label is the label to use in HSM operations
	Label string `json:"label,omitempty"`
	// CSR is Certificate Signing Request info
	CSR *CSRInfo `json:"csr,omitempty"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
	// AttrReqs are requests for attributes to add to the certificate.
	// Each attribute is added only if the requestor owns the attribute.
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}

// RevocationRequest is a revocation request for a single certificate or all certificates
// associated with an identity.
// To revoke a single certificate, both the Serial and AKI fields must be set;
// otherwise, to revoke all certificates and the identity associated with an enrollment ID,
// the Name field must be set to an existing enrollment ID.
// A RevocationRequest can only be performed by a user with the "hf.Revoker" attribute.
type RevocationRequest struct {
	// Name of the identity whose certificates should be revoked
	// If this field is omitted, then Serial and AKI must be specified.
	Name string `json:"id,omitempty" opt:"e" help:"Identity whose certificates should be revoked"`
	// Serial number of the certificate to be revoked
	// If this is omitted, then Name must be specified
	Serial string `json:"serial,omitempty" opt:"s" help:"Serial number of the certificate to be revoked"`
	// AKI (Authority Key Identifier) of the certificate to be revoked
	AKI string `json:"aki,omitempty" opt:"a" help:"AKI (Authority Key Identifier) of the certificate to be revoked"`
	// Reason is the reason for revocation.  See https://godoc.org/golang.org/x/crypto/ocsp for
	// valid values.  The default value is 0 (ocsp.Unspecified).
	Reason string `json:"reason,omitempty" opt:"r" help:"Reason for revocation"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
	// GenCRL specifies whether to generate a CRL
	GenCRL bool `def:"false" skip:"true" json:"gencrl,omitempty"`
}

// RevocationResponse represents response from the server for a revocation request
type RevocationResponse struct {
	// RevokedCerts is an array of certificates that were revoked
	RevokedCerts []RevokedCert
	// CRL is PEM-encoded certificate revocation list (CRL) that contains all unexpired revoked certificates
	CRL []byte
}

// RevokedCert represents a revoked certificate
type RevokedCert struct {
	// Serial number of the revoked certificate
	Serial string
	// AKI of the revoked certificate
	AKI string
}

// GetTCertBatchRequest is input provided to identity.GetTCertBatch
type GetTCertBatchRequest struct {
	// Number of TCerts in the batch.
	Count int `json:"count"`
	// The attribute names whose names and values are to be sealed in the issued TCerts.
	AttrNames []string `json:"attr_names,omitempty"`
	// EncryptAttrs denotes whether to encrypt attribute values or not.
	// When set to true, each issued TCert in the batch will contain encrypted attribute values.
	EncryptAttrs bool `json:"encrypt_attrs,omitempty"`
	// Certificate Validity Period.  If specified, the value used
	// is the minimum of this value and the configured validity period
	// of the TCert manager.
	ValidityPeriod time.Duration `json:"validity_period,omitempty"`
	// The pre-key to be used for key derivation.
	PreKey string `json:"prekey"`
	// DisableKeyDerivation if true disables key derivation so that a TCert is not
	// cryptographically related to an ECert.  This may be necessary when using an
	// HSM which does not support the TCert's key derivation function.
	DisableKeyDerivation bool `json:"disable_kdf,omitempty"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
}

// GetTCertBatchResponse is the return value of identity.GetTCertBatch
type GetTCertBatchResponse struct {
	ID     *big.Int  `json:"id"`
	TS     time.Time `json:"ts"`
	Key    []byte    `json:"key"`
	TCerts []TCert   `json:"tcerts"`
}

// TCert encapsulates a signed transaction certificate and optionally a map of keys
type TCert struct {
	Cert []byte            `json:"cert"`
	Keys map[string][]byte `json:"keys,omitempty"` //base64 encoded string as value
}

// GetCAInfoRequest is request to get generic CA information
type GetCAInfoRequest struct {
	CAName string `json:"caname,omitempty" skip:"true"`
}

// GenCRLRequest represents a request to get CRL for the specified certificate authority
type GenCRLRequest struct {
	CAName        string    `json:"caname,omitempty" skip:"true"`
	RevokedAfter  time.Time `json:"revokedafter,omitempty"`
	RevokedBefore time.Time `json:"revokedbefore,omitempty"`
	ExpireAfter   time.Time `json:"expireafter,omitempty"`
	ExpireBefore  time.Time `json:"expirebefore,omitempty"`
}

// GenCRLResponse represents a response to get CRL
type GenCRLResponse struct {
	// CRL is PEM-encoded certificate revocation list (CRL) that contains requested unexpired revoked certificates
	CRL []byte
}

// AddIdentityRequest represents the request to add a new identity to the
// fabric-ca-server
type AddIdentityRequest struct {
	ID             string      `json:"id" skip:"true"`
	Type           string      `json:"type" def:"user" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	Affiliation    string      `json:"affiliation" help:"The identity's affiliation"`
	Attributes     []Attribute `json:"attrs" mapstructure:"attrs" `
	MaxEnrollments int         `json:"max_enrollments" mapstructure:"max_enrollments" help:"The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)"`
	// Secret is an optional password.  If not specified,
	// a random secret is generated.  In both cases, the secret
	// is returned in the RegistrationResponse.
	Secret string `json:"secret,omitempty" mask:"password" help:"The enrollment secret for the identity being added"`
	CAName string `json:"caname,omitempty" skip:"true"`
}

// ModifyIdentityRequest represents the request to modify an existing identity on the
// fabric-ca-server
type ModifyIdentityRequest struct {
	ID             string      `skip:"true"`
	Type           string      `json:"type" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	Affiliation    string      `json:"affiliation" help:"The identity's affiliation"`
	Attributes     []Attribute `mapstructure:"attrs" json:"attrs"`
	MaxEnrollments int         `mapstructure:"max_enrollments" json:"max_enrollments" help:"The maximum number of times the secret can be reused to enroll"`
	Secret         string      `json:"secret,omitempty" mask:"password" help:"The enrollment secret for the identity"`
	CAName         string      `json:"caname,omitempty" skip:"true"`
}

// RemoveIdentityRequest represents the request to remove an existing identity from the
// fabric-ca-server
type RemoveIdentityRequest struct {
	ID     string `skip:"true"`
	Force  bool   `json:"force"`
	CAName string `json:"caname,omitempty" skip:"true"`
}

// GetIDResponse is the response from the GetIdentity call
type GetIDResponse struct {
	ID             string      `json:"id" skip:"true"`
	Type           string      `json:"type" def:"user"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs" mapstructure:"attrs" `
	MaxEnrollments int         `json:"max_enrollments" mapstructure:"max_enrollments"`
	CAName         string      `json:"caname,omitempty"`
}

// GetAllIDsResponse is the response from the GetAllIdentities call
type GetAllIDsResponse struct {
	Identities []IdentityInfo `json:"identities"`
	CAName     string         `json:"caname,omitempty"`
}

// IdentityResponse is the response from the any add/modify/remove identity call
type IdentityResponse struct {
	ID             string      `json:"id" skip:"true"`
	Type           string      `json:"type,omitempty"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs,omitempty" mapstructure:"attrs"`
	MaxEnrollments int         `json:"max_enrollments,omitempty" mapstructure:"max_enrollments"`
	Secret         string      `json:"secret,omitempty"`
	CAName         string      `json:"caname,omitempty"`
}

// IdentityInfo contains information about an identity
type IdentityInfo struct {
	ID             string      `json:"id"`
	Type           string      `json:"type"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs" mapstructure:"attrs"`
	MaxEnrollments int         `json:"max_enrollments" mapstructure:"max_enrollments"`
}

// AddAffiliationRequest represents the request to add a new affiliation to the
// fabric-ca-server
type AddAffiliationRequest struct {
	Name   string `json:"name"`
	Force  bool   `json:"force"`
	CAName string `json:"caname,omitempty"`
}

// ModifyAffiliationRequest represents the request to modify an existing affiliation on the
// fabric-ca-server
type ModifyAffiliationRequest struct {
	Name    string
	NewName string `json:"name"`
	Force   bool   `json:"force"`
	CAName  string `json:"caname,omitempty"`
}

// RemoveAffiliationRequest represents the request to remove an existing affiliation from the
// fabric-ca-server
type RemoveAffiliationRequest struct {
	Name   string
	Force  bool   `json:"force"`
	CAName string `json:"caname,omitempty"`
}

// AffiliationResponse contains the response for get, add, modify, and remove an affiliation
type AffiliationResponse struct {
	AffiliationInfo `mapstructure:",squash"`
	CAName          string `json:"caname,omitempty"`
}

// AffiliationInfo contains the affiliation name, child affiliation info, and identities
// associated with this affiliation.
type AffiliationInfo struct {
	Name         string            `json:"name"`
	Affiliations []AffiliationInfo `json:"affiliations,omitempty"`
	Identities   []IdentityInfo    `json:"identities,omitempty"`
}

// CSRInfo is Certificate Signing Request (CSR) Information
type CSRInfo struct {
	CN           string           `json:"CN"`
	Names        []csr.Name       `json:"names,omitempty"`
	Hosts        []string         `json:"hosts,omitempty"`
	KeyRequest   *BasicKeyRequest `json:"key,omitempty"`
	CA           *csr.CAConfig    `json:"ca,omitempty"`
	SerialNumber string           `json:"serial_number,omitempty"`
}

// GetCertificatesRequest represents the request to get certificates from the server
// per the enrollment ID and/or AKI and Serial. If neither ID or AKI/Serial are
// provided all certificates are returned which are in or under the caller's affiliation.
// By default all certificates are returned. However, only revoked and/or expired
// certificates can be requested by providing a time range.
type GetCertificatesRequest struct {
	ID         string    `skip:"true"`                                    // Get certificates for this enrollment ID
	AKI        string    `help:"Get certificates for this AKI"`           // Get certificate that matches this AKI
	Serial     string    `help:"Get certificates for this serial number"` // Get certificate that matches this serial
	Revoked    TimeRange `skip:"true"`                                    // Get certificates which were revoked between the specified time range
	Expired    TimeRange `skip:"true"`                                    // Get certificates which expire between the specified time range
	NotExpired bool      `help:"Don't return expired certificates"`       // Don't return expired certificates
	NotRevoked bool      `help:"Don't return revoked certificates"`       // Don't return revoked certificates
	CAName     string    `skip:"true"`                                    // Name of CA to send request to within the server
}

// CertificateResponse contains the response from Get or Delete certificate request.
type CertificateResponse struct {
	Certs []string `json:"certs"`
}

// TimeRange specifies a range of time
type TimeRange struct {
	StartTime string
	EndTime   string
}

// BasicKeyRequest encapsulates size and algorithm for the key to be generated
type BasicKeyRequest struct {
	Algo string `json:"algo" yaml:"algo"`
	Size int    `json:"size" yaml:"size"`
}

// Attribute is a name and value pair
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert,omitempty"`
}

// GetName returns the name of the attribute
func (a *Attribute) GetName() string {
	return a.Name
}

// GetValue returns the value of the attribute
func (a *Attribute) GetValue() string {
	return a.Value
}

// AttributeRequest is a request for an attribute.
// This implements the certmgr/AttributeRequest interface.
type AttributeRequest struct {
	Name     string `json:"name"`
	Optional bool   `json:"optional,omitempty"`
}

// GetName returns the name of an attribute being requested
func (ar *AttributeRequest) GetName() string {
	return ar.Name
}

// IsRequired returns true if the attribute being requested is required
func (ar *AttributeRequest) IsRequired() bool {
	return !ar.Optional
}

// NewBasicKeyRequest returns the BasicKeyRequest object that is constructed
// from the object returned by the csr.NewBasicKeyRequest() function
func NewBasicKeyRequest() *BasicKeyRequest {
	bkr := csr.NewBasicKeyRequest()
	return &BasicKeyRequest{Algo: bkr.A, Size: bkr.S}
}
