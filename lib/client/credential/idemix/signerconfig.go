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

package idemix

// SignerConfig contains the crypto material to set up an idemix signing identity
type SignerConfig struct {
	// Cred represents the serialized idemix credential of the default signer
	Cred []byte `protobuf:"bytes,1,opt,name=Cred,proto3" json:"Cred,omitempty"`
	// Sk is the secret key of the default signer, corresponding to credential Cred
	Sk []byte `protobuf:"bytes,2,opt,name=Sk,proto3" json:"Sk,omitempty"`
	// OrganizationalUnitIdentifier defines the organizational unit the default signer is in
	OrganizationalUnitIdentifier string `protobuf:"bytes,3,opt,name=organizational_unit_identifier,json=organizationalUnitIdentifier" json:"organizational_unit_identifier,omitempty"`
	// IsAdmin defines whether the default signer is admin or not
	IsAdmin bool `protobuf:"varint,4,opt,name=is_admin,json=isAdmin" json:"is_admin,omitempty"`
	// EnrollmentID contains the enrollment id of this signer
	EnrollmentID string `protobuf:"bytes,5,opt,name=enrollment_id,json=enrollmentId" json:"enrollment_id,omitempty"`
	// CRI contains a serialized Credential Revocation Information
	CertificateRevocationInformation []byte `protobuf:"bytes,6,opt,name=credential_revocation_information,json=credentialRevocationInformation,proto3" json:"credential_revocation_information,omitempty"`
}

// GetCred returns credential associated with this signer config
func (s *SignerConfig) GetCred() []byte {
	return s.Cred

}

// GetSk returns secret key associated with this signer config
func (s *SignerConfig) GetSk() []byte {
	return s.Sk
}

// GetOrganizationalUnitIdentifier returns OU of the user associated with this signer config
func (s *SignerConfig) GetOrganizationalUnitIdentifier() string {
	return s.OrganizationalUnitIdentifier
}

// GetIsAdmin returns true if the user associated with this signer config is an admin, else
// returns false
func (s *SignerConfig) GetIsAdmin() bool {
	return s.IsAdmin
}

// GetEnrollmentID returns enrollment ID of the user associated with this signer config
func (s *SignerConfig) GetEnrollmentID() string {
	return s.EnrollmentID
}

// GetCertificateRevocationInformation returns CRI
func (s *SignerConfig) GetCertificateRevocationInformation() []byte {
	return s.CertificateRevocationInformation
}
