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

package tcert

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// TCert is an object encapsulating various pieces of a transaction certificate
type TCert struct {
	// ASN1-encoded certificate which is part of a transaction payload signed by 'signer'
	Cert []byte `json:"cert"`
	// Keys which is part of a transient field of a transaction and used to look up
	// and unlock the enrollment ID and attributes which are in the extensions fields
	// of the 'Cert' (i.e. the ASN1-encoded certificate).
	Keys *CertKeys
	// private fields used by lib/tcert package
	signer crypto.Signer
	cert   *x509.Certificate
}

// GetCert returns the x509 certificate associated with this TCert
func (t *TCert) GetCert() (*x509.Certificate, error) {
	if t.cert != nil {
		return t.cert, nil
	}
	cert, err := x509.ParseCertificate(t.Cert)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %s", err)
	}
	t.cert = cert
	return cert, nil
}

// GetEnrollmentID returns the enrollment ID associated with the TCert.
func (t *TCert) GetEnrollmentID() (string, error) {
	val, err := t.GetExtensionValue("enrollmentID", tcertEnrollmentIDOID, t.Keys.EnrollmentID)
	if err != nil {
		return "", err
	}
	return string(val[:]), nil
}

// GetSigner returns the signer associated with this transaction certificate, or nil if not set
func (t *TCert) GetSigner() crypto.Signer {
	return t.signer
}

// GetAttributeNames returns the names of attributes in this tcert
func (t *TCert) GetAttributeNames() []string {
	names := make([]string, len(t.Keys.Attributes))
	idx := 0
	for name := range t.Keys.Attributes {
		names[idx] = name
		idx++
	}
	return names
}

// HasAttribute returns the value of an attribute
func (t *TCert) HasAttribute(name string) bool {
	_, ok := t.Keys.Attributes[name]
	return ok
}

// GetAttributeValue returns the value of an attribute from the certificate
func (t *TCert) GetAttributeValue(name string) ([]byte, error) {
	attrKey, ok := t.Keys.Attributes[name]
	if !ok {
		return nil, fmt.Errorf("Attribute '%s' was not found in transaction certificate", name)
	}
	oid := attrIndexToOID(attrKey.Index)
	what := fmt.Sprintf("attribute '%s'", name)
	return t.GetExtensionValue(what, oid, attrKey.Key)
}

// GetAttributes returns the attributes from this certificate for which there
// is an attribute key.
func (t *TCert) GetAttributes() ([]Attribute, error) {
	names := t.GetAttributeNames()
	attrs := make([]Attribute, len(names))
	for i, name := range names {
		value, err := t.GetAttributeValue(name)
		if err != nil {
			return nil, err
		}
		attrs[i].Name = name
		attrs[i].Value = string(value[:])
	}
	return attrs, nil
}

// GetExtensionValue returns the value of an extension in a TCert.
func (t *TCert) GetExtensionValue(what string, oid asn1.ObjectIdentifier, decryptionKey []byte) ([]byte, error) {
	cert, err := t.GetCert()
	if err != nil {
		return nil, err
	}
	val := getExtensionValueFromCert(cert, oid)
	if val == nil {
		return nil, fmt.Errorf("Value of %s was not found in transaction certificate", what)
	}
	if decryptionKey != nil {
		val, err = CBCPKCS7Decrypt(decryptionKey, val)
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt value of %s: %s", what, err)
		}
	}
	return val, nil
}

// CertKeys contains keys for accessing the enrollment ID and attributes inside a transaction certificate
type CertKeys struct {
	// The decryption key for the enrollment ID inside the certificate
	EnrollmentID []byte `json:"enrollmentid"`
	// The map of attribute names to attribute indices and decryption keys
	Attributes map[string]AttributeKey `json:"attrkeys,omitempty"`
}

// AttributeKey consists of an index and optional encryption key
type AttributeKey struct {
	Index int    `json:"idx"`
	Key   []byte `json:"key,omitempty"`
}

// attrIndexToOID converts an attribute index to an ASN1 object identitier
func attrIndexToOID(idx int) asn1.ObjectIdentifier {
	return newOID(oidAttrBase + idx)
}

// oidToAttrIndex converts an ASN1 object identitier to an attribute index
func oidToAttrIndex(oid asn1.ObjectIdentifier) int {
	return oidSuffix(oid) - oidAttrBase
}

// newOID creates an ASN1 object identitier as used by the tcert library
func newOID(suffix int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, suffix}
}

// oidSuffix returns the suffix associated with the object identifier
func oidSuffix(oid asn1.ObjectIdentifier) int {
	return oid[len(oid)-1]
}
