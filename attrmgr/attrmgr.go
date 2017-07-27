/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
 * The attrmgr package contains utilities for managing attributes.
 * Attributes are added to an X509 certificate as an extension, while
 * any keys for encrypted attributes are not part of the certificate.
 */

package attrmgr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
)

var (
	// AttrOID is the ASN.1 object identifier for an attribute extension in an
	// X509 certificate
	AttrOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 9}
	// AttrOIDString is the string version of AttrOID
	AttrOIDString = "1.2.3.4.5.6.9"
)

// Attribute is a name/value pair
type Attribute interface {
	// GetName returns the name of the attribute
	GetName() string
	// GetValue returns the value of the attribute
	GetValue() string
}

// AttributeRequest is a request for an attribute
type AttributeRequest interface {
	// GetName returns the name of an attribute
	GetName() string
	// IsRequired returns true if the attribute is required
	IsRequired() bool
	// ShouldEncrypt returns true if the attribute should be encrypted
	ShouldEncrypt() bool
}

// New constructs an attribute manager
func New(csp bccsp.BCCSP) *Mgr {
	if csp == nil {
		csp = factory.GetDefault()
	}
	return &Mgr{csp: csp}
}

// Mgr is the attribute manager and is the main object for this package
type Mgr struct {
	csp bccsp.BCCSP
}

// ProcessAttributeRequestsForCert processes attribute requests over attributes,
// adds the public attribute info to the certificate, and returns the secret
// attribute info (if any).
func (mgr *Mgr) ProcessAttributeRequestsForCert(reqs []AttributeRequest, attrs []Attribute, cert *x509.Certificate) (string, error) {
	pai, sai, err := mgr.ProcessAttributeRequests(reqs, attrs)
	if err != nil {
		return "", err
	}
	mgr.AddAttributesToCert(pai, cert)
	return sai, nil
}

// ProcessAttributeRequests takes an array of attribute requests and an identity's attributes
// and returns PublicAttrInfo and SecretAttrInfo as serialized strings.
// The PublicAttrInfo goes inside the certificate and the SecretAttrInfo is separate from the certificate.
func (mgr *Mgr) ProcessAttributeRequests(reqs []AttributeRequest, attrs []Attribute) (string, string, error) {
	var key, val []byte
	var err error
	pai := newPublicAttrInfo()
	sai := newSecretAttrInfo()
	missingRequiredAttrs := []string{}
	// For each of the attribute requests
	for _, req := range reqs {
		// Get the attribute
		name := req.GetName()
		attr := getAttrByName(name, attrs)
		if attr == nil {
			if req.IsRequired() {
				// Didn't find attribute and it was required; return error below
				missingRequiredAttrs = append(missingRequiredAttrs, name)
			}
			continue
		}
		value := attr.GetValue()
		if req.ShouldEncrypt() {
			// Create a new key and encrypt the attribute value with the key
			key, val, err = encryptString(value, mgr.csp)
			if err != nil {
				return "", "", err
			}
			// Add the encrypted value to the public attribute info and
			// the name, key, and index to the secret attribute info
			err = sai.add(name, key, pai.add("", val))
			if err != nil {
				return "", "", err
			}
		} else {
			// Add name and value to the public attribute info
			pai.add(name, []byte(value))
		}
	}
	if len(missingRequiredAttrs) > 0 {
		return "", "", fmt.Errorf("The following required attributes are missing: %+v",
			missingRequiredAttrs)
	}
	mpai, err := marshal("PublicAttrInfo", pai)
	if err != nil {
		return "", "", err
	}
	msai, err := marshal("SecretAttrInfo", sai)
	if err != nil {
		return "", "", err
	}
	return mpai, msai, nil
}

// AddAttributesToCert adds public attribute info to an X509 certificate.
func (mgr *Mgr) AddAttributesToCert(publicAttrInfo string, cert *x509.Certificate) {
	ext := pkix.Extension{
		Id:       AttrOID,
		Critical: false,
		Value:    []byte(publicAttrInfo),
	}
	cert.Extensions = append(cert.Extensions, ext)
}

// GetAttributesFromCert gets the attributes from a certificate and any secret info
// that is not part of the certificate.
func (mgr *Mgr) GetAttributesFromCert(cert *x509.Certificate, secretAttrInfo string) (*Attributes, error) {
	// We will read from 'pai' and 'sai' and populate 'attrs'
	pai := newPublicAttrInfo()
	sai := newSecretAttrInfo()
	attrs := map[string]*attrInfo{}
	// Get certificate attribute info from the certificate if it exists
	cai, err := getAttrInfoFromCert(cert)
	if err != nil {
		return nil, err
	}
	if cai != nil {
		// Populate the PublicAttrInfo structure from serialized string from cert
		err = unmarshal("public attribute info", string(cai), pai)
		if err != nil {
			return nil, err
		}
	}
	// Populate 'sai' with attribute info in the 'secretAttrInfo' parameter
	if secretAttrInfo != "" {
		err = unmarshal("secret attribute info", secretAttrInfo, sai)
		if err != nil {
			return nil, err
		}
	}
	// The attributes in 'pai' with a name are not encrypted, so add
	// them to attrs without a key.
	for _, pa := range pai.Attrs {
		if pa.Name != "" {
			attrs[pa.Name] = &attrInfo{Value: pa.Value}
		}
	}
	// The attributes in 'sai' are encrypted
	// The key is in 'sai' and the encrypted value is in 'pai'
	log.Debugf("Secret attributes: %+v", sai.Attrs)
	for name, sa := range sai.Attrs {
		attrs[name] = &attrInfo{
			Key:   sa.Key,
			Value: pai.Attrs[sa.Idx].Value,
		}
	}
	log.Debugf("GetAttributesFromCert returned: %+v", attrs)
	// Return the attributes object
	return &Attributes{csp: mgr.csp, attrs: attrs}, nil
}

func newPublicAttrInfo() *PublicAttrInfo {
	pai := new(PublicAttrInfo)
	pai.Attrs = []*PublicAttr{}
	return pai
}

// PublicAttrInfo is public attribute info which goes into a certificate
type PublicAttrInfo struct {
	Attrs []*PublicAttr
}

// Add an attribute name and value and return the index
func (pai *PublicAttrInfo) add(name string, value []byte) int {
	pai.Attrs = append(pai.Attrs, &PublicAttr{Name: name, Value: value})
	return len(pai.Attrs) - 1
}

// PublicAttr is an attribute as stored publically in the certificate
type PublicAttr struct {
	Name  string // nil if attribute is encrypted
	Value []byte
}

func newSecretAttrInfo() *SecretAttrInfo {
	sai := new(SecretAttrInfo)
	sai.Attrs = map[string]*SecretAttr{}
	return sai
}

// SecretAttrInfo is attribute info which does NOT go into the certificate
type SecretAttrInfo struct {
	Attrs map[string]*SecretAttr
}

func (sai *SecretAttrInfo) add(name string, key []byte, idx int) error {
	if sai.Attrs[name] != nil {
		return fmt.Errorf("attribute '%s' is already set", name)
	}
	sai.Attrs[name] = &SecretAttr{Key: key, Idx: idx}
	return nil
}

// SecretAttr is the secret part of an attribute
type SecretAttr struct {
	Key []byte // key for encrypted attribute values
	Idx int    // index into the certAttrInfo.attrs array
}

type attrInfo struct {
	Key, Value []byte
}

// Attributes is the object for reading attribute names and values
type Attributes struct {
	csp   bccsp.BCCSP
	attrs map[string]*attrInfo
}

// Names returns the names of the attributes
func (a *Attributes) Names() []string {
	i := 0
	names := make([]string, len(a.attrs))
	for name := range a.attrs {
		names[i] = name
		i++
	}
	return names
}

// Contains returns true if the named attribute is found
func (a *Attributes) Contains(name string) bool {
	_, ok := a.attrs[name]
	return ok
}

// Value returns an attribute's value
func (a *Attributes) Value(name string) (string, bool, error) {
	attr, ok := a.attrs[name]
	if !ok {
		// Doesn't contain this attribute
		return "", false, nil
	}
	if attr.Key == nil {
		// The value is not encrypted, so just return it as is
		return string(attr.Value), true, nil
	}
	val, err := decryptString(attr.Key, attr.Value, a.csp)
	if err != nil {
		return "", true, err
	}
	return val, true, nil
}

// Get the attribute info from a certificate extension, or return nil if not found
func getAttrInfoFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if isAttrOID(ext.Id) {
			return []byte(ext.Value), nil
		}
	}
	return nil, nil
}

// Is the object ID equal to the attribute info object ID?
func isAttrOID(oid asn1.ObjectIdentifier) bool {
	if len(oid) != len(AttrOID) {
		return false
	}
	for idx, val := range oid {
		if val != AttrOID[idx] {
			return false
		}
	}
	return true
}

// Get an attribute from 'attrs' by its name, or nil if not found
func getAttrByName(name string, attrs []Attribute) Attribute {
	for _, attr := range attrs {
		if attr.GetName() == name {
			return attr
		}
	}
	return nil
}

// marshal and return string
func marshal(name string, obj interface{}) (string, error) {
	buf, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal %s: %s", name, err)
	}
	return string(buf), nil
}

// unmarshal string and populate object
func unmarshal(name string, str string, obj interface{}) error {
	err := json.Unmarshal([]byte(str), obj)
	if err != nil {
		return fmt.Errorf("Invalid %s: %s", name, err)
	}
	return nil
}

// tmpKey and the associated logic below will be removed once changes to
// bccsp have been made to allow the bkey.Bytes() call below to work.
// I can't currently create an instance of aesPrivateKey with exportable set to true.
// See https://jira.hyperledger.org/browse/FAB-5736
var tmpKey = "key"

// Create a new key and use it to encrypt 'str'.
// Return the key and the cipher text.
func encryptString(str string, csp bccsp.BCCSP) ([]byte, []byte, error) {
	// BEGIN TO BE REMOVED
	if tmpKey != "" {
		return []byte(tmpKey), []byte(hex.EncodeToString([]byte(str))), nil
	}
	// END TO BE REMOVED
	bkey, err := csp.KeyGen(&bccsp.AESKeyGenOpts{Temporary: true})
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate key: %s", err)
	}
	key, err := bkey.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to serialize key: %s", err)
	}
	cipherText, err := csp.Encrypt(bkey, []byte(str), &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		return nil, nil, fmt.Errorf("Encryption failure: %s", err)
	}
	return key, cipherText, nil
}

// Decrypt a string given the key and cipher text
func decryptString(key []byte, cipherText []byte, csp bccsp.BCCSP) (string, error) {
	// BEGIN TO BE REMOVED
	if tmpKey != "" {
		if string(key) != tmpKey {
			return "", errors.New("Invalid decryption key")
		}
		ct, err := hex.DecodeString(string(cipherText))
		if err != nil {
			return "", fmt.Errorf("Failed to decode cipher text: %s", err)
		}
		return string(ct), nil
	}
	// END TO BE REMOVED
	// Import the key
	k, err := csp.KeyImport(key, &bccsp.AES256ImportKeyOpts{})
	if err != nil {
		return "", fmt.Errorf("Failed to import key: %s", err)
	}
	// Decrypt using key
	val, err := csp.Decrypt(k, cipherText, bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		return "", fmt.Errorf("Decryption failure: %s", err)
	}
	return string(val), nil
}
