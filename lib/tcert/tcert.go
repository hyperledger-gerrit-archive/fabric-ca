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
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"math/big"
	"strconv"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/core/crypto/bccsp"
)

var (
	// TCertEncTCertIndex is the ASN1 object identifier of the TCert index.
	TCertEncTCertIndex = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	// TCertEncEnrollmentID is the ASN1 object identifier of the enrollment id.
	TCertEncEnrollmentID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 8}

	// TCertAttributesHeaders is the ASN1 object identifier of attributes header.
	TCertAttributesHeaders = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 9}

	// Padding for encryption.
	Padding = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

	//Enrollment Id Encryption Key
	enrollmentID = "enrollmentID"
	//Enrollment Id Key used in Key map
	enrollmentIDMapKey = "enrollmentId"
)

// LoadMgr constructs a TCert manager given files containing a signing key and a CA cert
// @parameter caKeyFile is the file name for the CA's key
// @parameter caCertFile is the file name for the CA's cert
func LoadMgr(caKeyFile, caCertFile string) (*Mgr, error) {
	caKey, err := LoadKey(caKeyFile)
	if err != nil {
		return nil, err
	}
	caCert, err := LoadCert(caCertFile)
	if err != nil {
		return nil, err
	}
	return NewMgr(caKey, caCert)
}

// NewMgr is the constructor for a TCert manager given a key and an x509 certificate
// @parameter caKey is used for signing a certificate request
// @parameter caCert is used for extracting CA data to associate with issued certificates
func NewMgr(caKey interface{}, caCert *x509.Certificate) (*Mgr, error) {
	mgr := new(Mgr)
	mgr.CAKey = caKey
	mgr.CACert = caCert
	mgr.ValidityPeriod = time.Hour * 24 * 365 // default to 1 year
	mgr.MaxAllowedBatchSize = 1000
	return mgr, nil
}

// Mgr is the manager for the TCert library
type Mgr struct {
	// CAKey is used for signing a certificate request
	CAKey interface{}
	// CACert is used for extracting CA data to associate with issued certificates
	CACert *x509.Certificate
	// ValidityPeriod is the duration that the issued certificate will be valid
	// unless the user requests a shorter validity period.
	// The default value is 1 year.
	ValidityPeriod time.Duration
	// MaxAllowedBatchSize is the maximum number of TCerts which can be requested at a time.
	// The default value is 1000.
	MaxAllowedBatchSize uint
	//bccsp contains instance of BCCSP. CoP Server BCCSP instance needs to be passed
	BCCSP bccsp.BCCSP
}

// GetBatch gets a batch of TCerts
// @parameter req Is the TCert batch request
// @parameter ecert Is the enrollment certificate of the caller
func (tm *Mgr) GetBatch(req *GetBatchRequest, ecert *x509.Certificate) (*GetBatchResponse, error) {

	log.Debugf("GetBatch req=%+v", req)

	// Set numTCertsInBatch to the number of TCerts to get.
	// If 0 are requested, retrieve the maximum allowable;
	// otherwise, retrieve the number requested it not too many.
	var numTCertsInBatch int
	if req.Count == 0 {
		numTCertsInBatch = int(tm.MaxAllowedBatchSize)
	} else if req.Count <= tm.MaxAllowedBatchSize {
		numTCertsInBatch = int(req.Count)
	} else {
		return nil, fmt.Errorf("You may not request %d TCerts; the maximum is %d",
			req.Count, tm.MaxAllowedBatchSize)
	}

	// Certs are valid for the min of requested and configured max
	vp := tm.ValidityPeriod
	if req.ValidityPeriod > 0 && req.ValidityPeriod < vp {
		vp = req.ValidityPeriod
	}

	// Generate nonce for TCertIndex
	nonce := make([]byte, 16) // 8 bytes rand, 8 bytes timestamp
	rand.Reader.Read(nonce[:8])

	pub := ecert.PublicKey.(*ecdsa.PublicKey)

	mac := hmac.New(sha512.New384, []byte(createHMACKey()))
	raw, _ := x509.MarshalPKIXPublicKey(pub)
	mac.Write(raw)
	kdfKey := mac.Sum(nil)

	var set []TCert

	for i := 0; i < numTCertsInBatch; i++ {
		tcertid, uuidError := GenerateIntUUID()
		if uuidError != nil {
			return nil, fmt.Errorf("Failure generating UUID: %s", uuidError)
		}
		// Compute TCertIndex
		tidx := []byte(strconv.Itoa(2*i + 1))
		tidx = append(tidx[:], nonce[:]...)
		tidx = append(tidx[:], Padding...)

		mac := hmac.New(sha512.New384, kdfKey)
		mac.Write([]byte{1})
		extKey := mac.Sum(nil)[:32]

		mac = hmac.New(sha512.New384, kdfKey)
		mac.Write([]byte{2})
		mac = hmac.New(sha512.New384, mac.Sum(nil))
		mac.Write(tidx)

		one := new(big.Int).SetInt64(1)
		k := new(big.Int).SetBytes(mac.Sum(nil))
		k.Mod(k, new(big.Int).Sub(pub.Curve.Params().N, one))
		k.Add(k, one)

		tmpX, tmpY := pub.ScalarBaseMult(k.Bytes())
		txX, txY := pub.Curve.Add(pub.X, pub.Y, tmpX, tmpY)
		txPub := ecdsa.PublicKey{Curve: pub.Curve, X: txX, Y: txY}

		// Compute encrypted TCertIndex
		encryptedTidx, encryptErr := CBCPKCS7Encrypt(extKey, tidx)
		if encryptErr != nil {
			return nil, encryptErr
		}

		extensions, ks, extensionErr := generateExtensions(tcertid, encryptedTidx, ecert, req)

		if extensionErr != nil {
			return nil, extensionErr
		}

		pem, certError := GenerateCertificate(vp, tcertid, extensions, &txPub, tm.CAKey, tm.CACert)
		if certError != nil {
			errorMessage := fmt.Sprintf("Failed to generate a Transaction Certificate (TCert) [%v]", certError)
			log.Error(errorMessage)
			return nil, errors.New(errorMessage)
		}

		set = append(set, TCert{pem, ks})
	}

	tcertID := GenNumber(big.NewInt(20))
	tcertResponse := &GetBatchResponse{tcertID, time.Now(), kdfKey, set}

	return tcertResponse, nil

}

// GetBatchForGeneratedKey returns batch of TCerts for locally generated Key
// This is used for HSM Friendly TCert generation , no Key Derivation
func (tm *Mgr) GetBatchForGeneratedKey(req *GetBatchRequest) (*GetBatchResponse, error) {
	log.Debugf("GetBatchForGeneratedKey req=%+v", req)
	var errorMessage string
	if req == nil {
		errorMessage = "GetBatchRequest Request is nil"
		log.Error(errorMessage)
		return nil, errors.New(errorMessage)
	}

	publicKeyList := req.PublicKeys
	noOfPublicKeys := len(publicKeyList)
	if noOfPublicKeys == 0 {
		errorMessage = "Public Key for TCert is not present"
		log.Error(errorMessage)
		return nil, errors.New(errorMessage)
	}

	var set []TCert
	for i := 0; i < noOfPublicKeys; i++ {
		tcertid, uuidError := GenerateIntUUID()
		if uuidError != nil {
			return nil, fmt.Errorf("UUID generation failed with error : %s", uuidError)
		}

		// Certs are valid for the min of requested and configured max
		vp := tm.ValidityPeriod
		if req.ValidityPeriod > 0 && req.ValidityPeriod < vp {
			vp = req.ValidityPeriod
		}

		extensions, ks, extensionErr := generateExtensions(tcertid, nil, nil, req)
		if extensionErr != nil {
			return nil, extensionErr
		}

		pubKey, publicKeyParseError := BytesToPublicKey(publicKeyList[i])
		if publicKeyParseError != nil {
			log.Errorf("Public Key Marshalling failed with error : [%v]", publicKeyParseError)
			return nil, publicKeyParseError
		}
		pem, certError := GenerateCertificate(vp, tcertid, extensions, pubKey.(*ecdsa.PublicKey), tm.CAKey, tm.CACert)
		if certError != nil {
			errorMessage = fmt.Sprintf("TCert Generation Failed with error : [%v]", certError)
			log.Error(errorMessage)
			return nil, errors.New(errorMessage)
		}
		set = append(set, TCert{pem, ks})

	}

	tcertID := GenNumber(big.NewInt(20))
	tcertResponse := &GetBatchResponse{tcertID, time.Now(), nil, set}

	return tcertResponse, nil

}

/**
*  Create HMAC Key
*  returns HMAC String
 */
func createHMACKey() string {
	key := make([]byte, 49)
	rand.Reader.Read(key)
	var cooked = base64.StdEncoding.EncodeToString(key)
	return cooked
}

// Generate encrypted extensions to be included into the TCert (TCertIndex, EnrollmentID and attributes).
func generateExtensions(tcertid *big.Int, tidx []byte, enrollmentCert *x509.Certificate, batchRequest *GetBatchRequest) ([]pkix.Extension, map[string][]byte, error) {
	// For each TCert we need to store and retrieve to the user the list of Ks used to encrypt the EnrollmentID and the attributes.
	ks := make(map[string][]byte)
	attrs := batchRequest.Attrs
	extensions := make([]pkix.Extension, len(attrs))

	preK1 := batchRequest.PreKey
	mac := hmac.New(sha512.New384, []byte(preK1))
	mac.Write(tcertid.Bytes())
	preK0 := mac.Sum(nil)

	var err error
	var encEnrollmentID []byte
	var enrollmentIDerr error
	// Compute encrypted EnrollmentID
	if enrollmentCert != nil {
		mac = hmac.New(sha512.New384, preK0)
		mac.Write([]byte(enrollmentID))
		enrollmentIDKey := mac.Sum(nil)[:32]

		enrollmentID := []byte(GetEnrollmentIDFromCert(enrollmentCert))
		enrollmentID = append(enrollmentID, Padding...)

		encEnrollmentID, enrollmentIDerr = CBCPKCS7Encrypt(enrollmentIDKey, enrollmentID)
		if enrollmentIDerr != nil {
			return nil, nil, enrollmentIDerr
		}

		// save k used to encrypt EnrollmentID
		ks[enrollmentIDMapKey] = enrollmentIDKey
	}

	attributeIdentifierIndex := 9
	count := 0
	attributesHeader := make(map[string]int)

	// Append attributes to the extensions slice
	for i := 0; i < len(attrs); i++ {
		count++
		name := attrs[i].Name
		value := []byte(attrs[i].Value)

		// Save the position of the attribute extension on the header.
		attributesHeader[name] = count

		// Encrypt attribute if enabled
		if batchRequest.EncryptAttrs {
			mac = hmac.New(sha512.New384, preK0)
			mac.Write([]byte(name))
			attributeKey := mac.Sum(nil)[:32]

			value = append(value, Padding...)
			value, err = CBCPKCS7Encrypt(attributeKey, value)
			if err != nil {
				return nil, nil, err
			}

			// Save the key used to encrypt the attribute
			ks[name] = attributeKey
		}

		// Generate an ObjectIdentifier for the extension holding the attribute
		TCertEncAttributes := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, attributeIdentifierIndex + count}

		// Add the attribute extension to the extensions array
		extensions[count-1] = pkix.Extension{Id: TCertEncAttributes, Critical: false, Value: value}
	}

	// Append the TCertIndex to the extensions
	if tidx != nil {
		extensions = append(extensions, pkix.Extension{Id: TCertEncTCertIndex, Critical: true, Value: tidx})
	}

	// Append the encrypted EnrollmentID to the extensions
	if enrollmentCert != nil {
		extensions = append(extensions, pkix.Extension{Id: TCertEncEnrollmentID, Critical: false, Value: encEnrollmentID})
	}

	// Append the attributes header if there was attributes to include in the TCert
	if len(attrs) > 0 {
		extensions = append(extensions, pkix.Extension{Id: TCertAttributesHeaders, Critical: false, Value: buildAttributesHeader(attributesHeader)})
	}

	return extensions, ks, nil
}

func buildAttributesHeader(attributesHeader map[string]int) []byte {
	var headerString string
	for k, v := range attributesHeader {
		headerString = headerString + k + "->" + strconv.Itoa(v) + "#"
	}
	return []byte(headerString)
}
