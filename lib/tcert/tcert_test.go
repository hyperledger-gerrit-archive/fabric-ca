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
	"bytes"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
)

func TestTCertWithoutAttribute(t *testing.T) {

	log.Level = log.LevelDebug

	resp, err := getTCertWithoutAttributes(t)

	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)

		return
	}
	if len(resp.TCerts) != 1 {
		t.Errorf("Returned incorrect number of TCerts: expecting 1 but found %d", len(resp.TCerts))
	}

}

func getTCertWithoutAttributes(t *testing.T) (*GetBatchResponse, error) {

	mgr := getMgr(t)
	if mgr == nil {
		return nil, errors.New("TCert Manager was not instantiated")
	}

	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return nil, errors.New("Cannot load ECert for testing")
	}

	resp, err := mgr.GetBatch(&GetBatchRequest{
		Count:  1,
		PreKey: "S5i15SgeDdd1pYVmaeA92B30Gq1cY8HHpoMHN5qpEu+ioK0gdUsJP2XI4wK43AQh",
	}, ecert)

	return resp, err
}

func TestTCertEnrollmentId(t *testing.T) {
	resp, err := getTCertWithoutAttributes(t)
	if err != nil {
		t.Errorf("GetBatch failed with error: %s", err)
		return
	}
	if len(resp.TCerts) != 1 {
		t.Errorf("Returned incorrect number of TCerts: expecting 1 but received %d", len(resp.TCerts))
	}

	tcerts := resp.TCerts
	tcert := tcerts[0] //assuming 1 tcert
	cert := tcert.Cert

	keys := tcert.Keys
	enrollmentIDKey := keys["enrollmentId"]

	encEnrollmentID, encEnrollErr := getEnrollIDFromTCert(cert)
	if encEnrollErr != nil {
		t.Errorf("Error retrieving enrollmentID:[%v]", encEnrollErr)
	}
	if encEnrollmentID == nil {
		t.Fatal("EnrollmentID in TCert in nil")
	}

	enrollmentID, decryptError := CBCPKCS7Decrypt(enrollmentIDKey, encEnrollmentID)
	if decryptError != nil {
		t.Errorf("EnrollmentID decryption failed with error [%v]", decryptError)
	}
	byteLength := len(enrollmentID) - 16
	enrollID := enrollmentID[:byteLength]

	enrollmentCert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		t.Errorf("Failed loading Enrollment Cert: %s", err)

	}
	certEnrollmentID := GetEnrollmentIDFromCert(enrollmentCert)

	if !bytes.Equal(enrollID, []byte(certEnrollmentID)) {
		t.Error("TCert EnrollmentID is not set up right")
	}

}

func getEnrollIDFromTCert(certBuf []byte) ([]byte, error) {
	if certBuf == nil {
		return nil, errors.New("Cert is nil")
	}
	cert, error := GetCertificate(certBuf)
	if error != nil {
		return nil, errors.New("Certificate cannot be created")
	}
	//Get Extension
	extraExtension := cert.Extensions
	extraExtensionLength := len(extraExtension)
	var extension pkix.Extension
	var id asn1.ObjectIdentifier
	var critical bool
	var value []byte
	for i := 0; i < extraExtensionLength; i++ {
		extension = extraExtension[i]
		id = extension.Id
		critical = extension.Critical
		if id.Equal(TCertEncEnrollmentID) && !critical {
			value = extension.Value

		}
	}

	return value, nil

}

func TestTCertWitAttributes(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager
	mgr := getMgr(t)

	if mgr == nil {
		return
	}

	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}
	var Attrs = []Attribute{
		{
			Name:  "SSN",
			Value: "123-456-789",
		},

		{
			Name:  "Income",
			Value: "USD",
		},
	}
	resp, err := mgr.GetBatch(&GetBatchRequest{
		Count:        10,
		EncryptAttrs: true,
		Attrs:        Attrs,
		PreKey:       "S5i15SgeDdd1pYVmaeA92B30Gq1cY8HHpoMHN5qpEu+ioK0gdUsJP2XI4wK43AQh",
	}, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 10 {
		t.Errorf("Returned incorrect number of certs: expecting 10 but found %d", len(resp.TCerts))
	}

}

func TestTCertWithClientGeneratedKeyWithoutAttribute(t *testing.T) {
	mgr := getMgr(t)
	if mgr == nil {
		return
	}

	publicKeySet, publicKeyError := generateTestPublicKeys(t)
	if publicKeyError != nil {
		t.Logf("Error in generatingc[%v]", publicKeyError)
	}
	duration, durartionParseerror := time.ParseDuration("10h")
	if durartionParseerror != nil {
		t.Logf("time parse error [%v]", durartionParseerror)
	}
	tcertResponse, tcertResponseError := mgr.GetBatchForGeneratedKey(&GetBatchRequest{
		PreKey:         "anyroot",
		ValidityPeriod: duration,
		PublicKeys:     publicKeySet,
	})
	if tcertResponseError != nil {
		t.Errorf("Error from GetBatchForGeneratedKey: %s", tcertResponseError)
		return
	}
	if len(tcertResponse.TCerts) != 2 {
		t.Errorf("Returned incorrect number of certs: expecting 2 but found %d", len(tcertResponse.TCerts))
	}

}

func TestTCertWithClientGeneratedKeyWithAttribute(t *testing.T) {
	mgr := getMgr(t)
	if mgr == nil {
		return
	}

	publicKeySet, publicKeyError := generateTestPublicKeys(t)
	if publicKeyError != nil {
		t.Logf("Error in generating public key [%v]", publicKeyError)
	}
	duration, durartionParseerror := time.ParseDuration("10h")
	if durartionParseerror != nil {
		t.Logf("time parse error [%v]", durartionParseerror)
	}
	var Attrs = []Attribute{
		{
			Name:  "SSN",
			Value: "123-456-789",
		},

		{
			Name:  "Income",
			Value: "USD",
		},
	}

	tcertResponse, tcertResponseError := mgr.GetBatchForGeneratedKey(&GetBatchRequest{
		PreKey:         "S5i15SgeDdd1pYVmaeA92B30Gq1cY8HHpoMHN5qpEu+ioK0gdUsJP2XI4wK43AQh",
		ValidityPeriod: duration,
		EncryptAttrs:   true,
		Attrs:          Attrs,
		PublicKeys:     publicKeySet,
	})
	if tcertResponseError != nil {
		t.Errorf("Error from GetBatchForGeneratedKey: %s", tcertResponseError)
		return
	}
	if len(tcertResponse.TCerts) != 2 {
		t.Errorf("Returned incorrect number of certs: expecting 2 but found %d", len(tcertResponse.TCerts))
	}

}

func generateTestPublicKeys(t *testing.T) ([][]byte, error) {
	//Generate Key Pair and Crete Map
	var privKey *ecdsa.PrivateKey
	var publicKeyraw []byte
	var pemEncodedPublicKey []byte
	var privKeyError error
	var pemEncodingError error
	var set [][]byte
	for i := 0; i < 2; i++ {
		privKey, privKeyError = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if privKeyError != nil {
			t.Logf("Error  == [%v] ==  generating Private Key ", privKeyError)
			return nil, privKeyError
		}

		publicKeyraw, pemEncodingError = x509.MarshalPKIXPublicKey(privKey.Public())
		if pemEncodingError != nil {
			t.Logf("Error == [%v] == pem encoding public Key", pemEncodingError)
			return nil, pemEncodingError
		}
		pemEncodedPublicKey = ConvertDERToPEM(publicKeyraw, "PUBLIC KEY")

		set = append(set, pemEncodedPublicKey)
	}
	return set, nil
}

func getMgr(t *testing.T) *Mgr {
	keyFile := "../../testdata/ec-key.pem"
	certFile := "../../testdata/ec.pem"
	mgr, err := LoadMgr(keyFile, certFile)
	if err != nil {
		t.Errorf("Failed loading mgr: %s", err)
		return nil
	}
	return mgr
}
