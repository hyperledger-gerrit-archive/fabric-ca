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
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/rand"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric/bccsp/factory"
)

//ECDSASignature forms the structure for R and S value for ECDSA
type ECDSASignature struct {
	R, S *big.Int
}

func TestGenNumber(t *testing.T) {
	num := GenNumber(big.NewInt(20))
	if num == nil {
		t.Fatalf("Failed in GenNumber")
	}
}

func TestECCertificate(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ec.pem")
	if err != nil {
		t.Fatalf("Cannot read EC Certificate from file system")
	}
	_, error := GetCertificate(publicKeyBuff)
	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t : %s", error)
	}
}

func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {

	// Note: The purpose of this test is not to test AES-256 in CBC mode's strength
	// ... but rather to verify the code wrapping/unwrapping the cipher.
	key := make([]byte, AESKeyLength)
	rand.Reader.Read(key)

	var ptext = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %s", ptext, dErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}

}

func TestPreKey(t *testing.T) {
	rootKey := CreateRootPreKey()
	if len(rootKey) == 0 {
		t.Fatal("Root Key Cannot be generated")
	}

}

func TestSerialNumber(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ec.pem")
	if err != nil {
		t.Fatal("Cannot read EC Certificate from file system")
	}
	_, error := GetCertitificateSerialNumber(publicKeyBuff)

	if error != nil {
		t.Fatalf("EC certificate creation failed with error : %s", error)
	}

}

func TestGetBadCertificate(t *testing.T) {
	buf, err := ioutil.ReadFile("../../testdata/testconfig.json")
	if err != nil {
		t.Fatalf("Cannot read certificate from file system")
	}

	_, err = GetCertificate([]byte(buf))
	if err == nil {
		t.Fatalf("Should have failed with error :%s since file is json ", err)
	}
}

func TestGenerateUUID(t *testing.T) {
	_, err := GenerateIntUUID()
	if err != nil {
		t.Errorf("GenerateIntUUID failed: %s", err)
	}
}

func TestDerToPem(t *testing.T) {

	buf, err := ioutil.ReadFile("../../testdata/ecTest.der")
	if err != nil {
		t.Fatalf("Cannot read Certificate in DER format: %s", err)
	}
	cert := ConvertDERToPEM(buf, "CERTIFICATE")
	if cert == nil {
		t.Fatalf("Failed to ConvertDERToPEM")
	}
}

func TestValidateTCertBatchRequest(t *testing.T) {

	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	bccsp := mgr.BCCSP
	if bccsp == nil {
		t.Error("BCCSP instance was not found")
	}
	batchRequest := new(api.GetTCertBatchRequest)
	batchRequest.EncryptAttrs = false
	batchRequest.Count = 2

	keySigBatch, batchError := GetKeySigBatch(bccsp, batchRequest)
	if batchError != nil {
		t.Error("Unable to generate Key Sig Batch request")
	}
	if len(keySigBatch) == 0 {
		t.Error("Error in Batch of Signature and Key Pair ")
	}

	batchRequestNet := new(api.GetTCertBatchRequestNet)
	batchRequestNet.GetTCertBatchRequest = *batchRequest
	batchRequestNet.KeySigs = keySigBatch

	verified, verificationError := mgr.VerifyTCertBatchRequest(batchRequestNet)
	if !verified {
		t.Error(" Signature Validation failed in VerifyTCertBatchRequest")
	}
	if verificationError != nil {
		t.Errorf("Signature Validation failed with error : %s", verificationError)
	}
}

func TestSignatureValidation(t *testing.T) {
	//This  test test BCCSP implementation
	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	bccsp := mgr.BCCSP
	if bccsp == nil {
		t.Error("BCCSP instance is not available")
	}

	var signError, validationError error
	var isValid bool

	ecSignature, pubASN1, signError := ECDSASignDirect(bccsp, "SHA2_256")
	if signError != nil {
		t.Errorf("BCCSP signature failed with error : %s", signError)
	}
	keySig := api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA2_256",
	}

	//Create KeySig struct
	isValid, validationError = mgr.VerifyMessage(keySig)
	if !isValid {
		t.Errorf("Signature Validation Failed")
	}
	if validationError != nil {
		t.Errorf("Signature Validation with SHA2_256 digest algorithm failed with error : %s", validationError)
	}

	ecSignature, pubASN1, signError = ECDSASignDirect(bccsp, "SHA2_384")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	keySig = api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA2_384",
	}

	isValid, validationError = mgr.VerifyMessage(keySig)
	if !isValid {
		t.Errorf("Signature Validation Failed")
	}
	if validationError != nil {
		t.Errorf("Signature Validation with SHA2_384 digest algorithm failed with error: %s", validationError)
	}

	ecSignature, pubASN1, signError = ECDSASignDirect(bccsp, "SHA3_256")
	if signError != nil {
		t.Errorf("ECDSA Signature Creation failed with error : %s ", signError)
	}

	keySig = api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA3_256",
	}

	isValid, validationError = mgr.VerifyMessage(keySig)
	if !isValid {
		t.Errorf("Signature Validation Failed")
	}
	if validationError != nil {
		t.Errorf("Signature Validation with SHA3_256 digest algorithm failed with error : %s", validationError)
	}

	ecSignature, pubASN1, signError = ECDSASignDirect(bccsp, "SHA3_384")
	if signError != nil {
		t.Errorf("ECDSA Signature Creartion failed with error : %s", signError)
	}

	keySig = api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA3_384",
	}
	isValid, validationError = mgr.VerifyMessage(keySig)
	if !isValid {
		t.Errorf("Signature Validation Failed")
	}
	if validationError != nil {
		t.Errorf("Signature Validation with SHA3_384 digest algorithm failed with error : %s", validationError)
	}
}

func TestInvalidSignature(t *testing.T) {

	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	bccsp := mgr.BCCSP
	if bccsp == nil {
		t.Error("BCCSP instance is not availble")
	}
	var signError, validationError error
	var isValid bool
	ecSignature, pubASN1, signError := ECDSASignDirect(bccsp, "SHA2_256")
	if signError != nil {
		t.Errorf("ECDSA Signature creation failed with error :%s", signError)
	}

	keySig := api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA2_384",
	}
	isValid, validationError = mgr.VerifyMessage(keySig)
	if isValid {
		t.Errorf("Signature Validation should have Failed")
	}
	if validationError == nil {
		t.Errorf("Signature Validation with SHA2_256 digest algorithm failed with error : %s", validationError)
	}

}

func TestPubkeyArrayFromBatchRequest(t *testing.T) {

	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	bccsp := mgr.BCCSP
	if bccsp == nil {
		t.Error("BCCSP instance is not availble")
	}

	//Generate Test Public Key buffer
	getBatch := new(api.GetTCertBatchRequest)
	getBatch.Count = 1

	pubKeySigBatch, error := GetKeySigBatch(bccsp, getBatch)
	if error != nil {
		t.Logf("Public Key generation failed : %s", error)
	}

	getBatchNet := new(api.GetTCertBatchRequestNet)
	getBatchNet.GetTCertBatchRequest = *getBatch
	getBatchNet.KeySigs = pubKeySigBatch

	pubKeyByteArray, error := BatchRequestToPubkeyBuff(getBatchNet)
	if error != nil {
		t.Errorf("Getting publicKey from Batch Request failed with error : %s", error)
	}
	if len(pubKeyByteArray) == 0 {
		t.Error("No public key byte array returned")
	}
}

func getTCertMgr(t *testing.T) *Mgr {

	defaultBccsp, bccspError := factory.GetDefault()
	if bccspError != nil {
		t.Errorf("BCCSP initialiazation failed with error : %s", bccspError)
	}
	if defaultBccsp == nil {
		t.Error("Cannot get default instance of BCCSP")
	}

	caKey := "../../testdata/ec-key.pem"
	caCert := "../../testdata/ec.pem"

	mgr, err := LoadMgr(caKey, caCert)
	if err != nil {
		t.Errorf("Failed creating TCert manager: %s", err)
		return nil
	}
	mgr.BCCSP = defaultBccsp
	return mgr
}
