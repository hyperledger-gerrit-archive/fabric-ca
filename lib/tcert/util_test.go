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
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/rand"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric/bccsp"
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
	batchRequest := new(api.GetTCertBatchRequestNet)
	batchRequest.EncryptAttrs = false

	keySigBatch, batchError := GetTemporalBatch(bccsp, batchRequest, 2)
	if batchError != nil {
		t.Error("Unable to generate Temporal Batch request")
	}
	if len(keySigBatch) == 0 {
		t.Error("Error in Batch of Signature and Key Pair ")
	}

	batchRequest.KeySigs = keySigBatch

	verified, verificationError := mgr.VerifyTCertBatchRequest(batchRequest)
	if !verified {
		t.Error(" Signature Validation failed in VerifyTCertBatchRequest")
	}
	if verificationError != nil {
		t.Errorf("Signature Validation failed with error : %s", verificationError)
	}
}

func TestSignatureValidation(t *testing.T) {

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
	getBatch := new(api.GetTCertBatchRequestNet)
	getBatch.Count = 1

	pubKeySigBatch, error := GetTemporalBatch(bccsp, getBatch, 1)
	if error != nil {
		t.Logf("Public Key generation failed : %s", error)
	}

	getBatch.KeySigs = pubKeySigBatch

	pubKeyByteArray, error := BatchRequestToPubkeyBuff(getBatch)
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

func GetTemporalBatch(bccsp bccsp.BCCSP, batchRequest *api.GetTCertBatchRequestNet, count int) ([]api.KeySig, error) {

	var tempCrypto api.KeySig

	var set []api.KeySig
	for i := 0; i < count; i++ {
		ecSignature, pubASN1, signError := ECDSASignDirect(bccsp, "SHA2_256")
		if signError != nil {
			return nil, signError
		}
		tempCrypto = api.KeySig{Key: pubASN1, Sig: ecSignature, Alg: "ecdsa-with-SHA2_256"}

		set = append(set, tempCrypto)

	}

	return set, nil
}

// ECDSASignDirect Signs message using ECDSA using BCCSP
// @returns Signature byte , Public Key byte and error
func ECDSASignDirect(currentBCCSP bccsp.BCCSP, hashAlgo string) ([]byte, []byte, error) {

	if currentBCCSP == nil {
		return nil, nil, errors.New("BCCSP instance is not available")
	}

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		return nil, nil, fmt.Errorf("BCCSP Key Generation failed with error %s", err)
	}

	publicKey, pubKeyError := k.PublicKey()
	if pubKeyError != nil {
		return nil, nil, fmt.Errorf("Public key rertrieval failed with error :%s", pubKeyError)
	}
	pubkeyRaw, byteError := publicKey.Bytes()
	if byteError != nil {
		return nil, nil, fmt.Errorf("Public key to Byte Conversion failed with error :%s", byteError)
	}

	var digest []byte
	var digestError error
	switch hashAlgo {
	case "SHA2_256":
		digest, digestError = currentBCCSP.Hash(pubkeyRaw, &bccsp.SHA256Opts{})
	case "SHA2_384":
		digest, digestError = currentBCCSP.Hash(pubkeyRaw, &bccsp.SHA384Opts{})
	case "SHA3_256":
		digest, digestError = currentBCCSP.Hash(pubkeyRaw, &bccsp.SHA3_256Opts{})
	case "SHA3_384":
		digest, digestError = currentBCCSP.Hash(pubkeyRaw, &bccsp.SHA3_384Opts{})
	default:
		digest = nil
		digestError = errors.New("Right Hash Algorithm is not passed")

	}
	if digestError != nil {

		return nil, nil, fmt.Errorf("Digest operation failed with error:%s", digestError)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("BCCSP signature generation failed with error :%s", err)
	}
	if len(signature) == 0 {
		return nil, nil, errors.New("BCCSP signature creation failed. Signature must be different than nil")
	}

	return signature, pubkeyRaw, nil
}
