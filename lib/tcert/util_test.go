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
	"encoding/asn1"
	"errors"
	"hash"
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric/core/crypto/bccsp/factory"
	"golang.org/x/crypto/sha3"
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
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
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
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
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
		t.Fatalf("Cannot read EC Certificate from file system")
	}
	_, error := GetCertitificateSerialNumber(publicKeyBuff)

	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
	}

}

func TestGetBadCertificate(t *testing.T) {
	buf, err := ioutil.ReadFile("../../testdata/cop.json")
	if err != nil {
		t.Fatalf("Cannot read certificate from file system")
	}

	_, err = GetCertificate([]byte(buf))
	if err == nil {
		t.Fatalf("Should have failed since file is json:\t [%v] ", err)
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
	batchRequest := api.GetTCertBatchRequestNet{
		GetBatchRequest: api.GetTCertBatchRequest{
			EncryptAttrs: false,
		},
	}

	keySigBatch, batchError := GetTemporalBatch(&batchRequest, 2)
	if batchError != nil {
		t.Error("Unable to generate Temporal Batch request")
	}
	if len(keySigBatch) == 0 {
		t.Error("Error in Batch of Signature and Key Pair ")
	}

	getBatch := api.GetTCertBatchRequestNet{
		GetBatchRequest: api.GetTCertBatchRequest{
			EncryptAttrs: false,
		},
		KeySigs: keySigBatch,
	}
	verified, verificationError := mgr.VerifyTCertBatchRequest(&getBatch)
	if !verified {
		t.Error(" Signature Validation failed in VerifyTCertBatchRequest")
	}
	if verificationError != nil {
		t.Errorf("Signature Validation failed with error [%v]", verificationError)
	}
}

func TestSignatureValidation(t *testing.T) {

	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	//Get Public Key and Signature
	priv, privKeyErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if privKeyErr != nil {
		t.Errorf("Key Generation failed with error : [%v]", privKeyErr)
	}
	pubASN1, marshallError := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if marshallError != nil {
		t.Errorf("Public Key Marshalling failed with error : [%v]", marshallError)
	}
	var r, s *big.Int
	var signError, validationError error
	var isValid bool
	r, s, signError = ECDSASignDirect(priv, pubASN1, "SHA2_256")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	ecSignature, marshallError := asn1.Marshal(ECDSASignature{r, s})
	if marshallError != nil {
		t.Errorf("EC Signature Marshalling failed with error : %s", marshallError)
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
		t.Errorf("Signature Validation with SHA2_256 digest algorithm failed with error : [%v]", validationError)
	}

	r, s, signError = ECDSASignDirect(priv, pubASN1, "SHA2_384")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	ecSignature, marshallError = asn1.Marshal(ECDSASignature{r, s})
	if marshallError != nil {
		t.Errorf("EC Signature Marshalling failed with error : %s", marshallError)
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
		t.Errorf("Signature Validation with SHA2_384 digest algorithm failed with error  :[%v]", validationError)
	}

	r, s, signError = ECDSASignDirect(priv, pubASN1, "SHA3_256")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	ecSignature, marshallError = asn1.Marshal(ECDSASignature{r, s})
	if marshallError != nil {
		t.Errorf("EC Signature Marshalling failed with error : %s", marshallError)
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
		t.Errorf("Signature Validation with SHA3_256 digest algorithm failed with error : [%v]", validationError)
	}

	r, s, signError = ECDSASignDirect(priv, pubASN1, "SHA3_384")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	ecSignature, marshallError = asn1.Marshal(ECDSASignature{r, s})
	if marshallError != nil {
		t.Errorf("EC Signature Marshalling failed with error : %s", marshallError)
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
		t.Errorf("Signature Validation with SHA3_384 digest algorithm failed with error : [%v]", validationError)
	}
}

func TestInvalidSignature(t *testing.T) {

	mgr := getTCertMgr(t)
	if mgr == nil {
		return
	}
	message := []byte("signature validation")
	//Get Public Key and Signature
	priv, privKeyErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if privKeyErr != nil {
		t.Errorf("Key Generation failed with error : [%v]", privKeyErr)
	}
	pubASN1, marshallError := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if marshallError != nil {
		t.Errorf("Public Key Marshalling failed with error : [%v]", marshallError)
	}
	var r, s *big.Int
	var signError, validationError error
	var isValid bool
	r, s, signError = ECDSASignDirect(priv, message, "SHA2_256")
	if signError != nil {
		t.Error("ECDSA Signature was not created successfully")
	}

	ecSignature, marshallError := asn1.Marshal(ECDSASignature{r, s})
	if marshallError != nil {
		t.Errorf("EC Signature Marshalling failed with error : %s", marshallError)
	}
	keySig := api.KeySig{
		Key: pubASN1,
		Sig: ecSignature,
		Alg: "ecdsa-with-SHA2_256",
	}
	isValid, validationError = mgr.VerifyMessage(keySig)
	if isValid {
		t.Errorf("Signature Validation should have Failed")
	}
	if validationError == nil {
		t.Errorf("Signature Validation with SHA2_256 digest algorithm failed with error : [%v]", validationError)
	}

}

func TestPubkeyArrayFromBatchRequest(t *testing.T) {
	//Generate Test Public Key buffer
	pubKeySigBatch, error := GetTemporalBatch(&api.GetTCertBatchRequestNet{
		GetBatchRequest: api.GetTCertBatchRequest{
			Count: 1,
		},
	}, 1)

	if error != nil {
		t.Logf("Public Key generation failed : [%v]", error)
	}

	pubKeyByteArray, error := BatchRequestToPubkeyBuff(&api.GetTCertBatchRequestNet{
		GetBatchRequest: api.GetTCertBatchRequest{
			Count: 1,
		},
		KeySigs: pubKeySigBatch,
	})
	if error != nil {
		t.Errorf("Getting publicKey from Batch Request failed with error : [%v]", error)
	}
	if len(pubKeyByteArray) == 0 {
		t.Error("No public key byte array returned")
	}
}

func getTCertMgr(t *testing.T) *Mgr {

	defaultBccsp, bccspError := factory.GetDefault()
	if bccspError != nil {
		t.Errorf("BCCSP initialiazation failed with error : [%v]", bccspError)
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

func GetTemporalBatch(batchRequest *api.GetTCertBatchRequestNet, count int) ([]api.KeySig, error) {

	var priv *ecdsa.PrivateKey
	var err error
	var tempCrypto api.KeySig

	var set []api.KeySig
	for i := 0; i < count; i++ {
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubASN1, marshallError := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if marshallError != nil {
			return nil, marshallError
		}
		r, s, signError := ECDSASignDirect(priv, pubASN1, "SHA2_256")
		if signError != nil {
			return nil, signError
		}

		ecSignature, marshallError := asn1.Marshal(ECDSASignature{r, s})
		if marshallError != nil {
			return nil, marshallError
		}

		tempCrypto = api.KeySig{Key: pubASN1, Sig: ecSignature, Alg: "ecdsa-with-SHA2_256"}

		set = append(set, tempCrypto)

	}

	return set, nil
}

func ECDSASignDirect(signKey interface{}, msg []byte, hashAlgo string) (*big.Int, *big.Int, error) {
	temp := signKey.(*ecdsa.PrivateKey)

	var hash hash.Hash

	switch hashAlgo {
	case "SHA2_256":
		hash = sha256.New()
	case "SHA2_384":
		hash = sha512.New384()
	case "SHA3_256":
		hash = sha3.New256()
	case "SHA3_384":
		hash = sha3.New384()
	default:
		return nil, nil, errors.New("Hash Algorithm not recognized")
	}
	hash.Write(msg)
	h := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}
