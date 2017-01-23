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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric/bccsp"
)

const (
	// AESKeyLength is the default AES key length
	AESKeyLength = 32
)

var (
	//RootPreKeySize is the default value of root key
	RootPreKeySize = 48
	// tcertSubject is the subject name placed in all generated TCerts
	tcertSubject = pkix.Name{CommonName: "Fabric Transaction Certificate"}
	// strings delimiter to separate signature and hash algo
	algoDelimiter = "-with-"
)

// GenerateIntUUID returns a UUID based on RFC 4122 returning a big.Int
func GenerateIntUUID() (*big.Int, error) {
	uuid, err := GenerateBytesUUID()
	if err != nil {
		return nil, err
	}
	z := big.NewInt(0)
	return z.SetBytes(uuid), nil
}

// GenerateBytesUUID returns a UUID based on RFC 4122 returning the generated bytes
func GenerateBytesUUID() ([]byte, error) {
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		return nil, err
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return uuid, nil
}

// CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	return CBCEncrypt(key, PKCS7Padding(src))
}

// CBCEncrypt encrypts using CBC mode
func CBCEncrypt(key, s []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("CBCEncrypt failure: plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("CBCEncrypt failure in io.ReadFull: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// PKCS7Padding pads as prescribed by the PKCS7 standard
func PKCS7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

//ConvertDERToPEM returns data from DER to PEM format
//DERData is DER
func ConvertDERToPEM(der []byte, datatype string) []byte {
	pemByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  datatype,
			Bytes: der,
		},
	)
	return pemByte
}

//GenNumber generates random numbers of type *big.Int with fixed length
func GenNumber(numlen *big.Int) *big.Int {
	lowerBound := new(big.Int).Exp(big.NewInt(10), new(big.Int).Sub(numlen, big.NewInt(1)), nil)
	upperBound := new(big.Int).Exp(big.NewInt(10), numlen, nil)
	randomNum, _ := rand.Int(rand.Reader, upperBound)
	val := new(big.Int).Add(randomNum, lowerBound)
	valMod := new(big.Int).Mod(val, upperBound)

	if valMod.Cmp(lowerBound) == -1 {
		newval := new(big.Int).Add(valMod, lowerBound)
		return newval
	}
	return valMod
}

// GetEnrollmentIDFromCert retrieves Enrollment Id from certificate
func GetEnrollmentIDFromCert(ecert *x509.Certificate) string {
	return ecert.Subject.CommonName
}

//GetCertificate returns interface containing *rsa.PublicKey or ecdsa.PublicKey
func GetCertificate(certificate []byte) (*x509.Certificate, error) {

	var certificates []*x509.Certificate
	var isvalidCert bool
	var err error

	var errorMsg string
	block, _ := pem.Decode(certificate)
	if block == nil {
		certificates, err = x509.ParseCertificates(certificate)
		if err != nil {
			return nil, fmt.Errorf("DER Certificate Parse failed with error : %s", err)
		}
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			errorMsg = "Certificate expired"
			return nil, errors.New(errorMsg)
		}

	} else {
		certificates, err = x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PEM Certificatre Parse failed with error :%s", err)
		}
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			errorMsg = "Certificate expired"
			return nil, errors.New(errorMsg)
		}
	}
	return certificates[0], nil

}

//GetCertitificateSerialNumber returns serial number for Certificate byte
//return -1 , if there is problem with the cert
func GetCertitificateSerialNumber(certificatebyte []byte) (*big.Int, error) {
	certificate, error := GetCertificate(certificatebyte)
	if error != nil {
		return big.NewInt(-1), fmt.Errorf("Certificate Object creation failed with error : %s", error)
	}
	return certificate.SerialNumber, nil
}

//ValidateCert checks for expiry in the certificate cert
//Does not check for revocation
func ValidateCert(cert *x509.Certificate) bool {
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	currentTime := time.Now()
	diffFromExpiry := notAfter.Sub(currentTime)
	diffFromStart := currentTime.Sub(notBefore)
	return ((diffFromExpiry > 0) && (diffFromStart > 0))
}

// CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	pt, err := CBCDecrypt(key, src)
	if err != nil {

		return nil, err
	}

	original, err := PKCS7UnPadding(pt)
	if err != nil {

		return nil, err
	}

	return original, nil
}

// CBCDecrypt decrypts using CBC mode
func CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {

		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {

		return nil, errors.New("ciphertext too short")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {

		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(src, src)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return src, nil
}

// PKCS7UnPadding unpads as prescribed by the PKCS7 standard
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return src[:(length - unpadding)], nil
}

//CreateRootPreKey method generates root key
func CreateRootPreKey() string {
	var cooked string
	key := make([]byte, RootPreKeySize)
	rand.Reader.Read(key)
	cooked = base64.StdEncoding.EncodeToString(key)
	return cooked
}

// GenerateCertificate generates X509 Certificate based on parameter passed
func GenerateCertificate(validityPeriod time.Duration, serialNumber *big.Int,
	extensions []pkix.Extension, pubkey *ecdsa.PublicKey,
	CAKey interface{}, CACert *x509.Certificate) ([]byte, error) {
	// Create a template from which to create all other TCerts.
	// Since a TCert is anonymous and unlinkable, do not include
	template := &x509.Certificate{
		Subject: tcertSubject,
	}
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(validityPeriod)
	template.IsCA = false
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	template.Extensions = extensions
	template.ExtraExtensions = extensions
	template.SerialNumber = serialNumber

	raw, err := x509.CreateCertificate(rand.Reader, template, CACert, pubkey, CAKey)
	if err != nil {
		return nil, fmt.Errorf("Certificate Creation failed with error : %s", err)
	}

	pem := ConvertDERToPEM(raw, "CERTIFICATE")

	return pem, nil
}

// VerifyMessage verifies message using BCCSP
// payload is the same as Public Key
func (tm *Mgr) VerifyMessage(signature api.KeySig) (bool, error) {

	pubkeyRaw := signature.Key
	signatureAlgo := signature.Alg
	signatureByte := signature.Sig

	if signatureByte == nil {
		return false, errors.New("Signature is not present")
	}

	if pubkeyRaw == nil {
		return false, errors.New("Public key is not present")
	}

	if len(signatureAlgo) == 0 {
		return false, errors.New("Hash Algorithm in signature is not present")
	}
	//Implemented ECDSA only , hence ignoring the value
	_, hashAlgo := parseSigntureString(signatureAlgo)

	//Import public key into BCCSP
	pk2, err := tm.BCCSP.KeyImport(pubkeyRaw, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		return false, fmt.Errorf("Public Key import into BCCSP failed with error : %s", err)
	}
	if pk2 == nil {
		return false, errors.New("Public Key Cannot be imported into BCCSP")
	}

	//Get Hash over the message
	var digest []byte
	var digestError error
	switch hashAlgo {
	case "SHA2_256":
		digest, digestError = tm.BCCSP.Hash(pubkeyRaw, &bccsp.SHA256Opts{})
	case "SHA2_384":
		digest, digestError = tm.BCCSP.Hash(pubkeyRaw, &bccsp.SHA384Opts{})
	case "SHA3_256":
		digest, digestError = tm.BCCSP.Hash(pubkeyRaw, &bccsp.SHA3_256Opts{})
	case "SHA3_384":
		digest, digestError = tm.BCCSP.Hash(pubkeyRaw, &bccsp.SHA3_384Opts{})
	default:
		digest = nil
		digestError = errors.New("Right Hash Algorithm is not passed")

	}
	if digestError != nil {
		return false, fmt.Errorf("Digest operation failed with error: %s", digestError)
	}

	valid, validErr := tm.BCCSP.Verify(pk2, signatureByte, digest, nil)
	if validErr != nil {
		return false, fmt.Errorf("Signature validation failed with error : %s ", validErr)
	}
	if !valid {
		return false, errors.New("Signature Validation failed")
	}

	return true, nil
}

// BytesToPublicKey parses a DER encoded public key (or a PEM block) returning
// an X509 PublicKey interface
func BytesToPublicKey(publicKey []byte) (interface{}, error) {

	block, _ := pem.Decode(publicKey)
	var pubKey interface{}
	var pubKeyParseError error
	if block != nil {
		pubKey, pubKeyParseError = x509.ParsePKIXPublicKey(block.Bytes)
	} else {
		pubKey, pubKeyParseError = x509.ParsePKIXPublicKey(publicKey)
	}

	if pubKeyParseError != nil {
		return nil, pubKeyParseError
	}
	return pubKey, nil
}

// GetPrivateKey returns ecdsa.PrivateKey or rsa.privateKey object for the private Key Bytes
func GetPrivateKey(buf []byte) (interface{}, error) {
	var err error
	var privateKey interface{}

	block, _ := pem.Decode(buf)
	if block == nil {
		privateKey, err = ParsePrivateKey(buf)
		if err != nil {
			return nil, fmt.Errorf("Failure parsing DER-encoded private key: %s", err)
		}
	} else {
		privateKey, err = ParsePrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Failure parsing PEM private key: %s", err)
		}
	}

	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return privateKey, nil
	case *ecdsa.PrivateKey:
		return privateKey, nil
	default:
		return nil, errors.New("Key is neither RSA nor ECDSA")
	}

}

// ParsePrivateKey parses private key
func ParsePrivateKey(der []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("Key is neither RSA nor ECDSA")
		}
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failure parsing private key: %s", err)
	}
	return key, nil
}

// LoadCert loads a certificate from a file
func LoadCert(path string) (*x509.Certificate, error) {
	certBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return GetCertificate(certBuf)
}

// LoadKey loads a private key from a file
func LoadKey(path string) (interface{}, error) {
	keyBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := GetPrivateKey(keyBuf)
	if err != nil {
		return nil, err
	}
	return key, nil

}

// VerifyTCertBatchRequest does signature verification over the request
//  @returns : True all signature verification passes
//             False otherwise
func (tm *Mgr) VerifyTCertBatchRequest(tcertbatch *api.GetTCertBatchRequestNet) (bool, error) {

	if tcertbatch == nil {
		return false, errors.New("Request is nil. Please provide valid request")
	}

	temporalSignatures := tcertbatch.KeySigs
	noOfTemporalSignatures := len(temporalSignatures)
	if noOfTemporalSignatures == 0 {
		return false, errors.New("None of the temporal public keys are signed")
	}
	for i := 0; i < noOfTemporalSignatures; i++ {

		isValid, validationError := tm.VerifyMessage(temporalSignatures[i])
		if validationError != nil {
			return false, fmt.Errorf("Singature Validation failed with error :%s", validationError)
		}
		if !isValid {
			return false, errors.New("Signature Validation failed")
		}

	}

	return true, nil
}

// BatchRequestToPubkeyBuff retutns batch of public keys
// from the TCert Batch Request
func BatchRequestToPubkeyBuff(tcertbatch *api.GetTCertBatchRequestNet) ([][]byte, error) {
	if tcertbatch == nil {
		return nil, errors.New("Batch Request is nil")
	}
	sigBatch := tcertbatch.KeySigs
	sigBatchLength := len(sigBatch)

	if len(sigBatch) == 0 {
		return nil, errors.New("Signature batch is nil")
	}

	var pubKey []byte
	var pubKeyByteArray [][]byte
	for i := 0; i < sigBatchLength; i++ {
		pubKey = sigBatch[i].Key
		pubKeyByteArray = append(pubKeyByteArray, pubKey)
	}
	return pubKeyByteArray, nil
}

// GetTemporalBatch takes the value from the Batch Request
// @return : Array of KeySig structure
func GetTemporalBatch(bccsp bccsp.BCCSP, batchRequest *api.GetTCertBatchRequest) ([]api.KeySig, error) {

	var tempCrypto api.KeySig
	var set []api.KeySig

	count := batchRequest.Count

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

// ParseSigntureString returns Signature and Hash Algo
func parseSigntureString(sigString string) (string, string) {
	algoIdentifier := strings.Split(sigString, algoDelimiter)
	signatureType := algoIdentifier[0]
	hashAlgo := algoIdentifier[1]
	return signatureType, hashAlgo
}
