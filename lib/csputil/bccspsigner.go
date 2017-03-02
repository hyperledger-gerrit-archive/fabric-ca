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

package csputil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	_ "time" // for ocspSignerFromConfig

	_ "github.com/cloudflare/cfssl/cli" // for ocspSignerFromConfig
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	_ "github.com/cloudflare/cfssl/ocsp" // for ocspSignerFromConfig
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/hyperledger/fabric/bccsp"
	cspsigner "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// BccspBackedSigner determines whether a file-backed local signer is supported.
func BccspBackedSigner(root *universal.Root, policy *config.Signing, csp bccsp.BCCSP) (signer.Signer, bool, error) {
	caFile := root.Config["cert-file"]
	if caFile == "" {
		return nil, false, nil
	}

	_, cspSigner, parsedCa, err := GetSignerFromCertFile(caFile, csp)
	if err != nil {
		log.Debug("Failed to load bccspBackedSigner: %s", err)
		return nil, false, err
	}

	signer, err := local.NewSigner(cspSigner, parsedCa, signer.DefaultSigAlgo(cspSigner), policy)
	return signer, true, err
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
//func ocspSignerFromConfig(c cli.Config, myCSP bccsp.BCCSP) (ocsp.Signer, error) {
//	log.Debug("Loading responder cert: ", c.ResponderFile)
//	responderBytes, err := ioutil.ReadFile(c.ResponderFile)
//	if err != nil {
//		return nil, err
//	}
//
//	responderCert, err := helpers.ParseCertificatePEM(responderBytes)
//	if err != nil {
//		return nil, err
//	}
//
//	log.Debug("Loading issuer cert: ", c.CAFile)
//	_, cspSigner, issuerCert, err := GetSignerFromCertFile(c.CAFile, myCSP)
//	if err != nil {
//		return nil, err
//	}
//
//	return ocsp.NewSigner(issuerCert, responderCert, cspSigner, time.Duration(c.Interval))
//}

// getBCCSPKeyOpts generates a key as specified in the request. Currently,
// only ECDSA and RSA are supported.
func getBCCSPKeyOpts(kr csr.KeyRequest, ephemeral bool) (opts bccsp.KeyGenOpts, err error) {
	if kr == nil {
		return &bccsp.ECDSAKeyGenOpts{Temporary: ephemeral}, nil
	}
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		switch kr.Size() {
		case 2048:
			return &bccsp.RSA2048KeyGenOpts{Temporary: ephemeral}, nil
		case 3072:
			return &bccsp.RSA3072KeyGenOpts{Temporary: ephemeral}, nil
		case 4096:
			return &bccsp.RSA4096KeyGenOpts{Temporary: ephemeral}, nil
		default:
			if kr.Size() < 2048 {
				return nil, errors.New("RSA key is too weak")
			}
			if kr.Size() > 8192 {
				return nil, errors.New("RSA key size too large")
			}
			// Need to add a way to specify arbitrary RSA key size to bccsp
			return nil, errors.New("unsupported RSA key size")
		}
	case "ecdsa":
		switch kr.Size() {
		case 256:
			return &bccsp.ECDSAP256KeyGenOpts{Temporary: ephemeral}, nil
		case 384:
			return &bccsp.ECDSAP384KeyGenOpts{Temporary: ephemeral}, nil
		case 521:
			// Need to add curve P521 to bccsp
			// return &bccsp.ECDSAP512KeyGenOpts{Temporary: false}, nil
			return nil, errors.New("unsupported curve")
		default:
			return nil, errors.New("invalid curve")
		}
	default:
		return nil, errors.New("invalid algorithm")
	}
}

// GetSignerFromCert load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCert(cert *x509.Certificate, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, fmt.Errorf("CFG.csp was not initialized")
	}

	// get the public key in the right format
	certPubK, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to import certitifacate's public key [%s]", err)
	}

	privateKey, err := csp.GetKey(certPubK.SKI())
	if err != nil {
		return nil, nil, fmt.Errorf("Could not find matching private key for SKI [%s]", err.Error())
	}

	signer := &cspsigner.CryptoSigner{}
	if err = signer.Init(csp, privateKey); err != nil {
		return nil, nil, fmt.Errorf("Failed to load ski from bccsp %s", err.Error())
	}
	return privateKey, signer, nil
}

// GetSignerFromCertFile load skiFile and load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCertFile(certFile string, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, *x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not read certFile [%s]: %s", certFile, err.Error())
	}

	parsedCa, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	key, cspSigner, err := GetSignerFromCert(parsedCa, csp)
	return key, cspSigner, parsedCa, err
}

// BCCSPKeyRequestGenerate generates keys through BCCSP
// somewhat mirroring to cfssl/req.KeyRequest.Generate()
func BCCSPKeyRequestGenerate(req *csr.CertificateRequest, myCSP bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	log.Infof("generating key: %+v", req.KeyRequest)
	keyOpts, err := getBCCSPKeyOpts(req.KeyRequest, false)
	if err != nil {
		return nil, nil, errors.New(err.Error())
	}

	key, err := myCSP.KeyGen(keyOpts)
	if err != nil {
		return nil, nil, errors.New(err.Error())
	}

	cspSigner := &cspsigner.CryptoSigner{}
	err = cspSigner.Init(myCSP, key)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed initializing CryptoSigner [%s]", err)
	}
	return key, cspSigner, nil
}

// ImportBCCSPKeyFromPEM attempts to create a private BCCSP key from a pem file keyFile
func ImportBCCSPKeyFromPEM(keyFile string, myCSP bccsp.BCCSP, temporary bool) (bccsp.Key, error) {
	keyBuff, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	key, err := utils.PEMtoPrivateKey(keyBuff, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed parsing private key [%s]: [%s]", keyFile, err.Error())
	}

	switch key.(type) {
	case *ecdsa.PrivateKey:
		priv, err := utils.PrivateKeyToDER(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("Failed converting raw to ecdsa.PrivateKey [%s]", err)
		}

		sk, err := myCSP.KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: temporary})
		if err != nil {
			return nil, fmt.Errorf("Failed importing ECDSA private key [%s]", err)
		}
		return sk, nil
		//return &ecdsaPrivateKey{key.(*ecdsa.PrivateKey)}, nil
	case *rsa.PrivateKey:
		return nil, errors.New("FIXME: RSA Private Key import not supported")
		//return &rsaPrivateKey{key.(*rsa.PrivateKey)}, nil
	default:
		return nil, errors.New("Secret key type not recognized")
	}
}
