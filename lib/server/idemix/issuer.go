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

import (
	"reflect"
	"time"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// Issuer is the interface to the Issuer for external components
type Issuer interface {
	Init(renew bool, levels *dbutil.Levels) error
	IssuerPublicKey() ([]byte, error)
	IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error)
}

// MyIssuer provides functions for accessing issuer components
type MyIssuer interface {
	Name() string
	Config() *Config
	IdemixLib() Lib
	DB() dbutil.FabricCADB
	IdemixRand() *amcl.RAND
	IssuerCredential() IssuerCredential
	RevocationAuthority() RevocationAuthority
	NonceManager() NonceManager
	CredDBAccessor() CredDBAccessor
}

// ServerRequestCtx is the server request context that Idemix enroll expects
type ServerRequestCtx interface {
	IsBasicAuth() bool
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCaller() (spi.User, error)
	ReadBody(body interface{}) error
}

type issuer struct {
	name      string
	homeDir   string
	cfg       *Config
	idemixLib Lib
	db        dbutil.FabricCADB
	// The Idemix credential DB accessor
	credDBAccessor CredDBAccessor
	// idemix issuer credential for the CA
	issuerCred IssuerCredential
	// A random number used in generation of Idemix nonces and credentials
	idemixRand    *amcl.RAND
	rc            RevocationAuthority
	nm            NonceManager
	isInitialized bool
}

// NewIssuer returns an object that implements Issuer interface
func NewIssuer(name, homeDir string, config *Config, db dbutil.FabricCADB, idemixLib Lib) Issuer {
	issuer := issuer{name: name, homeDir: homeDir, cfg: config, db: db, idemixLib: idemixLib}
	return &issuer
}

func (i *issuer) Init(renew bool, levels *dbutil.Levels) error {
	if i.isInitialized {
		return nil
	}
	if i.db == nil || reflect.ValueOf(i.db).IsNil() || !i.db.IsInitialized() {
		log.Debugf("Returning without initializing Issuer for CA '%' as the database is not initialized", i.Name())
		return nil
	}
	err := i.cfg.init(i.homeDir)
	if err != nil {
		return err
	}
	err = i.initKeyMaterial(renew)
	if err != nil {
		return err
	}
	i.credDBAccessor = NewCredentialAccessor(i.db, levels.Credential)
	i.rc, err = NewRevocationAuthority(i, levels.RAInfo)
	if err != nil {
		return err
	}
	i.nm, err = NewNonceManager(i, &wallClock{}, levels.Nonce)
	if err != nil {
		return err
	}
	i.isInitialized = true
	return nil
}

func (i *issuer) initKeyMaterial(renew bool) error {
	log.Debug("Initialize Idemix key material")

	rng, err := i.idemixLib.GetRand()
	if err != nil {
		return errors.Wrapf(err, "Error generating random number")
	}
	i.idemixRand = rng

	idemixPubKey := i.cfg.IssuerPublicKeyfile
	idemixSecretKey := i.cfg.IssuerSecretKeyfile
	issuerCred := NewIssuerCredential(idemixPubKey, idemixSecretKey, i.idemixLib)

	if !renew {
		pubKeyFileExists := util.FileExists(idemixPubKey)
		privKeyFileExists := util.FileExists(idemixSecretKey)
		// If they both exist, the CA was already initialized, load the keys from the disk
		if pubKeyFileExists && privKeyFileExists {
			log.Info("The Idemix issuer public and secret key files already exist")
			log.Infof("   secret key file location: %s", idemixSecretKey)
			log.Infof("   public key file location: %s", idemixPubKey)
			err := issuerCred.Load()
			if err != nil {
				return err
			}
			i.issuerCred = issuerCred
			return nil
		}
	}
	ik, err := issuerCred.NewIssuerKey()
	if err != nil {
		return err
	}
	log.Infof("The Idemix public and secret keys were generated for Issuer %s", i.name)
	issuerCred.SetIssuerKey(ik)
	err = issuerCred.Store()
	if err != nil {
		return err
	}
	i.issuerCred = issuerCred
	return nil
}

func (i *issuer) IssuerPublicKey() ([]byte, error) {
	ik, err := i.issuerCred.GetIssuerKey()
	if err != nil {
		return nil, err
	}
	ipkBytes, err := proto.Marshal(ik.IPk)
	if err != nil {
		return nil, err
	}
	return ipkBytes, nil
}

// Name returns the name of the issuer
func (i *issuer) Name() string {
	return i.name
}

// Config returns config of this issuer
func (i *issuer) Config() *Config {
	return i.cfg
}

// IdemixLib return idemix library instance
func (i *issuer) IdemixLib() Lib {
	return i.idemixLib
}

// DB returns the FabricCADB object (which represents database handle
// to the CA database) associated with this issuer
func (i *issuer) DB() dbutil.FabricCADB {
	return i.db
}

// IdemixRand returns random number used by this issuer in generation of nonces
// and Idemix credentials
func (i *issuer) IdemixRand() *amcl.RAND {
	return i.idemixRand
}

// IssuerCredential returns IssuerCredential of this issuer
func (i *issuer) IssuerCredential() IssuerCredential {
	return i.issuerCred
}

// RevocationAuthority returns revocation authority of this issuer
func (i *issuer) RevocationAuthority() RevocationAuthority {
	return i.rc
}

// NonceManager returns nonce manager of this issuer
func (i *issuer) NonceManager() NonceManager {
	return i.nm
}

// CredDBAccessor returns the Idemix credential DB accessor for issuer
func (i *issuer) CredDBAccessor() CredDBAccessor {
	return i.credDBAccessor
}

func (i *issuer) IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error) {
	handler := EnrollRequestHandler{
		Ctx:     ctx,
		Issuer:  i,
		IdmxLib: i.idemixLib,
	}

	return handler.HandleRequest()
}

type wallClock struct{}

func (wc wallClock) Now() time.Time {
	return time.Now()
}
