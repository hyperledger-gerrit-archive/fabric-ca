/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	idemixapi "github.com/hyperledger/fabric-ca/lib/common/idemix/api"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// Issuer is the interface to the Issuer for external components
type Issuer interface {
	Init(renew bool, db dbutil.FabricCADB, levels *dbutil.Levels) error
	IssuerPublicKey() ([]byte, error)
	RevocationPublicKey() ([]byte, error)
	IssueCredential(ctx ServerRequestCtx) (*idemixapi.EnrollmentResponse, error)
	Revoke(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error)
	RevokeByRH(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error)
	RevokeByName(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error)
	GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error)
	VerifyToken(authHdr string, body []byte) (string, error)
}

// MyIssuer provides functions for accessing issuer components
type MyIssuer interface {
	Name() string
	HomeDir() string
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
	GetUser(user string) (spi.User, error)
	CanRevoke(user spi.User) error
	ReadBody(body interface{}) error
}

type issuer struct {
	name      string
	homeDir   string
	cfg       *Config
	idemixLib Lib
	db        dbutil.FabricCADB
	csp       bccsp.BCCSP
	// The Idemix credential DB accessor
	credDBAccessor CredDBAccessor
	// idemix issuer credential for the CA
	issuerCred IssuerCredential
	// A random number used in generation of Idemix nonces and credentials
	idemixRand    *amcl.RAND
	rc            RevocationAuthority
	nm            NonceManager
	isInitialized bool
	mutex         sync.Mutex
}

// NewIssuer returns an object that implements Issuer interface
func NewIssuer(name, homeDir string, config *Config, csp bccsp.BCCSP, idemixLib Lib) Issuer {
	issuer := issuer{name: name, homeDir: homeDir, cfg: config, csp: csp, idemixLib: idemixLib}
	return &issuer
}

func (i *issuer) Init(renew bool, db dbutil.FabricCADB, levels *dbutil.Levels) error {

	if i.isInitialized {
		return nil
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	// After obtaining a lock, check again to see if issuer has been initialized by another thread
	if i.isInitialized {
		return nil
	}

	if db == nil || reflect.ValueOf(db).IsNil() || !db.IsInitialized() {
		log.Debugf("Returning without initializing Idemix issuer for CA '%s' as the database is not initialized", i.Name())
		return nil
	}
	i.db = db
	err := i.cfg.init(i.homeDir)
	if err != nil {
		return err
	}
	err = i.initKeyMaterial(renew)
	if err != nil {
		return err
	}
	i.credDBAccessor = NewCredentialAccessor(i.db, levels.Credential)
	log.Debugf("Intializing revocation authority for issuer '%s'", i.Name())
	i.rc, err = NewRevocationAuthority(i, levels.RAInfo)
	if err != nil {
		return err
	}
	log.Debugf("Intializing nonce manager for issuer '%s'", i.Name())
	i.nm, err = NewNonceManager(i, &wallClock{}, levels.Nonce)
	if err != nil {
		return err
	}
	i.isInitialized = true
	return nil
}

func (i *issuer) IssuerPublicKey() ([]byte, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	ik, err := i.issuerCred.GetIssuerKey()
	if err != nil {
		return nil, err
	}
	ipkBytes, err := proto.Marshal(ik.Ipk)
	if err != nil {
		return nil, err
	}
	return ipkBytes, nil
}

func (i *issuer) RevocationPublicKey() ([]byte, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	rpk := i.RevocationAuthority().PublicKey()
	encodedPubKey, err := x509.MarshalPKIXPublicKey(rpk)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to encode revocation authority public key of the issuer %s", i.Name())
	}
	pemEncodedPubKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPubKey})
	return pemEncodedPubKey, nil
}

func (i *issuer) IssueCredential(ctx ServerRequestCtx) (*idemixapi.EnrollmentResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := EnrollRequestHandler{
		Ctx:     ctx,
		Issuer:  i,
		IdmxLib: i.idemixLib,
	}

	return handler.HandleRequest()
}

func (i *issuer) GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := CRIRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	return handler.HandleRequest()
}

func (i *issuer) Revoke(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := RevokeRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	rhs, err := handler.HandleRequest()
	if err != nil {
		return nil, err
	}

	res := &idemixapi.RevocationResponse{RevokedHandles: rhs}
	if len(rhs) > 0 {
		cri, err := i.RevocationAuthority().CreateCRI()
		if err != nil {
			return nil, err
		}
		criBytes, err := marshalCRI(cri)
		if err != nil {
			return nil, err
		}
		res.CRI = util.B64Encode(criBytes)
	}
	return res, nil
}

func (i *issuer) RevokeByRH(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := RevokeRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	var req api.RevocationRequest
	err := handler.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	rhs, err := handler.RevokeByRH(&req)
	if err != nil {
		return nil, err
	}

	res := &idemixapi.RevocationResponse{RevokedHandles: rhs}
	if len(rhs) > 0 {
		cri, err := i.RevocationAuthority().CreateCRI()
		if err != nil {
			return nil, err
		}
		criBytes, err := marshalCRI(cri)
		if err != nil {
			return nil, err
		}
		res.CRI = util.B64Encode(criBytes)
	}
	return res, nil
}

func (i *issuer) RevokeByName(ctx ServerRequestCtx) (*idemixapi.RevocationResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := RevokeRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	var req api.RevocationRequest
	err := handler.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	rhs, err := handler.RevokeByName(&req)
	if err != nil {
		return nil, err
	}

	res := &idemixapi.RevocationResponse{RevokedHandles: rhs}
	if len(rhs) > 0 {
		cri, err := i.RevocationAuthority().CreateCRI()
		if err != nil {
			return nil, err
		}
		criBytes, err := marshalCRI(cri)
		if err != nil {
			return nil, err
		}
		res.CRI = util.B64Encode(criBytes)
	}
	return res, nil
}

func (i *issuer) VerifyToken(authHdr string, body []byte) (string, error) {
	if !i.isInitialized {
		return "", errors.New("Issuer is not initialized")
	}
	// Disclosure array indicates which attributes are disclosed. 1 means disclosed. Currently four attributes are
	// supported: OU, isAdmin, enrollmentID and revocationHandle. Third element of disclosure array is set to 1
	// to indicate that the server expects enrollmentID to be disclosed in the signature sent in the authorization token.
	// EnrollmentID is disclosed to check if the signature was infact created using credential of a user whose
	// enrollment ID is the one specified in the token. So, enrollment ID in the token is used to check if the user
	// is valid and has a credential (by checking the DB) and it is used to verify zero knowledge proof.
	disclosure := []byte{0, 0, 1, 0}
	parts := getTokenParts(authHdr)
	if parts == nil {
		return "", errors.New("Invalid Idemix token format; token format must be: 'idemix.<enrollment ID>.<base64 encoding of Idemix signature bytes>'")
	}
	if parts[1] != TokenVersion1 {
		return "", errors.New("Invalid version found in the Idemix token. Version must be 1")
	}
	enrollmentID := parts[2]
	creds, err := i.credDBAccessor.GetCredentialsByID(enrollmentID)
	if err != nil {
		return "", errors.Errorf("Failed to check if enrollment ID '%s' is valid", enrollmentID)
	}
	if len(creds) == 0 {
		return "", errors.Errorf("Enrollment ID '%s' does not have any Idemix credentials", enrollmentID)
	}
	idBytes := []byte(enrollmentID)
	attrs := []*fp256bn.BIG{nil, nil, idemix.HashModOrder(idBytes), nil}
	msg := util.B64Encode(body)
	digest, digestError := i.csp.Hash([]byte(msg), &bccsp.SHAOpts{})
	if digestError != nil {
		return "", errors.WithMessage(digestError, fmt.Sprintf("Failed to create authentication token '%s'", msg))
	}

	issuerKey, err := i.issuerCred.GetIssuerKey()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get issuer key")
	}
	ra := i.RevocationAuthority()
	epoch, err := ra.Epoch()
	if err != nil {
		return "", err
	}

	sigBytes, err := util.B64Decode(parts[3])
	if err != nil {
		return "", errors.WithMessage(err, "Failed to base64 decode signature specified in the token")
	}
	sig := &idemix.Signature{}
	err = proto.Unmarshal(sigBytes, sig)
	if err != nil {
		return "", errors.WithMessage(err, "Failed to unmarshal signature bytes specified in the token")
	}
	err = sig.Ver(disclosure, issuerKey.Ipk, digest, attrs, 3, ra.PublicKey(), epoch)
	if err != nil {
		return "", errors.WithMessage(err, "Failed to verify the token")
	}
	return enrollmentID, nil
}

// Name returns the name of the issuer
func (i *issuer) Name() string {
	return i.name
}

// HomeDir returns the home directory of the issuer
func (i *issuer) HomeDir() string {
	return i.homeDir
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

func (i *issuer) initKeyMaterial(renew bool) error {
	//log.Debug("Initialize Idemix issuer key material")

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
	//log.Infof("Idemix issuer public and secret keys were generated for CA '%s'", i.name)
	issuerCred.SetIssuerKey(ik)
	err = issuerCred.Store()
	if err != nil {
		return err
	}
	i.issuerCred = issuerCred
	return nil
}

func getTokenParts(token string) []string {
	parts := strings.Split(token, ".")
	if len(parts) == 4 && parts[0] == "idemix" {
		return parts
	}
	return nil
}

// IsToken returns true if the specified token has the format expected of an authorization token
// that is created using an Idemix credential
func IsToken(token string) bool {
	if getTokenParts(token) != nil {
		return true
	}
	return false
}

type wallClock struct{}

func (wc wallClock) Now() time.Time {
	return time.Now()
}
