/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"strings"

	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	idemixapi "github.com/hyperledger/fabric-ca/lib/common/idemix/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

// CertificateStatus represents status of an enrollment certificate
type CertificateStatus string

const (
	// Revoked is the status of a revoked certificate
	Revoked CertificateStatus = "revoked"
	// Good is the status of a active certificate
	Good = "good"

	typeX509   = "x509"
	typeIdemix = "idemix"
)

// HandleRevoke handles revoking x509 certificates and idemix credentials
type HandleRevoke struct {
	ca             *CA
	ctx            *serverRequestContextImpl
	certDBAccessor *CertDBAccessor
	registry       spi.UserRegistry
	name           string
	serial         string
	aki            string
	reason         int
	revokeType     string
	idemixRH       string
}

func newRevokeEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: revokeHandler,
		Server:  s,
	}
}

// Handle an revoke request
func revokeHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	// Parse revoke request body
	var req api.RevocationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authentication
	_, err = ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	// Get targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	r := &HandleRevoke{
		ca:             ca,
		ctx:            ctx,
		certDBAccessor: ca.certDBAccessor,
		registry:       ca.registry,
		name:           req.Name,
		serial:         parseInput(req.Serial),
		aki:            parseInput(req.AKI),
		reason:         util.RevocationReasonCodes[req.Reason],
		revokeType:     strings.ToLower(req.Type),
		idemixRH:       req.IdemixRH,
	}

	err = r.argsCheck()
	if err != nil {
		return nil, err
	}

	result := &api.RevocationResponse{}
	if r.serial != "" && r.aki != "" {
		err := r.RevokeBySerialAKI(result)
		if err != nil {
			return nil, err
		}
	} else if r.name != "" {
		err := r.RevokeByName(result)
		if err != nil {
			return nil, err
		}
	}

	if req.GenCRL && len(result.RevokedCerts) > 0 {
		log.Debugf("Generating CRL")
		crl, err := genCRL(ca, api.GenCRLRequest{CAName: ca.Config.CA.Name})
		if err != nil {
			return nil, err
		}
		result.CRL = util.B64Encode(crl)
	}

	if r.revokeType == typeX509 {
		return result, nil
	}

	idemixResult := &idemixapi.RevocationResponse{}
	// If type is not specified, both x509 certificates and idemix credentials should be revoked
	// Only need to revokey by revocation handle because revocation by name has already been handled above
	if req.IdemixRH != "" {
		err := r.revokeByRH(idemixResult)
		if err != nil {
			return nil, err
		}
	} else if r.name != "" {
		err := r.RevokeByNameIdemix(idemixResult)
		if err != nil {
			return nil, err
		}
	}

	if r.name != "" || req.IdemixRH != "" {
		allResult := api.AllRevocationResponse{
			X509Revocation:   *result,
			IdemixRevocation: *idemixResult,
		}
		return api.AllRevocationResponseNet{allResult}, nil
	}

	allResult := api.AllRevocationResponse{
		X509Revocation: *result,
	}
	return api.AllRevocationResponseNet{allResult}, nil
}

// RevokeBySerialAKI revokes certificates based on serial number and AKI
func (r *HandleRevoke) RevokeBySerialAKI(result *api.RevocationResponse) error {
	certificate, err := r.certDBAccessor.GetCertificateWithID(r.serial, r.aki)
	if err != nil {
		return caerrors.NewHTTPErr(404, caerrors.ErrRevCertNotFound, "Certificate with serial %s and AKI %s was not found: %s",
			r.serial, r.aki, err)
	}

	if certificate.Status == string(Revoked) {
		return caerrors.NewHTTPErr(404, caerrors.ErrCertAlreadyRevoked, "Certificate with serial %s and AKI %s was already revoked",
			r.serial, r.aki)
	}

	if r.name != "" && r.name != certificate.ID {
		return caerrors.NewHTTPErr(400, caerrors.ErrCertWrongOwner, "Certificate with serial %s and AKI %s is not owned by %s",
			r.serial, r.aki, r.name)
	}

	userInfo, err := r.registry.GetUser(certificate.ID, nil)
	if err != nil {
		return caerrors.NewHTTPErr(404, caerrors.ErrRevokeIDNotFound, "Identity %s was not found: %s", certificate.ID, err)
	}

	err = r.ctx.CanRevoke(userInfo)
	if err != nil {
		return err
	}

	err = r.certDBAccessor.RevokeCertificate(r.serial, r.aki, r.reason)
	if err != nil {
		return caerrors.NewHTTPErr(500, caerrors.ErrRevokeFailure, "Revoke of certificate <%s,%s> failed: %s", r.serial, r.aki, err)
	}

	result.RevokedCerts = append(result.RevokedCerts, api.RevokedCert{Serial: r.serial, AKI: r.aki})
	return nil
}

// RevokeByName revokes an identity based on enrollment ID
func (r *HandleRevoke) RevokeByName(result *api.RevocationResponse) error {
	user, err := r.registry.GetUser(r.name, nil)
	if err != nil {
		return caerrors.NewHTTPErr(404, caerrors.ErrRevokeIDNotFound, "Identity %s was not found: %s", r.name, err)
	}

	err = r.ctx.CanRevoke(user)
	if err != nil {
		return err
	}

	err = user.Revoke()
	if err != nil {
		return caerrors.NewHTTPErr(500, caerrors.ErrRevokeUpdateUser, "Failed to revoke user: %s", err)
	}

	var recs []CertRecord
	recs, err = r.certDBAccessor.RevokeCertificatesByID(r.name, r.reason)
	if err != nil {
		return caerrors.NewHTTPErr(500, caerrors.ErrNoCertsRevoked, "Failed to revoke certificates for '%s': %s",
			r.name, err)
	}

	if len(recs) == 0 {
		log.Warningf("No certificates were revoked for '%s' but the ID was disabled", r.name)
	} else {
		log.Debugf("Revoked the following certificates owned by '%s': %+v", r.name, recs)
		for _, certRec := range recs {
			result.RevokedCerts = append(result.RevokedCerts, api.RevokedCert{AKI: certRec.AKI, Serial: certRec.Serial})
		}
	}

	return nil
}

// RevokeByNameIdemix revokes Idemix credentials based on enrollment ID
func (r *HandleRevoke) RevokeByNameIdemix(result *idemixapi.RevocationResponse) error {
	idemixRevokeResponse, err := r.ca.issuer.RevokeByName(&idemixServerCtx{r.ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/revocation request: %s", err.Error())
		return err
	}
	log.Debug("Idemix revoke by name was successful")
	*result = *idemixRevokeResponse
	return nil
}

func (r *HandleRevoke) revokeByRH(result *idemixapi.RevocationResponse) error {
	idemixRevokeResponse, err := r.ca.issuer.RevokeByRH(&idemixServerCtx{r.ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/revocation request: %s", err.Error())
		return err
	}
	log.Debug("Idemix revoke by Revocation Handle was successful")
	*result = *idemixRevokeResponse
	return nil
}

func (r *HandleRevoke) argsCheck() error {
	switch r.revokeType {
	case typeX509:
		if r.name == "" && (r.serial == "" || r.aki == "") {
			return caerrors.NewHTTPErr(400, caerrors.ErrMissingRevokeArgs, "Either Name or Serial and AKI are required for a X509 revoke request")
		}
	case typeIdemix:
		if r.name == "" && r.idemixRH == "" {
			return caerrors.NewHTTPErr(400, caerrors.ErrMissingRevokeArgs, "Either Name or Revocation Handle are required for an Idemix revoke request")
		}
	default:
		if r.name == "" && (r.serial == "" || r.aki == "") && r.idemixRH == "" {
			return caerrors.NewHTTPErr(400, caerrors.ErrMissingRevokeArgs, "No arguments provided for revoke request")
		}
	}
	return nil
}

func parseInput(input string) string {
	return strings.Replace(strings.TrimLeft(strings.ToLower(input), "0"), ":", "", -1)
}

func checkAuth(callerName, revokeUserName string, ca *CA) error {
	if callerName != revokeUserName {
		// Make sure that the caller has the "hf.Revoker" attribute.
		err := ca.attributeIsTrue(callerName, "hf.Revoker")
		if err != nil {
			return caerrors.NewAuthorizationErr(caerrors.ErrNotRevoker, "Caller does not have authority to revoke")
		}
	}
	return nil
}
