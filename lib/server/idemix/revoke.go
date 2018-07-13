/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/util"
)

// RevokeRequestHandler is the handler for Idemix revocation request
type RevokeRequestHandler struct {
	Ctx    ServerRequestCtx
	Issuer MyIssuer
}

// HandleRequest handles processing for Idemix revoke
func (h *RevokeRequestHandler) HandleRequest() ([]string, error) {
	_, err := h.Ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}

	var req api.RevocationRequest
	err = h.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	return h.RevokeIdemix(&req)
}

// RevokeIdemix revokes Idemix credentials
func (h *RevokeRequestHandler) RevokeIdemix(req *api.RevocationRequest) ([]string, error) {
	if req.IdemixRH != "" {
		return h.RevokeByRH(req)
	} else if req.Name != "" {
		return h.RevokeByName(req)
	} else {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrMissingRevokeArgs, "Either Name or RevocationHandle is required for a revocation request")
	}
}

// RevokeByRH revokes Idemix credential by revocation handle
func (h *RevokeRequestHandler) RevokeByRH(req *api.RevocationRequest) ([]string, error) {
	cred, err := h.Issuer.CredDBAccessor().GetCredential(req.IdemixRH)
	if err != nil {
		return nil, caerrors.NewHTTPErr(404, caerrors.ErrRevCertNotFound, "Credential with revocation handle %s was not found: %s",
			req.IdemixRH, err)
	}

	if cred.Status == "revoked" {
		return nil, caerrors.NewHTTPErr(404, caerrors.ErrCertAlreadyRevoked, "Credential with revocation handle %s was already revoked",
			req.IdemixRH)
	}

	if req.Name != "" && req.Name != cred.ID {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrCertWrongOwner, "Credential with revocation handle %s is not owned by %s",
			req.IdemixRH, req.Name)
	}

	user, err := h.Ctx.GetUser(cred.ID)
	if err != nil {
		return nil, err
	}

	err = h.Ctx.CanRevoke(user)
	if err != nil {
		return nil, err
	}

	reason := util.RevocationReasonCodes[req.Reason]
	err = h.Issuer.CredDBAccessor().RevokeCredential(req.IdemixRH, reason)
	if err != nil {
		log.Errorf("Failed to update status of the credential '%s' to revoked in the database: %s", req.IdemixRH, err.Error())
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrRevokeFailure, "Failed to update revocation status of the credential in the datastore")
	}
	rhs := []string{req.IdemixRH}
	return rhs, nil
}

// RevokeByName revokes Idemix credential by enrollment id
func (h *RevokeRequestHandler) RevokeByName(req *api.RevocationRequest) ([]string, error) {
	user, err := h.Ctx.GetUser(req.Name)
	if err != nil {
		return nil, err
	}

	err = h.Ctx.CanRevoke(user)
	if err != nil {
		return nil, err
	}

	err = user.Revoke()
	if err != nil {
		return nil, err
	}
	reason := util.RevocationReasonCodes[req.Reason]
	crs, err := h.Issuer.CredDBAccessor().RevokeCredentialsByID(user.GetName(), reason)
	if err != nil {
		log.Errorf("Failed to update status of the credentials of the user '%s' to revoked in the database: %s", user.GetName(), err.Error())
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrRevokeFailure, "Failed to update revocation status of the credentials in the datastore")
	}
	if len(crs) == 0 {
		log.Warningf("No credentials were revoked for '%s' but the ID was disabled", req.Name)
	} else {
		log.Debugf("Revoked the following credentials owned by '%s': %+v", req.Name, crs)
	}
	rhs := []string{}
	for _, cr := range crs {
		rhs = append(rhs, cr.RevocationHandle)
	}
	// Success
	return rhs, nil
}
