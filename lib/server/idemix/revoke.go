/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	idemixapi "github.com/hyperledger/fabric-ca/lib/common/idemix/api"
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

	var req idemixapi.RevocationRequest
	err = h.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	if req.RevocationHandle != "" {
		cred, err := h.Issuer.CredDBAccessor().GetCredential(req.RevocationHandle)
		if err != nil {
			return nil, caerrors.NewHTTPErr(404, caerrors.ErrRevCertNotFound, "Credential with revocation handle %s was not found: %s",
				req.RevocationHandle, err)
		}

		if cred.Status == "revoked" {
			return nil, caerrors.NewHTTPErr(404, caerrors.ErrCertAlreadyRevoked, "Credential with revocation handle %s was already revoked",
				req.RevocationHandle)
		}

		if req.Name != "" && req.Name != cred.ID {
			return nil, caerrors.NewHTTPErr(400, caerrors.ErrCertWrongOwner, "Credential with revocation handle %s is not owned by %s",
				req.RevocationHandle, req.Name)
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
		err = h.Issuer.CredDBAccessor().RevokeCredential(req.RevocationHandle, reason)
		if err != nil {
			log.Errorf("Failed to update status of the credential '%s' to revoked in the database: %s", req.RevocationHandle, err.Error())
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrRevokeFailure, "Failed to update revocation status of the credential in the datastore")
		}
		rhs := []string{req.RevocationHandle}
		return rhs, nil
	} else if req.Name != "" {
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
	} else {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrMissingRevokeArgs, "Either Name or RevocationHandle is required for a revocation request")
	}
}
