/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/cloudflare/cfssl/log"
)

func newIdemixRevokeEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   handleIdemixRevokeReq,
		Server:    s,
		successRC: 201,
	}
}

// handleIdemixRevokeReq handles an Idemix cri request
func handleIdemixRevokeReq(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	idemixRevokeResp, err := ca.issuer.Revoke(&idemixServerCtx{ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/revocation request: %s", err.Error())
		return nil, err
	}

	return idemixRevokeResp, nil
}
