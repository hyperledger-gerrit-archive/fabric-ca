/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/cloudflare/cfssl/log"
	idemixapi "github.com/hyperledger/fabric-ca/lib/common/idemix/api"
	infoapi "github.com/hyperledger/fabric-ca/lib/common/info/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
)

func newIdemixEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   handleIdemixEnrollReq,
		Server:    s,
		successRC: 201,
	}
}

// handleIdemixEnrollReq handles an Idemix enroll request
func handleIdemixEnrollReq(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	idemixEnrollResp, err := ca.issuer.IssueCredential(&idemixServerCtx{ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/credential request: %s", err.Error())
		return nil, err
	}
	resp := newIdemixEnrollmentResponseNet(idemixEnrollResp)
	err = ctx.ca.fillCAInfo(&resp.CAInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// newIdemixEnrollmentResponseNet returns an instance of IdemixEnrollmentResponseNet that is
// constructed using the specified idemix.EnrollmentResponse object
func newIdemixEnrollmentResponseNet(resp *idemixapi.EnrollmentResponse) idemixapi.EnrollmentResponseNet {
	respNet := idemixapi.EnrollmentResponseNet{
		CAInfo: infoapi.CAInfoResponseNet{},
	}
	respNet.EnrollmentResponse = *resp
	return respNet
}

// idemixServerCtx implements idemix.ServerRequestContext
type idemixServerCtx struct {
	srvCtx *serverRequestContextImpl
}

func (c *idemixServerCtx) IsBasicAuth() bool {
	_, _, isBasicAuth := c.srvCtx.req.BasicAuth()
	return isBasicAuth
}
func (c *idemixServerCtx) BasicAuthentication() (string, error) {
	return c.srvCtx.BasicAuthentication()
}
func (c *idemixServerCtx) TokenAuthentication() (string, error) {
	return c.srvCtx.TokenAuthentication()
}
func (c *idemixServerCtx) GetCaller() (spi.User, error) {
	return c.srvCtx.GetCaller()
}
func (c *idemixServerCtx) ReadBody(body interface{}) error {
	return c.srvCtx.ReadBody(body)
}
func (c *idemixServerCtx) GetUser(id string) (spi.User, error) {
	return c.srvCtx.GetRegistry().GetUser(id, nil)
}
func (c *idemixServerCtx) CanRevoke(user spi.User) error {
	return c.srvCtx.CanRevoke(user)
}
