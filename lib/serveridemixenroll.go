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

package lib

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
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
func handleIdemixEnrollReq(ctx *serverRequestContext) (interface{}, error) {
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
func newIdemixEnrollmentResponseNet(resp *idemix.EnrollmentResponse) common.IdemixEnrollmentResponseNet {
	return common.IdemixEnrollmentResponseNet{
		Nonce:      resp.Nonce,
		Attrs:      resp.Attrs,
		Credential: resp.Credential,
		CAInfo:     common.CAInfoResponseNet{}}
}

// idemixServerCtx implements idemix.ServerRequestContext
type idemixServerCtx struct {
	srvCtx *serverRequestContext
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
