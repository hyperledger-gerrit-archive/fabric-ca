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

package lib

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric-ca/util"
)

// serverRequestContext represents an HTTP request/response context in the server
type serverRequestContext struct {
	req            *http.Request
	resp           http.ResponseWriter
	server         *Server
	ca             *CA
	enrollmentID   string
	enrollmentCert *x509.Certificate
	body           struct {
		read bool   // true after body is read
		buf  []byte // the body itself
		err  error  // any error from reading the body
	}
}

// newServerRequestContext is the constructor for a serverRequestContext
func newServerRequestContext(r *http.Request, w http.ResponseWriter, s *Server) *serverRequestContext {
	return &serverRequestContext{
		req:    r,
		resp:   w,
		server: s,
	}
}

// BasicAuthentication authenticates the caller's username and password
// in the authorization header and returns the username
func (ctx *serverRequestContext) BasicAuthentication() (string, error) {
	r := ctx.req
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", newErr(ErrNoAuthHdr, 401, "No authorization header")
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", newErr(ErrNoUserPass, 401, "No user/pass in authorization header")
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	ui, err := ca.registry.GetUser(username, nil)
	if err != nil {
		return "", newErr(ErrInvalidUser, 401, "Invalid user")
	}
	err = ui.Login(password)
	if err != nil {
		return "", newErr(ErrInvalidPass, 401, "Login failure")
	}
	ctx.enrollmentID = username
	return username, nil
}

// TokenAuthentication authenticates the caller by token
// in the authorization header.
// Returns the enrollment ID or error.
func (ctx *serverRequestContext) TokenAuthentication() (string, error) {
	r := ctx.req
	// Requires authorization header
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", newErr(ErrNoAuthHdr, 401, "No authorization header")
	}
	// Get the CA
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	// Get the request body
	body, err := ctx.ReadBodyBytes()
	if err != nil {
		return "", err
	}
	// Verify the token; the signature is over the header and body
	cert, err2 := util.VerifyToken(ca.csp, authHdr, body)
	if err2 != nil {
		return "", newErr(ErrInvalidToken, 401, "Invalid token in authorization header: %s", err2)
	}
	id := util.GetEnrollmentIDFromX509Certificate(cert)
	log.Debugf("Checking for revocation/expiration of certificate owned by '%s'", id)
	// VerifyCertificate ensures that the certificate passed in hasn't
	// expired and checks the CRL for the server.
	revokedOrExpired, checked := revoke.VerifyCertificate(cert)
	if !checked {
		return "", newErr(ErrRevokeCheckingFailed, 500, "Failed while checking for revocation")
	}
	if revokedOrExpired {
		return "", newErr(ErrRevokedOrExpired, 401,
			"The certificate in the authorization header is a revoked or expired certificate")
	}
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki = strings.ToLower(strings.TrimLeft(aki, "0"))
	serial = strings.ToLower(strings.TrimLeft(serial, "0"))
	certs, err := ca.CertDBAccessor().GetCertificate(serial, aki)
	if err != nil {
		return "", newErr(ErrCertNotFound, 500, "Failed searching certificates: %s", err)
	}
	if len(certs) == 0 {
		return "", newErr(ErrCertNotFound, 401, "Certificate not found with AKI '%s' and serial '%s'", aki, serial)
	}
	for _, certificate := range certs {
		if certificate.Status == "revoked" {
			return "", newErr(ErrRevoked, 401,
				"The certificate in the authorization header is a revoked certificate")
		}
	}
	ctx.enrollmentID = id
	ctx.enrollmentCert = cert
	log.Debugf("Successful token authentication of '%s'", id)
	return id, nil
}

// GetECert returns the enrollment certificate of the caller, assuming
// token authentication was successful.
func (ctx *serverRequestContext) GetECert() *x509.Certificate {
	return ctx.enrollmentCert
}

// GetCA returns the CA to which this request is targeted
func (ctx *serverRequestContext) GetCA() (*CA, error) {
	if ctx.ca == nil {
		// Get the CA name
		name, err := ctx.getCAName()
		if err != nil {
			return nil, err
		}
		// Get the CA by its name
		ctx.ca, err = ctx.server.GetCA(name)
		if err != nil {
			return nil, err
		}
	}
	return ctx.ca, nil
}

// GetUserinfo returns the caller's requested attribute values and affiliation path
func (ctx *serverRequestContext) GetUserInfo(attrNames []string) ([]tcert.Attribute, []string, error) {
	id := ctx.enrollmentID
	if id == "" {
		return nil, nil, newErr(ErrBadInternalState, 500, "Caller is not authenticated")
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, nil, err
	}
	user, err := ca.registry.GetUser(id, attrNames)
	if err != nil {
		return nil, nil, err
	}
	var attrs []tcert.Attribute
	for _, name := range attrNames {
		value := user.GetAttribute(name)
		if value != "" {
			attrs = append(attrs, tcert.Attribute{Name: name, Value: value})
		}
	}
	return attrs, user.GetAffiliationPath(), nil
}

// caNameReqBody is a sparse request body to unmarshal only the CA name
type caNameReqBody struct {
	CAName string `json:"caname,omitempty"`
}

// getCAName returns the targeted CA name for this request
func (ctx *serverRequestContext) getCAName() (string, error) {
	// Check the query parameters first
	ca := ctx.req.URL.Query().Get("ca")
	if ca != "" {
		return ca, nil
	}
	// Next, check the request body
	var body caNameReqBody
	err := ctx.ReadBody(&body)
	if err != nil {
		return "", err
	}
	return body.CAName, nil
}

// ReadBody reads the request body and JSON unmarshals into 'body'
func (ctx *serverRequestContext) ReadBody(body interface{}) error {
	buf, err := ctx.ReadBodyBytes()
	if err != nil {
		return err
	}
	if len(buf) == 0 {
		return newErr(ErrEmptyReqBody, 400, "Empty request body")
	}
	err = json.Unmarshal(buf, body)
	if err != nil {
		return newErr(ErrBadReqBody, 400, "Invalid request body: %s; body=%s",
			err, string(buf))
	}
	return nil
}

// ReadBodyBytes reads the request body and returns bytes
func (ctx *serverRequestContext) ReadBodyBytes() ([]byte, error) {
	if !ctx.body.read {
		r := ctx.req
		buf, err := ioutil.ReadAll(r.Body)
		r.Body = ioutil.NopCloser(bytes.NewReader(buf))
		ctx.body.buf = buf
		ctx.body.err = err
		ctx.body.read = true
	}
	err := ctx.body.err
	if err != nil {
		return nil, newErr(ErrReadingReqBody, 400, "Failed reading request body: %s", err)
	}
	return ctx.body.buf, nil
}
