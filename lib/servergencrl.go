/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// The response to the GET /info request
type genCRLResponseNet struct {
	CRL []byte
}

func newGenCRLEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: genCRLHandler,
		Server:  s,
	}
}

// Handle an generate CRL request
func genCRLHandler(ctx *serverRequestContext) (interface{}, error) {
	var req api.GenCRLRequest
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	// Authenticate the invoker
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	log.Debugf("Received gencrl request from %s: %+v", id, util.StructToString(&req))

	// Get targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	// Make sure that the user has the "hf.GenCRL" attribute in order to be authorized
	// to generate CRL. This attribute comes from the user registry, which
	// is either in the DB if LDAP is not configured, or comes from LDAP if LDAP is
	// configured.
	err = ca.attributeIsTrue(id, "hf.GenCRL")
	if err != nil {
		return nil, errors.WithMessage(err,
			fmt.Sprintf("the identity '%s' does not have authority to generate CRL", id))
	}

	crl, err := genCRL(ca, req)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRL: %s\n", crl)

	resp := &genCRLResponseNet{CRL: crl}
	return resp, nil
}

// GenCRL will generate CRL
func genCRL(ca *CA, req api.GenCRLRequest) ([]byte, error) {
	var err error
	before := req.RevokedBefore
	if before.IsZero() {
		before = time.Now().UTC()
	}
	if req.RevokedAfter.After(before) {
		log.Errorf("GenCRLRequest.RevokedAfter timestamp %s is greater than the GenCRLRequest.RevokedBefore timestamp %s",
			req.RevokedAfter.Format(time.RFC3339), before.Format(time.RFC3339))
		return nil, errors.New("invalid revokedafter value. It must not be a timestamp greater than revokedbefore")
	}

	// Get revoked certificates from the database
	certs, err := ca.certDBAccessor.GetRevokedCertificates(req.RevokedAfter, before)
	if err != nil {
		log.Errorf("Failed to get revoked certificates from the database: %s", err)
		return nil, errors.WithMessage(err, "failed to get revoked certificates from the database")
	}
	if len(certs) == 0 {
		return nil, errors.Errorf("no revoked certificates found between %s and %s",
			req.RevokedAfter.Format(time.RFC3339), before.Format(time.RFC3339))
	}

	caCert, err := getCACert(ca)
	if err != nil {
		log.Errorf("Failed to get certificate for the CA %s: %s", ca.HomeDir, err)
		return nil, errors.Wrapf(err, "failed to get certficate for the CA %s", ca.HomeDir)
	}

	// Get the signer for the CA
	_, signer, err := util.GetSignerFromCert(caCert, ca.csp)
	if err != nil {
		log.Errorf("Failed to get signer for the CA %s: %s", ca.HomeDir, err)
		return nil, errors.WithMessage(err, fmt.Sprintf("failed to get signer for the CA %s", ca.HomeDir))
	}

	// Expiry is set to 3 months (no significance), Fabric does not use this value
	// as it uses push model, where CRL needs to be added to the crls folder of the
	// MSP
	expiry := time.Now().UTC().AddDate(0, 3, 0)
	var revokedCerts []pkix.RevokedCertificate

	// For every record, create a new revokedCertificate and add it to slice
	for _, certRecord := range certs {
		serialInt := new(big.Int)
		serialInt.SetString(certRecord.Serial, 16)
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	crl, err := crl.CreateGenericCRL(revokedCerts, signer, caCert, expiry)
	if err != nil {
		log.Errorf("Failed to generate CRL for the CA %s: %s", ca.HomeDir, err)
		return nil, errors.Wrap(err, "failed to generate CRL")
	}
	return crl, nil
}

func getCACert(ca *CA) (*x509.Certificate, error) {
	// Get CA certificate
	caCertBytes, err := ioutil.ReadFile(ca.Config.CA.Certfile)
	if err != nil {
		log.Errorf("Failed to read certificate for the CA %s: %s", ca.HomeDir, err)
		return nil, err
	}
	caCert, err := BytesToX509Cert(caCertBytes)
	if err != nil {
		log.Errorf("Failed to get certificate for the CA %s: %s", ca.HomeDir, err)
		return nil, err
	}
	return caCert, nil
}
