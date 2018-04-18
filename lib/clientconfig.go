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
	"fmt"
	"net/url"
	"path"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
)

// ClientConfig represents configuration used by the Fabric CA client
type ClientConfig interface {
	// Enrolls an identity using the enrollment request specified in this config and
	// the lib.EnrollmentResponse object
	Enroll(rawurl, home string) (*EnrollmentResponse, error)
	// Generates a CSR using the csr info specified in this config and writes it
	// to the <msp dir>/signcerts/<cn specifed in the csr section of the config>.csr file
	GenCSR(home string) error
	// Returns Fabric CA server URL specified in this config
	GetURL() string
	// Returns name of the CA specified in this config
	GetCAName() string
	// Returns fully qualified name of the msp directory specified in this config
	GetMSPDir() string
	// Returns enrollment info specified in this config
	GetEnrollmentRequest() *api.EnrollmentRequest
	// Returns registration info specified in this config
	GetID() *api.RegistrationRequest
}

// ClientConfigImpl is the Fabric CA client's config
type ClientConfigImpl struct {
	URL        string `def:"http://localhost:7054" opt:"u" help:"URL of fabric-ca-server"`
	MSPDir     string `def:"msp" opt:"M" help:"Membership Service Provider directory"`
	TLS        tls.ClientTLSConfig
	Enrollment api.EnrollmentRequest
	CSR        api.CSRInfo
	ID         api.RegistrationRequest
	Revoke     api.RevocationRequest
	CAInfo     api.GetCAInfoRequest
	CAName     string               `help:"Name of CA"`
	CSP        *factory.FactoryOpts `mapstructure:"bccsp"`
}

// Enroll a client given the server's URL and the client's home directory.
// The URL may be of the form: http://user:pass@host:port where user and pass
// are the enrollment ID and secret, respectively.
func (c *ClientConfigImpl) Enroll(rawurl, home string) (*EnrollmentResponse, error) {
	purl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if purl.User != nil {
		name := purl.User.Username()
		secret, _ := purl.User.Password()
		c.Enrollment.Name = name
		c.Enrollment.Secret = secret
		purl.User = nil
	}

	// When requesting idemix credential, user can use either basic or
	// token auth based on X509 certificate. So, return error only when
	// enroll is for X509 cert and userid/password are missing from the
	// server URL.
	if c.Enrollment.Name == "" && !c.Enrollment.Idemix {
		expecting := fmt.Sprintf(
			"%s://<enrollmentID>:<secret>@%s",
			purl.Scheme, purl.Host)
		return nil, errors.Errorf(
			"The URL of the fabric CA server is missing the enrollment ID and secret;"+
				" found '%s' but expecting '%s'", rawurl, expecting)
	}
	c.Enrollment.CAName = c.CAName
	c.URL = purl.String()
	c.TLS.Enabled = purl.Scheme == "https"
	c.Enrollment.CSR = &c.CSR
	client := &Client{HomeDir: home, Config: c}
	return client.Enroll(&c.Enrollment)
}

// GenCSR generates a certificate signing request and writes the CSR to a file.
func (c *ClientConfigImpl) GenCSR(home string) error {

	client := &Client{HomeDir: home, Config: c}
	// Generate the CSR

	err := client.Init()
	if err != nil {
		return err
	}

	if c.CSR.CN == "" {
		return errors.Errorf("CSR common name not specified; use '--csr.cn' flag")
	}

	csrPEM, _, err := client.GenCSR(&c.CSR, c.CSR.CN)
	if err != nil {
		return err
	}

	csrFile := path.Join(client.Config.MSPDir, "signcerts", fmt.Sprintf("%s.csr", c.CSR.CN))
	err = util.WriteFile(csrFile, csrPEM, 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the CSR")
	}
	log.Infof("Stored CSR at %s", csrFile)
	return nil
}

// GetURL returns server URL from this configuration
func (c *ClientConfigImpl) GetURL() string {
	return c.URL
}

// GetCAName returns CA name from this configuration
func (c *ClientConfigImpl) GetCAName() string {
	return c.CAName
}

// GetMSPDir returns msp directory from this configuration
func (c *ClientConfigImpl) GetMSPDir() string {
	return c.MSPDir
}

// GetEnrollmentRequest returns enrollment request from this configuration
func (c *ClientConfigImpl) GetEnrollmentRequest() *api.EnrollmentRequest {
	return &c.Enrollment
}

// GetID returns registration request from this configuration
func (c *ClientConfigImpl) GetID() *api.RegistrationRequest {
	return &c.ID
}
