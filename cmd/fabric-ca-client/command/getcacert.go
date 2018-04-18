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

package command

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

const (
	// GetCACertCmdUsage is the usage text for getCACert command
	GetCACertCmdUsage = "getcacert -u http://serverAddr:serverPort -M <MSP-directory>"
	// GetCACertCmdShortDesc is the short description for getCACert command
	GetCACertCmdShortDesc = "Get CA certificate chain and idemix issuer public key"
)

// getCACertCmd reperesents getcacert command
type getCACertCmd struct {
	Command
}

// NewGetCACertCmd returns cobra.Command that represents getcacert command
func NewGetCACertCmd(c Command) *cobra.Command {
	getcacertcmd := &getCACertCmd{c}
	return getcacertcmd.getCommand()
}

// getCommand returns cobra.Command object for getcacert command
func (c *getCACertCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     GetCACertCmdUsage,
		Short:   GetCACertCmdShortDesc,
		PreRunE: c.preRunGetCACert,
		RunE:    c.runGetCACert,
	}
	return cmd
}

// preRunGetCACert is the PreRunE function for getcacert cobra command
func (c *getCACertCmd) preRunGetCACert(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

// runGetCACert is the RunE function for getcacert cobra command
func (c *getCACertCmd) runGetCACert(cmd *cobra.Command, args []string) error {
	log.Debug("Entered RunGetCACert")

	client := c.GetClient()

	req := &api.GetCAInfoRequest{
		CAName: c.GetClientCfg().GetCAName(),
	}

	si, err := client.GetCAInfo(req)
	if err != nil {
		return err
	}

	err = storeCAChain(c.GetClientCfg(), si)
	if err != nil {
		return err
	}
	return storeIssuerPublicKey(c.GetClientCfg(), si)
}

// Store the CAChain in the CACerts folder of MSP (Membership Service Provider)
// The root cert in the chain goes into MSP 'cacerts' directory.
// The others (if any) go into the MSP 'intermediatecerts' directory.
func storeCAChain(config Config, si *lib.GetServerInfoResponse) error {
	mspDir := config.GetMSPDir()
	// Get a unique name to use for filenames
	serverURL, err := url.Parse(config.GetURL())
	if err != nil {
		return err
	}
	fname := serverURL.Host
	if config.GetCAName() != "" {
		fname = fmt.Sprintf("%s-%s", fname, config.GetCAName())
	}
	fname = strings.Replace(fname, ":", "-", -1)
	fname = strings.Replace(fname, ".", "-", -1) + ".pem"
	tlsfname := fmt.Sprintf("tls-%s", fname)

	rootCACertsDir := path.Join(mspDir, "cacerts")
	intCACertsDir := path.Join(mspDir, "intermediatecerts")
	tlsRootCACertsDir := path.Join(mspDir, "tlscacerts")
	tlsIntCACertsDir := path.Join(mspDir, "tlsintermediatecerts")

	var rootBlks [][]byte
	var intBlks [][]byte
	chain := si.CAChain
	for len(chain) > 0 {
		var block *pem.Block
		block, chain = pem.Decode(chain)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrap(err, "Failed to parse certificate in the CA chain")
		}

		if !cert.IsCA {
			return errors.New("A certificate in the CA chain is not a CA certificate")
		}

		// If authority key id is not present or if it is present and equal to subject key id,
		// then it is a root certificate
		if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
			rootBlks = append(rootBlks, pem.EncodeToMemory(block))
		} else {
			intBlks = append(intBlks, pem.EncodeToMemory(block))
		}
	}

	// Store the root certificates in the "cacerts" msp folder
	certBytes := bytes.Join(rootBlks, []byte(""))
	if len(certBytes) > 0 {
		if config.GetEnrollmentRequest().Profile == "tls" {
			err := storeCert("TLS root CA certificate", tlsRootCACertsDir, tlsfname, certBytes)
			if err != nil {
				return err
			}
		} else {
			err = storeCert("root CA certificate", rootCACertsDir, fname, certBytes)
			if err != nil {
				return err
			}
		}
	}

	// Store the intermediate certificates in the "intermediatecerts" msp folder
	certBytes = bytes.Join(intBlks, []byte(""))
	if len(certBytes) > 0 {
		if config.GetEnrollmentRequest().Profile == "tls" {
			err = storeCert("TLS intermediate certificates", tlsIntCACertsDir, tlsfname, certBytes)
			if err != nil {
				return err
			}
		} else {
			err = storeCert("intermediate CA certificates", intCACertsDir, fname, certBytes)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func storeIssuerPublicKey(config Config, si *lib.GetServerInfoResponse) error {
	if len(si.IssuerPublicKey) > 0 {
		err := storeCert("Issuer public key", config.GetMSPDir(), "IssuerPublicKey", si.IssuerPublicKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func storeCert(what, dir, fname string, contents []byte) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return errors.Wrapf(err, "Failed to create directory for %s at '%s'", what, dir)
	}
	fpath := path.Join(dir, fname)
	err = util.WriteFile(fpath, contents, 0644)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to store %s at '%s'", what, fpath))
	}
	log.Infof("Stored %s at %s", what, fpath)
	return nil
}
