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

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

func (c *ClientCmd) newGetCACertCommand() *cobra.Command {
	getCACertCmd := &cobra.Command{
		Use:   "getcacert -u http://serverAddr:serverPort -M <MSP-directory>",
		Short: "Get CA certificate chain",
		// PreRunE block for this command will load client configuration
		// before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runGetCACert()
			if err != nil {
				return err
			}
			return nil
		},
	}
	return getCACertCmd
}

// The client "getcacert" main logic
func (c *ClientCmd) runGetCACert() error {
	log.Debug("Entered runGetCACert")

	client := &lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	req := &api.GetCAInfoRequest{
		CAName: c.clientCfg.CAName,
	}

	si, err := client.GetCAInfo(req)
	if err != nil {
		return err
	}

	return storeCAChain(client.Config, si)
}

// Store the CAChain in the CACerts folder of MSP (Membership Service Provider)
// The 1st cert in the chain goes into MSP 'cacerts' directory.
// The others (if any) go into the MSP 'intermediates' directory.
func storeCAChain(config *lib.ClientConfig, si *lib.GetServerInfoResponse) error {
	mspDir := config.MSPDir
	// Get a unique name to use for filenames
	serverURL, err := url.Parse(config.URL)
	if err != nil {
		return err
	}
	fname := serverURL.Host
	if config.CAName != "" {
		fname = fmt.Sprintf("%s-%s", fname, config.CAName)
	}
	fname = strings.Replace(fname, ":", "-", -1)
	fname = strings.Replace(fname, ".", "-", -1) + ".pem"
	tlsfname := fmt.Sprintf("tls-%s", fname)

	rootCACertsDir := path.Join(mspDir, "cacerts")
	intCACertsDir := path.Join(mspDir, "intermediatecerts")
	tlsRootCACertsDir := path.Join(mspDir, "tlscacerts")
	tlsIntCACertsDir := path.Join(mspDir, "tlsintermediatecerts")

	// Remove existing directories
	os.RemoveAll(rootCACertsDir)
	os.RemoveAll(intCACertsDir)
	os.RemoveAll(tlsRootCACertsDir)
	os.RemoveAll(tlsIntCACertsDir)

	chain := si.CAChain
	for len(chain) > 0 {
		var block *pem.Block
		var certsDir, tlsCertsDir, what string
		block, chain = pem.Decode(chain)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrap(err, "Failed to parse certificate in the CA chain")
		}

		// If authority key id is not present then it must be the root certificate
		if cert.AuthorityKeyId == nil || len(cert.AuthorityKeyId) == 0 {
			// Store the root certificate in the "cacerts" msp folder
			certsDir = rootCACertsDir
			tlsCertsDir = tlsRootCACertsDir
			what = "root certificate"
		} else {
			// Store the root certificate in the "intermediatecerts" msp folder
			certsDir = intCACertsDir
			tlsCertsDir = tlsIntCACertsDir
			what = "intermediate certificate"
		}
		certBytes := pem.EncodeToMemory(block)
		err = storeCert(what, certsDir, fname, certBytes)
		if err != nil {
			return err
		}
		err = storeCert(fmt.Sprintf("TLS %s", what), tlsCertsDir, tlsfname, certBytes)
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
	err = util.AppendToFile(fpath, contents, 0644)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to store %s at '%s'", what, fpath))
	}
	log.Infof("Stored %s at %s", what, fpath)
	return nil
}
