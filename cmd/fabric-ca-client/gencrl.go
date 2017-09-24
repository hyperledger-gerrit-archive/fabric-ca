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
	"bufio"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	// crlsFolder is the MSP folder name where generate CRL will be stored
	crlsFolder = "crls"
	// crlFile is the name of the file used to the generate CRL
	crlFile = "crl.pem"
	// crlPemHeader is the header of a X509 CRL
	crlPemHeader = "-----BEGIN X509 CRL-----\n"
	// crlPemFooter is the footer of a X509 CRL
	crlPemFooter = "\n-----END X509 CRL-----\n"
)

func (c *ClientCmd) newGenCRLCommand() *cobra.Command {
	var genCrlCmd = &cobra.Command{
		Use:   "gencrl",
		Short: "Generate a CRL",
		Long:  "Generate a Certificate Revocation List",
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
			err := c.runGenCRL()
			if err != nil {
				return err
			}

			return nil
		},
	}

	util.RegisterFlags(c.myViper, genCrlCmd.Flags(), &c.crlParams, nil)
	return genCrlCmd
}

// The client register main logic
func (c *ClientCmd) runGenCRL() error {
	log.Debug("Entered runGenCRL")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}
	var after, before time.Time
	if c.crlParams.RevokedAfter != "" {
		after, err = time.Parse(time.RFC3339, c.crlParams.RevokedAfter)
		if err != nil {
			return err
		}
	}

	if c.crlParams.RevokedBefore != "" {
		before, err = time.Parse(time.RFC3339, c.crlParams.RevokedBefore)
		if err != nil {
			return err
		}
	}

	if !before.IsZero() && after.After(before) {
		return errors.Errorf("invalid revokedafter value '%s'. It must not be a timestamp greater than revokedbefore '%s'",
			c.crlParams.RevokedAfter, c.crlParams.RevokedBefore)
	}

	req := &api.GenCRLRequest{
		CAName:        c.clientCfg.CAName,
		RevokedAfter:  after,
		RevokedBefore: before,
	}

	resp, err := id.GenCRL(req)
	if err != nil {
		return err
	}
	err = storeCRL(c.clientCfg, resp)
	if err != nil {
		return err
	}
	return nil
}

// Store the CRL
func storeCRL(config *lib.ClientConfig, resp *api.GenCRLResponse) error {
	dirName := path.Join(config.MSPDir, crlsFolder)
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		err = os.Mkdir(dirName, os.ModeDir|0755)
		if err != nil {
			return errors.Wrapf(err, "failed to create directory %s", dirName)
		}
	}

	fileName := path.Join(dirName, crlFile)
	f, err := os.Create(fileName)
	if err != nil {
		return errors.Wrapf(err, "failed to create CRL file %s", fileName)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	w.WriteString(crlPemHeader)
	w.WriteString(resp.CRL)
	w.WriteString(crlPemFooter)
	w.Flush()
	return nil
}
