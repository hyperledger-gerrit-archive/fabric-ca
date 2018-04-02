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
)

type crlArgs struct {
	// Genenerate CRL with all the certificates that were revoked after this timestamp
	RevokedAfter string `help:"Generate CRL with certificates that were revoked after this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that were revoked before this timestamp
	RevokedBefore string `help:"Generate CRL with certificates that were revoked before this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that expire after this timestamp
	ExpireAfter string `help:"Generate CRL with certificates that expire after this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that expire before this timestamp
	ExpireBefore string `help:"Generate CRL with certificates that expire before this UTC timestamp (in RFC3339 format)"`
}

type genCRLCmd struct {
	Command
	// gencrl command argument values
	params crlArgs
}

func newGenCRLCmd(c *ClientCmd) *genCRLCmd {
	cmd := &genCRLCmd{c, crlArgs{}}
	return cmd
}

func (c *genCRLCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "gencrl",
		Short:   "Generate a CRL",
		Long:    "Generate a Certificate Revocation List",
		PreRunE: c.preRunGenCRL,
		RunE:    c.runGenCRL,
	}
	util.RegisterFlags(c.GetViper(), cmd.Flags(), &c.params, nil)
	return cmd
}

func (c *genCRLCmd) preRunGenCRL(cmd *cobra.Command, args []string) error {
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

// The client genCRL main logic
func (c *genCRLCmd) runGenCRL(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runGenCRL")
	client := lib.Client{
		HomeDir: filepath.Dir(c.GetCfgFileName()),
		Config:  c.GetClientCfg(),
	}
	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}
	var revokedAfter, revokedBefore time.Time
	if c.params.RevokedAfter != "" {
		revokedAfter, err = time.Parse(time.RFC3339, c.params.RevokedAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedafter' value")
		}
	}
	if c.params.RevokedBefore != "" {
		revokedBefore, err = time.Parse(time.RFC3339, c.params.RevokedBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedbefore' value")
		}
	}
	if !revokedBefore.IsZero() && revokedAfter.After(revokedBefore) {
		return errors.Errorf("Invalid revokedafter value '%s'. It must not be a timestamp greater than revokedbefore value '%s'",
			c.params.RevokedAfter, c.params.RevokedBefore)
	}

	var expireAfter, expireBefore time.Time
	if c.params.ExpireAfter != "" {
		expireAfter, err = time.Parse(time.RFC3339, c.params.ExpireAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expireafter' value")
		}
	}
	if c.params.ExpireBefore != "" {
		expireBefore, err = time.Parse(time.RFC3339, c.params.ExpireBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expirebefore' value")
		}
	}
	if !expireBefore.IsZero() && expireAfter.After(expireBefore) {
		return errors.Errorf("Invalid expireafter value '%s'. It must not be a timestamp greater than expirebefore value '%s'",
			c.params.ExpireAfter, c.params.ExpireBefore)
	}
	req := &api.GenCRLRequest{
		CAName:        c.GetClientCfg().CAName,
		RevokedAfter:  revokedAfter,
		RevokedBefore: revokedBefore,
		ExpireAfter:   expireAfter,
		ExpireBefore:  expireBefore,
	}
	resp, err := id.GenCRL(req)
	if err != nil {
		return err
	}
	log.Info("Successfully generated the CRL")
	err = storeCRL(c.GetClientCfg(), resp.CRL)
	if err != nil {
		return err
	}
	return nil
}

// Store the CRL
func storeCRL(config *lib.ClientConfig, crl []byte) error {
	dirName := path.Join(config.MSPDir, crlsFolder)
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(dirName, os.ModeDir|0755)
		if mkdirErr != nil {
			return errors.Wrapf(mkdirErr, "Failed to create directory %s", dirName)
		}
	}
	fileName := path.Join(dirName, crlFile)
	err := util.WriteFile(fileName, crl, 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write CRL to the file %s", fileName)
	}
	log.Info("Successfully stored the CRL in the file %s", fileName)
	return nil
}
