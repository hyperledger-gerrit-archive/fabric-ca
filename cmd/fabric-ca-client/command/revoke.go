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
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

const (
	// RevokeCmdUsage is the usage text for revoke command
	RevokeCmdUsage = "revoke"
	// RevokeCmdShortDesc is the short description for revoke command
	RevokeCmdShortDesc = "Revoke an identity"
	// RevokeCmdLongDesc is the long description for revoke command
	RevokeCmdLongDesc = "Revoke an identity with Fabric CA server"
)

var errInput = errors.New("Invalid usage; either --revoke.name and/or both --revoke.serial and --revoke.aki are required")

type revokeArgs struct {
	// GenCRL specifies whether to generate a CRL
	GenCRL bool   `def:"false" json:"gencrl,omitempty" help:"Generates a CRL that contains all revoked certificates"`
	Type   string `def:"x509" help:"The type of revocation request: 'x509' or 'idemix'"`
}

type revokeCmd struct {
	Command
	revokeParams revokeArgs
}

func newRevokeCmd(c Command) *revokeCmd {
	revCmd := &revokeCmd{c, revokeArgs{}}
	return revCmd
}

func (c *revokeCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     RevokeCmdUsage,
		Short:   RevokeCmdShortDesc,
		Long:    RevokeCmdLongDesc,
		PreRunE: c.preRunRevoke,
		RunE:    c.runRevoke,
	}
	util.RegisterFlags(c.GetViper(), cmd.Flags(), &c.revokeParams, nil)
	return cmd
}

func (c *revokeCmd) preRunRevoke(cmd *cobra.Command, args []string) error {
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

// The client revoke main logic
func (c *revokeCmd) runRevoke(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runRevoke")

	var err error
	clientCfg := c.GetClientCfg()
	client := lib.Client{
		HomeDir: filepath.Dir(c.GetCfgFileName()),
		Config:  clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	if c.revokeParams.Type == "Idemix" {

	} else {
		// aki and serial # are required to revoke a certificate. The enrollment ID
		// is required to revoke an identity. So, either aki and serial must be
		// specified OR enrollment ID must be specified, else return an error.
		// Note that all three can be specified, in which case server will revoke
		// certificate associated with the specified aki, serial number.
		if (clientCfg.Revoke.Name == "") && (clientCfg.Revoke.AKI == "" ||
			clientCfg.Revoke.Serial == "") {
			cmd.Usage()
			return errInput
		}

		req := &api.RevocationRequest{
			Name:   clientCfg.Revoke.Name,
			Serial: clientCfg.Revoke.Serial,
			AKI:    clientCfg.Revoke.AKI,
			Reason: clientCfg.Revoke.Reason,
			GenCRL: c.revokeParams.GenCRL,
			CAName: clientCfg.CAName,
		}
		result, err := id.Revoke(req)

		if err != nil {
			return err
		}
		log.Infof("Sucessfully revoked certificates: %+v", result.RevokedCerts)

		if req.GenCRL {
			return storeCRL(clientCfg, result.CRL)
		}
	}

	return nil
}
