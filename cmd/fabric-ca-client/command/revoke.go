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

type x509RevokeArgs struct {
	api.RevocationRequest
}

type idemixRevokeArgs struct {
	api.IdemixRevocationRequest
}

// Revoke defines all the revoke related functions an identity can invoke
type Revoke interface {
	RevokeIdemix(*api.IdemixRevocationRequest) (*api.IdemixRevocationResponse, error)
}

type revokeCmd struct {
	Command
	x509   x509RevokeArgs
	Idemix idemixRevokeArgs
}

func newRevokeCmd(c Command) *revokeCmd {
	revCmd := &revokeCmd{c, x509RevokeArgs{}, idemixRevokeArgs{}}
	return revCmd
}

func (c *revokeCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     RevokeCmdUsage,
		Short:   RevokeCmdShortDesc,
		Long:    RevokeCmdLongDesc,
		PreRunE: c.preRunRevoke,
		RunE:    c.runX509Revoke,
	}
	util.RegisterFlags(c.GetViper(), cmd.Flags(), &c.x509.RevocationRequest, nil)
	cmd.AddCommand(c.newIdemixCommand())
	return cmd
}

func (c *revokeCmd) newIdemixCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "idemix",
		Short:   "Revoke idemix credentials",
		Long:    "Revoke idemix credentials based on enrollment ID and/or revocation handle",
		PreRunE: c.preRunRevoke,
		RunE:    c.runIdemixRevoke,
	}
	util.RegisterFlags(c.GetViper(), cmd.Flags(), &c.Idemix.IdemixRevocationRequest, nil)
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
func (c *revokeCmd) runX509Revoke(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runX509Revoke")

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

	c.getReq(clientCfg)
	result, err := id.Revoke(&c.x509.RevocationRequest)

	if err != nil {
		return err
	}
	log.Infof("Sucessfully revoked certificates: %+v", result.RevokedCerts)

	if c.x509.GenCRL {
		return storeCRL(clientCfg, result.CRL)
	}

	return nil
}

// The client logic for revoking idemix credentials
func (c *revokeCmd) runIdemixRevoke(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runIdemixRevoke")

	var err error
	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	if (c.Idemix.Name == "") && (c.Idemix.RevocationHandle == "") {
		return errors.New("Enrollment ID and/or Revocation Handle are required to revoke Idemix credential")
	}

	result, err := c.revokeIdemix(id)
	if err != nil {
		return err
	}

	log.Infof("Successfully revoked credential: %+v", result.RevokedHandles)
	return nil
}

func (c *revokeCmd) revokeIdemix(id Revoke) (*api.IdemixRevocationResponse, error) {
	result, err := id.RevokeIdemix(&c.Idemix.IdemixRevocationRequest)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Local flags override any global flags, if any local flags are not set
// then try to get global flag values
func (c *revokeCmd) getReq(clientCfg *lib.ClientConfig) {
	if c.x509.Name == "" {
		c.x509.Name = clientCfg.Revoke.Name
	}
	if c.x509.Serial == "" {
		c.x509.Serial = clientCfg.Revoke.Serial
	}
	if c.x509.AKI == "" {
		c.x509.AKI = clientCfg.Revoke.AKI
	}
	if c.x509.Reason == "" {
		c.x509.Reason = clientCfg.Revoke.Reason
	}
	c.x509.CAName = clientCfg.CAName
}
