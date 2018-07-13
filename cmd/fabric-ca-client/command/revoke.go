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
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	idemixapi "github.com/hyperledger/fabric-ca/lib/common/idemix/api"
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
	api.RevocationRequest
}

// Revoke defines all the revoke related functions an identity can invoke
type Revoke interface {
	RevokeIdemix(*api.RevocationRequest) (*idemixapi.RevocationResponse, error)
	RevokeAll(*api.RevocationRequest) (*api.AllRevocationResponse, error)
}

type revokeCmd struct {
	Command
	args revokeArgs
	id   *lib.Identity
}

func newRevokeCmd(c Command) *revokeCmd {
	revCmd := &revokeCmd{c, revokeArgs{}, nil}
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
	util.RegisterFlags(c.GetViper(), cmd.Flags(), &c.args.RevocationRequest, nil)
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
	c.id, err = c.LoadMyIdentity()
	if err != nil {
		return err
	}

	switch strings.ToLower(c.args.Type) {
	case "x509":
		return c.runX509Revoke(cmd, args)
	case "idemix":
		return c.runIdemixRevoke(cmd, args)
	default:
		return c.runRevokeAll(cmd, args)
	}
}

// The client logic for revoking x509 certificates
func (c *revokeCmd) runX509Revoke(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runX509Revoke")

	err := c.argCheck()
	if err != nil {
		cmd.Usage()
		return err
	}

	result, err := c.id.Revoke(&c.args.RevocationRequest)
	if err != nil {
		return err
	}
	log.Infof("Sucessfully revoked certificates: %+v", result.RevokedCerts)

	if c.args.GenCRL {
		return storeCRL(c.GetClientCfg(), []byte(result.CRL))
	}

	return nil
}

// The client logic for revoking idemix credentials
func (c *revokeCmd) runIdemixRevoke(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runIdemixRevoke")

	if (c.args.Name == "") && (c.args.IdemixRH == "") {
		return errors.New("Enrollment ID and/or Revocation Handle are required to revoke Idemix credential")
	}

	result, err := c.revokeIdemix(c.id)
	if err != nil {
		return err
	}

	log.Infof("Successfully revoked credential: %+v", result.RevokedHandles)
	return nil
}

func (c *revokeCmd) revokeIdemix(id Revoke) (*idemixapi.RevocationResponse, error) {
	result, err := id.RevokeIdemix(&c.args.RevocationRequest)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// The client logic for revoking idemix credentials
func (c *revokeCmd) runRevokeAll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runRevokeAll")

	err := c.argCheck()
	if err != nil {
		cmd.Usage()
		return err
	}

	if (c.args.Name == "") && (c.args.IdemixRH == "") {
		log.Warning("Enrollment ID and/or Revocation Handle are required to revoke Idemix credential")
	}

	result, err := c.revokeAll(c.id)
	if err != nil {
		return err
	}

	if c.args.GenCRL {
		return storeCRL(c.GetClientCfg(), []byte(result.X509Revocation.CRL))
	}

	log.Infof("Sucessfully revoked certificates: %+v\nSuccessfully revoked credential: %+v", result.X509Revocation.RevokedCerts, result.IdemixRevocation.RevokedHandles)
	return nil
}

func (c *revokeCmd) revokeAll(id Revoke) (*api.AllRevocationResponse, error) {
	result, err := id.RevokeAll(&c.args.RevocationRequest)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Local flags override any global flags, if any local flags are not set
// then try to get global flag values
func (c *revokeCmd) getReq(clientCfg *lib.ClientConfig) {
	if c.args.Name == "" {
		c.args.Name = clientCfg.Revoke.Name
	}
	if c.args.Serial == "" {
		c.args.Serial = clientCfg.Revoke.Serial
	}
	if c.args.AKI == "" {
		c.args.AKI = clientCfg.Revoke.AKI
	}
	if c.args.Reason == "" {
		c.args.Reason = clientCfg.Revoke.Reason
	}
	c.args.CAName = clientCfg.CAName
}

func (c *revokeCmd) argCheck() error {
	clientCfg := c.GetClientCfg()
	c.getReq(clientCfg)

	// aki and serial # are required to revoke a certificate. The enrollment ID
	// is required to revoke an identity. So, either aki and serial must be
	// specified OR enrollment ID must be specified, else return an error.
	// Note that all three can be specified, in which case server will revoke
	// certificate associated with the specified aki, serial number.
	if (c.args.Name == "") && (c.args.AKI == "" || c.args.Serial == "") {
		return errInput
	}

	return nil
}
