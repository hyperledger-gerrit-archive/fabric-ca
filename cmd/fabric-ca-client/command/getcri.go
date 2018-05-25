/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"
	"path"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/client/credential/idemix"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

const (
	// GetCRICmdUsage is the usage text for getcri command
	GetCRICmdUsage = "getcri"
	// GetCRICmdShortDesc is the short description for getcri command
	GetCRICmdShortDesc = "GET latest CRI from the Fabric CA server"
)

type getCRICmd struct {
	Command
}

func newGetCRICmd(c Command) *getCRICmd {
	getcricmd := &getCRICmd{c}
	return getcricmd
}

func (c *getCRICmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "getcri",
		Short:   "GET latest CRI from the Fabric CA server",
		Long:    "GET latest CRI from the Fabric CA server",
		PreRunE: c.preRunGetCRI,
		RunE:    c.runGetCRI,
	}
	return cmd
}

func (c *getCRICmd) preRunGetCRI(cmd *cobra.Command, args []string) error {
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

func (c *getCRICmd) runGetCRI(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runGetCRI")
	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.GetCRIRequest{
		CAName: c.GetClientCfg().CAName,
	}
	resp, err := id.GetCRI(req)
	if err != nil {
		return err
	}
	log.Info("Successfully got the Idemix Credential Revocation Information from the server")
	criBytes, err := util.B64Decode(resp.CRI)
	if err != nil {
		return errors.WithMessage(err, "Failed to decode CRI present in the response")
	}
	cred := id.GetIdemixCredential()
	if cred != nil {
		val, err := cred.Val()
		if err != nil {
			log.Errorf("Invalid state; Identity has unitialized Idemix credential")
			return err
		}
		signerCfg, _ := val.(idemix.SignerConfig)
		signerCfg.CredentialRevocationInformation = criBytes
		err = cred.Store()
		if err != nil {
			return err
		}
		log.Info("Successfully updated the CRI in the user's SignerConfig")
	} else {
		crifile := path.Join(c.GetClientCfg().MSPDir, "cri")
		err := util.WriteFile(crifile, criBytes, 0644)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to write CRI to file %s", crifile))
		}
	}
	return nil
}
