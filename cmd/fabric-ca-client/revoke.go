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
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var errInput = errors.New("Invalid usage; either --eid or both --serial and --aki are required")

func newRevokeCommand(c *ClientCmd) *cobra.Command {
	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an identity",
		Long:  "Revoke an identity with fabric-ca server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := configInit(c, cmd.Name())
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("Unrecognized arguments found: %v\n%s", args, cmd.UsageString())
			}

			err := runRevoke(c, cmd)
			if err != nil {
				return err
			}

			return nil
		},
	}
	revokeFlags := revokeCmd.Flags()
	util.FlagString(revokeFlags, "eid", "e", "", "Enrollment ID (Optional)")
	util.FlagString(revokeFlags, "serial", "s", "", "Serial Number")
	util.FlagString(revokeFlags, "aki", "a", "", "AKI")
	util.FlagString(revokeFlags, "reason", "r", "", "Reason for revoking")
	return revokeCmd
}

// The client revoke main logic
func runRevoke(c *ClientCmd, cmd *cobra.Command) error {
	log.Debug("Revoke entered")

	var err error

	enrollmentID := viper.GetString("eid")
	serial := viper.GetString("serial")
	aki := viper.GetString("aki")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
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
	if (enrollmentID == "") && (aki == "" || serial == "") {
		cmd.Usage()
		return errInput
	}

	reasonInput := viper.GetString("reason")
	var reason int
	if reasonInput != "" {
		reason = util.RevocationReasonCodes[reasonInput]
	}

	err = id.Revoke(
		&api.RevocationRequest{
			Name:   enrollmentID,
			Serial: serial,
			AKI:    aki,
			Reason: reason,
		})

	if err == nil {
		log.Infof("Revocation was successful")
	}

	return err
}
