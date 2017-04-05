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
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/spf13/cobra"
)

var errInput = errors.New("Invalid usage; either --eid or both --serial and --aki are required")

// initCmd represents the init command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke user",
	Long:  "Revoke user with fabric-ca server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		err := configInit(cmd.Name())
		if err != nil {
			return err
		}

		log.Debugf("Client configuration settings: %+v", clientCfg)

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runRevoke(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
}

// The client revoke main logic
func runRevoke(cmd *cobra.Command) error {
	log.Debug("Revoke Entered")

	var err error

	client := lib.Client{
		HomeDir: filepath.Dir(cfgFileName),
		Config:  clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	if clientCfg.Revoke.Name == "" {
		if clientCfg.Revoke.Serial == "" || clientCfg.Revoke.AKI == "" {
			return errInput
		}
	} else {
		if clientCfg.Revoke.Serial != "" || clientCfg.Revoke.AKI != "" {
			return errInput
		}
	}

	err = id.Revoke(
		&api.RevocationRequest{
			Name:   clientCfg.Revoke.Name,
			Serial: clientCfg.Revoke.Serial,
			AKI:    clientCfg.Revoke.AKI,
			Reason: clientCfg.Revoke.Reason,
		})

	if err == nil {
		log.Infof("Revocation was successful")
	}

	return err
}
