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
	"fmt"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/spf13/cobra"
)

func newReenrollCommand(c *ClientCmd) *cobra.Command {
	reenrollCmd := &cobra.Command{
		Use:   "reenroll",
		Short: "Reenroll an identity",
		Long:  "Reenroll an identity with fabric-ca server",
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

			err := runReenroll(c)
			if err != nil {
				return err
			}

			return nil
		},
	}
	return reenrollCmd
}

// The client reenroll main logic
func runReenroll(c *ClientCmd) error {
	log.Debug("Reenroll entered")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ReenrollmentRequest{
		Hosts:   c.clientCfg.Enrollment.Hosts,
		Label:   c.clientCfg.Enrollment.Label,
		Profile: c.clientCfg.Enrollment.Profile,
		CSR:     &c.clientCfg.CSR,
	}

	resp, err := id.Reenroll(req)
	if err != nil {
		return fmt.Errorf("Failed to store enrollment information: %s", err)
	}

	err = resp.Identity.Store()
	if err != nil {
		return err
	}

	err = storeCAChain(c.clientCfg, &resp.ServerInfo)
	if err != nil {
		return err
	}

	return nil
}
