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
	"path/filepath"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
)

// newServerCfgCommand creates a command on the client
func (c *ClientCmd) newServerCfgCommand() *cobra.Command {
	servercfgCmd := &cobra.Command{
		Use:   "servercfg",
		Short: "Update server's configuration",
		Long:  "Update Fabric-CA server's configuration",
		// PreRunE block for this command will check to make sure username
		// and secret provided for the enroll command before creating and/or
		// reading configuration file
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runServerCfg(cmd, args)
			if err != nil {
				return err
			}
			return nil
		},
	}

	return servercfgCmd
}

// runServerCfg is the main logic on client side for updating server's configuration
func (c *ClientCmd) runServerCfg(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runServerCfg, requesting server configuration updates")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := new(api.UpdateConfigRequest)
	req.Update = args
	err = id.UpdateServerConfig(req)
	if err != nil {
		return err
	}

	return nil
}
