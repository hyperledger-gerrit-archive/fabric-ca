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

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"

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
	util.RegisterFlags(c.myViper, servercfgCmd.Flags(), &c.affiliations, nil)
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

	if len(args) == 0 {
		return errors.Errorf("No arguments specified")
	}

	if len(args)%2 != 0 {
		return errors.Errorf("Incorrect number of arguments specified; each action must have an associated configuration update request")
	}

	numberOfCmds := len(args) % 2
	commands := make([]api.Command, numberOfCmds)
	// Process the array of args consisting of configuration updates request
	for i := 0; i < len(args); i = i + 2 {
		commands = append(commands, api.Command{Args: []string{args[i], args[i+1]}})
	}

	req := &api.ConfigRequest{
		Commands: commands,
		CAName:   c.clientCfg.CAName,
		Force:    c.affiliations.Force,
	}
	resp, err := id.UpdateServerConfig(req)

	if resp != nil {
		if len(resp.Responses) != 0 {
			fmt.Println("Successful Configuration Updates:")
			for _, response := range resp.Responses {
				fmt.Printf("Request: %s\n   Result: %s\n", response.Request, response.Result)
			}
		}
	}

	if err != nil {
		return err
	}

	return nil
}
