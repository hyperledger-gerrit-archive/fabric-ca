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

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

type affiliationArgs struct {
	affiliation string
	add         api.AddAffiliationRequest
	modify      api.ModifyAffiliationRequest
	remove      api.RemoveAffiliationRequest
}

func (c *ClientCmd) newAffiliationCommand() *cobra.Command {
	affiliationCmd := &cobra.Command{
		Use:   "affiliation",
		Short: "Update an affiliation",
		Long:  "Dynamically update an affiliation on Fabric CA server",
	}
	affiliationCmd.AddCommand(c.newListAffiliationCommand())
	affiliationCmd.AddCommand(c.newAddAffiliationCommand())
	affiliationCmd.AddCommand(c.newModifyAffiliationCommand())
	affiliationCmd.AddCommand(c.newRemoveAffiliationCommand())
	return affiliationCmd
}

func (c *ClientCmd) newListAffiliationCommand() *cobra.Command {
	affiliationListCmd := &cobra.Command{
		Use:   "list",
		Short: "List affiliation information",
		Long:  "List affiliation information",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runListAffiliation()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := affiliationListCmd.Flags()
	flags.StringVarP(
		&c.dynamicAffiliation.affiliation, "affiliation", "", "", "Get affiliation information from the fabric-ca server")
	return affiliationListCmd
}

func (c *ClientCmd) newAddAffiliationCommand() *cobra.Command {
	affiliationAddCmd := &cobra.Command{
		Use:   "add <affiliation>",
		Short: "Add affiliation",
		Long:  "Add an affiliation on Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args, "affiliation")
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runAddAffiliation(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	return affiliationAddCmd
}

func (c *ClientCmd) newModifyAffiliationCommand() *cobra.Command {
	affiliationModifyCmd := &cobra.Command{
		Use:   "modify <affiliation>",
		Short: "Modify affiliation",
		Long:  "Modify an existing affiliation on Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args, "affiliation")
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runModifyAffiliation(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := affiliationModifyCmd.Flags()
	flags.StringVarP(
		&c.dynamicAffiliation.modify.Path, "rename", "", "", "Rename the affiliation")
	return affiliationModifyCmd
}

func (c *ClientCmd) newRemoveAffiliationCommand() *cobra.Command {
	affiliationRemoveCmd := &cobra.Command{
		Use:   "remove <affiliation>",
		Short: "Remove affiliation",
		Long:  "Remove an affiliation from Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args, "affiliation")
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runRemoveAffiliation(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := affiliationRemoveCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicAffiliation.remove, nil)
	return affiliationRemoveCmd
}

// The client side logic for listing affiliation information
func (c *ClientCmd) runListAffiliation() error {
	log.Debugf("Entered runListAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicAffiliation.affiliation != "" {
		resp, err := id.GetAffiliation(c.dynamicAffiliation.affiliation, c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Printf("Affiliation: %+v\n", resp.AffiliationInfo)
		return nil
	}

	resp, err := id.GetAllAffiliations(c.clientCfg.CAName)
	if err != nil {
		return err
	}

	fmt.Println("Affiliations:")
	for _, aff := range resp.Affiliations {
		fmt.Printf("%+v\n", aff)
	}

	return nil
}

// The client side logic for adding an affiliation
func (c *ClientCmd) runAddAffiliation(args []string) error {
	log.Debugf("Entered runAddAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddAffiliationRequestNet{}
	req.Path = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.AddAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added affiliation: %+v\n", resp)

	return nil
}

// The client side logic for modifying an affiliation
func (c *ClientCmd) runModifyAffiliation(args []string) error {
	log.Debugf("Entered runModifyAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ModifyAffiliationRequestNet{}
	req.Path = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.ModifyAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified affiliation: %+v\n", resp)

	return nil
}

// The client side logic for removing an affiliation
func (c *ClientCmd) runRemoveAffiliation(args []string) error {
	log.Debugf("Entered runRemoveAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.RemoveAffiliationRequestNet{}
	req.Path = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.RemoveAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified affiliation: %+v\n", resp)

	return nil
}
