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
		Short: "Manage affiliations",
		Long:  "Manage affiliations",
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
		Short: "List affiliations",
		Long:  "List affiliations visible to caller",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: c.runListAffiliation,
	}
	flags := affiliationListCmd.Flags()
	flags.StringVarP(
		&c.dynamicAffiliation.affiliation, "affiliation", "", "", "Get affiliation information from the fabric-ca server")
	return affiliationListCmd
}

func (c *ClientCmd) newAddAffiliationCommand() *cobra.Command {
	affiliationAddCmd := &cobra.Command{
		Use:     "add <affiliation>",
		Short:   "Add affiliation",
		Long:    "Add affiliation",
		PreRunE: c.affiliationPreRunE,
		RunE:    c.runAddAffiliation,
	}
	return affiliationAddCmd
}

func (c *ClientCmd) newModifyAffiliationCommand() *cobra.Command {
	affiliationModifyCmd := &cobra.Command{
		Use:     "modify <affiliation>",
		Short:   "Modify affiliation",
		Long:    "Modify existing affiliation",
		PreRunE: c.affiliationPreRunE,
		RunE:    c.runModifyAffiliation,
	}
	flags := affiliationModifyCmd.Flags()
	flags.StringVarP(
		&c.dynamicAffiliation.modify.Info.Name, "name", "", "", "Rename the affiliation")
	return affiliationModifyCmd
}

func (c *ClientCmd) newRemoveAffiliationCommand() *cobra.Command {
	affiliationRemoveCmd := &cobra.Command{
		Use:     "remove <affiliation>",
		Short:   "Remove affiliation",
		Long:    "Remove affiliation",
		PreRunE: c.affiliationPreRunE,
		RunE:    c.runRemoveAffiliation,
	}
	flags := affiliationRemoveCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicAffiliation.remove, nil)
	return affiliationRemoveCmd
}

// The client side logic for listing affiliation information
func (c *ClientCmd) runListAffiliation(cmd *cobra.Command, args []string) error {
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

		fmt.Printf("%+v\n", resp.AffiliationInfo)
		return nil
	}

	resp, err := id.GetAllAffiliations(c.clientCfg.CAName)
	if err != nil {
		return err
	}

	for _, aff := range resp.Affiliations {
		fmt.Printf("%+v\n", aff)
	}

	return nil
}

// The client side logic for adding an affiliation
func (c *ClientCmd) runAddAffiliation(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runAddAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddAffiliationRequest{}
	req.Name = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.AddAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added affiliation: %+v\n", resp)

	return nil
}

// The client side logic for modifying an affiliation
func (c *ClientCmd) runModifyAffiliation(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runModifyAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ModifyAffiliationRequest{}
	req.Name = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.ModifyAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified affiliation: %+v\n", resp)

	return nil
}

// The client side logic for removing an affiliation
func (c *ClientCmd) runRemoveAffiliation(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runRemoveAffiliation: %+v", c.dynamicAffiliation)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.RemoveAffiliationRequest{}
	req.Name = args[0]
	req.CAName = c.clientCfg.CAName

	resp, err := id.RemoveAffiliation(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified affiliation: %+v\n", resp)

	return nil
}

func (c *ClientCmd) affiliationPreRunE(cmd *cobra.Command, args []string) error {
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
}
