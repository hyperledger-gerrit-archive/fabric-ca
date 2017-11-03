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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type identityArgs struct {
	getID     string
	getAllIDs bool
	json      string
	add       api.AddIdentityRequest
	modify    api.ModifyIdentityRequest
	remove    api.RemoveIdentityRequest
}

func (c *ClientCmd) newIdentityCommand() *cobra.Command {
	identityCmd := &cobra.Command{
		Use:   "identity",
		Short: "Dynamically update identity",
		Long:  "Dynamically update an identity on Fabric CA server",
		// PreRunE block for this command will check to make sure enrollment
		// information exists before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityCmd.Flags()
	flags.StringVarP(
		&c.dynamicIdentity.getID, "getid", "", "", "Get identity information from the fabric-ca server")
	flags.BoolVarP(
		&c.dynamicIdentity.getAllIDs, "getallids", "", false, "Get all identities that the caller is authorized to view")
	identityCmd.AddCommand(c.newAddIdentityCommand())
	identityCmd.AddCommand(c.newModifyIdentityCommand())
	identityCmd.AddCommand(c.newRemoveIdentityCommand())
	return identityCmd
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	identityAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add identity",
		Long:  "Add an identity on Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runAddIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityAddCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.add.RegistrationRequest, nil)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for adding a new identity")
	return identityAddCmd
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	identityModifyCmd := &cobra.Command{
		Use:   "modify",
		Short: "Modify identity",
		Long:  "Modify an existing identity on Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runModifyIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityModifyCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.modify.RegistrationRequest, nil)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for modifying an existing identity")
	return identityModifyCmd
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	identityRemoveCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove identity",
		Long:  "Remove an identity from Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runRemoveIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityRemoveCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.remove, nil)
	return identityRemoveCmd
}

// The client side logic for executing identity command
func (c *ClientCmd) runIdentity() error {
	log.Debugf("Entered runIdentity: %+v", c.dynamicIdentity)

	if c.dynamicIdentity.getAllIDs && c.dynamicIdentity.getID != "" {
		return errors.Errorf("Both 'getallids' and 'getid' flags can't be set at the same time")
	}

	if !c.dynamicIdentity.getAllIDs && c.dynamicIdentity.getID == "" {
		return errors.Errorf("No flags or sub-command specified")
	}

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.getAllIDs {
		resp, err := id.GetAllIdentities(c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Println("Identities:")
		for _, id := range resp.Identities {
			fmt.Printf("%+v\n", id)
		}

		return nil
	}

	resp, err := id.GetIdentity(c.dynamicIdentity.getID, c.clientCfg.CAName)
	if err != nil {
		return err
	}

	fmt.Printf("Identity: %+v\n", resp.IdentityInfo)

	return nil
}

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity() error {
	log.Debugf("Entered runAddIdentity: %+v", c.dynamicIdentity)

	if c.dynamicIdentity.json != "" && c.dynamicIdentity.add.RegistrationRequest.Name != "" {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddIdentityRequest{}

	if c.dynamicIdentity.json != "" {
		newIdentity := api.RegistrationRequest{}
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), &newIdentity, "addIdentity")
		if err != nil {
			return errors.Wrap(err, "Unmarshalling failed")
		}
		req.RegistrationRequest = newIdentity
	} else {
		req.RegistrationRequest = c.dynamicIdentity.add.RegistrationRequest
		req.RegistrationRequest.Attributes = c.clientCfg.ID.Attributes
	}

	req.CAName = c.clientCfg.CAName
	resp, err := id.AddIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added identity: %+v", resp)

	return nil
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity() error {
	log.Debugf("Entered runModifyIdentity: %+v", c.dynamicIdentity)

	if c.dynamicIdentity.json != "" && c.dynamicIdentity.modify.RegistrationRequest.Name != "" {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ModifyIdentityRequest{}

	if c.dynamicIdentity.json != "" {
		modifyIdentity := &api.RegistrationRequest{}
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), modifyIdentity, "modifyIdentity")
		if err != nil {
			return errors.Wrap(err, "Unmarshalling failed")
		}
		req.RegistrationRequest = *modifyIdentity
	} else {
		req.RegistrationRequest = c.dynamicIdentity.modify.RegistrationRequest
		req.RegistrationRequest.Attributes = c.clientCfg.ID.Attributes
	}

	req.CAName = c.clientCfg.CAName
	resp, err := id.ModifyIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified identity: %+v", resp)

	return nil
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity() error {
	log.Debugf("Entered runRemoveIdentity: %+v", c.dynamicIdentity)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &c.dynamicIdentity.remove

	req.CAName = c.clientCfg.CAName
	resp, err := id.RemoveIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed identity: %+v", resp)

	return nil
}
