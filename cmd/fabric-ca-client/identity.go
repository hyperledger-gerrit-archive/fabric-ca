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
	id     string
	json   string
	add    api.AddIdentityRequest
	modify api.ModifyIdentityRequest
	remove api.RemoveIdentityRequest
}

func (c *ClientCmd) newIdentityCommand() *cobra.Command {
	identityCmd := &cobra.Command{
		Use:   "identity",
		Short: "Update an identity",
		Long:  "Dynamically update an identity on Fabric CA server",
	}
	identityCmd.AddCommand(c.newListIdentityCommand())
	identityCmd.AddCommand(c.newAddIdentityCommand())
	identityCmd.AddCommand(c.newModifyIdentityCommand())
	identityCmd.AddCommand(c.newRemoveIdentityCommand())
	return identityCmd
}

func (c *ClientCmd) newListIdentityCommand() *cobra.Command {
	identityListCmd := &cobra.Command{
		Use:   "list",
		Short: "List information an identity or identities",
		Long:  "List information an identity or identities from the Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runListIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityListCmd.Flags()
	flags.StringVarP(
		&c.dynamicIdentity.id, "id", "", "", "Get identity information from the fabric-ca server")
	return identityListCmd
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	identityAddCmd := &cobra.Command{
		Use:     "add",
		Short:   "Add identity",
		Long:    "Add an identity on Fabric CA server",
		Example: "fabric-ca-client identity add <id> [flags]\nfabric-ca-client identity add user1 --type peer",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
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
			if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
				return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
			}

			err := c.runAddIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityAddCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.add.IdentityInfo, nil)
	flags.StringVarP(
		&c.dynamicIdentity.add.Secret, "secret", "", "", "The enrollment secret for the identity being registered")
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for adding a new identity")
	return identityAddCmd
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	identityModifyCmd := &cobra.Command{
		Use:     "modify",
		Short:   "Modify identity",
		Long:    "Modify an existing identity on Fabric CA server",
		Example: "fabric-ca-client identity modify <id> [flags]\nfabric-ca-client identity modify user1 --type peer",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
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
			if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
				return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
			}

			err := c.runModifyIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityModifyCmd.Flags()
	tags := map[string]string{
		"skip.id": "true",
	}
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.modify.IdentityInfo, tags)
	flags.StringVarP(
		&c.dynamicIdentity.modify.Secret, "secret", "", "", "The enrollment secret for the identity being registered")
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for modifying an existing identity")
	return identityModifyCmd
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	identityRemoveCmd := &cobra.Command{
		Use:     "remove",
		Short:   "Remove identity",
		Long:    "Remove an identity from Fabric CA server",
		Example: "fabric-ca-client identity remove <id> [flags]\nfabric-ca-client identity remove user1",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
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
			err := c.runRemoveIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	return identityRemoveCmd
}

// The client side logic for executing list identity command
func (c *ClientCmd) runListIdentity() error {
	log.Debug("Entered runListIdentity")

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.id != "" {
		resp, err := id.GetIdentity(c.dynamicIdentity.id, c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Printf("Identity: %+v\n", resp.IdentityInfo)
		return nil
	}

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

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity(args []string) error {
	log.Debugf("Entered runAddIdentity: %+v", c.dynamicIdentity)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddIdentityRequest{}

	if c.dynamicIdentity.json != "" {
		newIdentity := api.IdentityInfo{}
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), &newIdentity, "addIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
		req.IdentityInfo = newIdentity
	} else {
		req.IdentityInfo = c.dynamicIdentity.add.IdentityInfo
		req.IdentityInfo.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.AddIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added identity: %+v\n", resp)

	return nil
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity(args []string) error {
	log.Debugf("Entered runModifyIdentity: %+v", c.dynamicIdentity)

	req := &api.ModifyIdentityRequest{}

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.json != "" {
		modifyIdentity := &api.IdentityInfo{}
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), modifyIdentity, "modifyIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
		req.IdentityInfo = *modifyIdentity
	} else {
		req.IdentityInfo = c.dynamicIdentity.modify.IdentityInfo
		req.IdentityInfo.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.ModifyIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified identity: %+v\n", resp)

	return nil
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity(args []string) error {
	log.Debugf("Entered runRemoveIdentity: %+v", c.dynamicIdentity)

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	req := &c.dynamicIdentity.remove
	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.RemoveIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed identity: %+v\n", resp)

	return nil
}

// checkOtherFlags returs true if other flags besides '--json' are set
// Viper.IsSet does not work correctly if there are defaults defined for
// flags. This is a workaround until this bug is addressed in Viper.
// Viper Bug: https://github.com/spf13/viper/issues/276
func checkOtherFlags(cmd *cobra.Command) bool {
	checkFlags := []string{"id", "type", "affiliation", "secret", "maxenrollments", "attrs"}
	flags := cmd.Flags()
	for _, checkFlag := range checkFlags {
		flag := flags.Lookup(checkFlag)
		if flag != nil {
			if flag.Changed {
				return true
			}
		}
	}

	return false
}

func argsCheck(args []string) error {
	if len(args) == 0 {
		return errors.Errorf("Identity name is required")
	}
	if len(args) > 1 {
		return errors.Errorf("Too many arguments, only the identity name should be passed in as argument")
	}
	return nil
}
