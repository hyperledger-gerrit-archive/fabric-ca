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
	"os"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ClientCmd encapsulates cobra command that provides command line interface
// for the Fabric CA client and the configuration used by the Fabric CA client
type ClientCmd struct {
	// rootCmd is the base command for the Hyerledger Fabric CA client
	rootCmd *cobra.Command
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// clientCfg is the client's configuration
	clientCfg *lib.ClientConfig
}

// NewCommand returns new ClientCmd ready for running
func NewCommand() *ClientCmd {
	c := &ClientCmd{}
	c.init()
	return c
}

// Execute runs this ClientCmd
func (c *ClientCmd) Execute() error {
	return c.rootCmd.Execute()
}

// init initializes the ClientCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (c *ClientCmd) init() {
	c.rootCmd = &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			util.CmdRunBegin()

			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			return nil
		},
	}
	c.rootCmd.AddCommand(newRegisterCommand(c),
		newEnrollCommand(c),
		newReenrollCommand(c),
		newRevokeCommand(c),
		newGetCACertCommand(c))
	c.registerFlags()
}

// registerFlags registers command flags with viper
func (c *ClientCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	viper.SetEnvPrefix(envVarPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	host, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}

	// Set global flags used by all commands
	pflags := c.rootCmd.PersistentFlags()
	pflags.StringVarP(&c.cfgFileName, "config", "c", cfg, "Configuration file")
	util.FlagString(pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")

	c.clientCfg = &lib.ClientConfig{}
	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request",
		"help.csr.serialnumber": "The serial number in a certificate signing request",
		"help.csr.hosts":        "A list of space-separated host names in a certificate signing request",
	}
	err = util.RegisterFlags(pflags, c.clientCfg, tags)
	if err != nil {
		panic(err)
	}
}
