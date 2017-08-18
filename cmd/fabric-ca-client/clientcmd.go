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
	"os"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/cmd"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	fabricCAClientProfileMode = "FABRIC_CA_CLIENT_PROFILE_MODE"
	extraArgsError            = "Unrecognized arguments found: %v\n\n%s"
)

const (
	client    = "client"
	enroll    = "enroll"
	reenroll  = "reenroll"
	register  = "register"
	revoke    = "revoke"
	getcacert = "getcacert"
	gencsr    = "gencsr"
)

// ClientCmd encapsulates cobra command that provides command line interface
// for the Fabric CA client and the configuration used by the Fabric CA client
type ClientCmd struct {
	// name of the sub command
	name string
	// rootCmd is the base command for the Hyerledger Fabric CA client
	rootCmd *cobra.Command
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// clientCfg is the client's configuration
	clientCfg *lib.ClientConfig
	// cfgAttrs are the attributes specified via flags or env variables
	// and translated to Attributes field in registration
	cfgAttrs []string
	// cfgCsrNames are the certificate signing request names specified via flags
	// or env variables
	cfgCsrNames []string
	// csrCommonName is the certificate signing request common name specified via the flag
	csrCommonName string
	// profileMode is the profiling mode, cpu or mem or empty
	profileMode string
	// profileInst is the profiling instance object
	profileInst interface {
		Stop()
	}
}

// NewCommand returns new ClientCmd ready for running
func NewCommand(name string) *ClientCmd {
	c := &ClientCmd{}
	c.name = strings.ToLower(name)
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
			err := c.checkAndEnableProfiling()
			if err != nil {
				return err
			}
			util.CmdRunBegin()
			cmd.SilenceUsage = true
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if c.profileMode != "" && c.profileInst != nil {
				c.profileInst.Stop()
			}
			return nil
		},
	}
	c.rootCmd.AddCommand(c.newRegisterCommand(),
		c.newEnrollCommand(),
		c.newReenrollCommand(),
		c.newRevokeCommand(),
		c.newGetCACertCommand(),
		c.newGenCsrCommand())
	c.rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Client version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	})
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
	pflags.StringSliceVarP(
		&c.cfgAttrs, "id.attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	util.FlagString(pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")
	pflags.StringSliceVarP(
		&c.cfgCsrNames, "csr.names", "", nil, "A list of comma-separated CSR names of the form <name>=<value> (e.g. C=CA,O=Org1)")

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

// checkAndEnableProfiling checks for the FABRIC_CA_CLIENT_PROFILE_MODE
// env variable, if it is set to "cpu", cpu profiling is enbled;
// if it is set to "heap", heap profiling is enabled
func (c *ClientCmd) checkAndEnableProfiling() error {
	c.profileMode = strings.ToLower(os.Getenv(fabricCAClientProfileMode))
	if c.profileMode != "" {
		wd, err := os.Getwd()
		if err != nil {
			wd = os.Getenv("HOME")
		}
		opt := profile.ProfilePath(wd)
		switch c.profileMode {
		case "cpu":
			c.profileInst = profile.Start(opt, profile.CPUProfile)
		case "heap":
			c.profileInst = profile.Start(opt, profile.MemProfileRate(2048))
		default:
			msg := fmt.Sprintf("Invalid value for the %s environment variable; found '%s', expecting 'cpu' or 'heap'",
				fabricCAClientProfileMode, c.profileMode)
			return errors.New(msg)
		}
	}
	return nil
}

// Certain client commands can only be executed if enrollment credentials
// are present
func (c *ClientCmd) requiresEnrollment() bool {
	return c.name != enroll && c.name != getcacert && c.name != gencsr
}

// Create default client configuration file only during an enroll command
func (c *ClientCmd) shouldCreateDefaultConfig() bool {
	return c.name == enroll || c.name == gencsr
}

func (c *ClientCmd) requiresUser() bool {
	return c.name != gencsr
}
