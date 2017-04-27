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
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ServerCmd encapsulates cobra command that provides command line interface
// for the Fabric CA server and the configuration used by the Fabric CA server
type ServerCmd struct {
	// rootCmd is the cobra command
	rootCmd *cobra.Command
	// blockingStart indicates whether to block after starting the server or not
	blockingStart bool
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// serverCfg is the server's configuration
	serverCfg *lib.ServerConfig
}

// NewCommand returns new ServerCmd ready for running
func NewCommand(blockingStart bool) *ServerCmd {
	s := &ServerCmd{
		blockingStart: blockingStart,
	}
	s.init()
	return s
}

// Execute runs this ServerCmd
func (s *ServerCmd) Execute() error {
	return s.rootCmd.Execute()
}

// init initializes the ServerCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (s *ServerCmd) init() {
	// root command
	rootCmd := &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := configInit(s)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			util.CmdRunBegin()
			return nil
		},
	}
	s.rootCmd = rootCmd

	// initCmd represents the server init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s", shortName),
		Long:  "Generate the key material needed by the server if it doesn't already exist",
	}
	initCmd.RunE = func(cmd *cobra.Command, args []string) error {
		fmt.Printf("args:%v", args)
		if len(args) > 0 {
			return fmt.Errorf("Usage: too many arguments.\n%s", initCmd.UsageString())
		}
		err := s.getServer().Init(false)
		if err != nil {
			util.Fatal("Initialization failure: %s", err)
		}
		log.Info("Initialization was successful")
		return nil
	}
	s.rootCmd.AddCommand(initCmd)

	// startCmd represents the server start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s", shortName),
	}

	startCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("Usage: too many arguments.\n%s", startCmd.UsageString())
		}
		err := s.getServer().Start()
		if err != nil {
			return err
		}
		return nil
	}
	s.rootCmd.AddCommand(startCmd)

	s.registerFlags()
}

// registerFlags registers command flags with viper
func (s *ServerCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	viper.SetEnvPrefix(envVarPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set specific global flags used by all commands
	pflags := s.rootCmd.PersistentFlags()
	pflags.StringVarP(&s.cfgFileName, "config", "c", cfg, "Configuration file")
	util.FlagString(pflags, "url", "u", "", "URL of the parent fabric-ca-server")
	util.FlagString(pflags, "boot", "b", "",
		"The user:pass for bootstrap admin which is required to build default config file")

	// Register flags for all tagged and exported fields in the config
	s.serverCfg = &lib.ServerConfig{}
	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request to a parent fabric-ca-server",
		"help.csr.serialnumber": "The serial number in a certificate signing request to a parent fabric-ca-server",
		"help.csr.hosts":        "A list of space-separated host names in a certificate signing request to a parent fabric-ca-server",
	}
	err := util.RegisterFlags(pflags, s.serverCfg, nil)
	if err != nil {
		panic(err)
	}
	s.serverCfg.CAcfg = lib.CAConfig{}
	err = util.RegisterFlags(pflags, &s.serverCfg.CAcfg, tags)
	if err != nil {
		panic(err)
	}
}

// getServer returns a lib.Server for the init and start commands
func (s *ServerCmd) getServer() *lib.Server {
	return &lib.Server{
		HomeDir:       filepath.Dir(s.cfgFileName),
		Config:        s.serverCfg,
		BlockingStart: s.blockingStart,
		CA: lib.CA{
			Config: &s.serverCfg.CAcfg,
		},
	}
}
