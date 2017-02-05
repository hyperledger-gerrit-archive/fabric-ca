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
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

// InitConfig is the part of the config needed by init
type InitConfig struct {
	CSR csr.CertificateRequest `json:"csr,omitempty"`
}

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: fmt.Sprintf("Initialize the %s", shortName),
	Long:  "Generate the key material needed by the server if it doesn't already exist",
}

func init() {
	initCmd.Run = runInit
	rootCmd.AddCommand(initCmd)
	flags := initCmd.Flags()
	registerCommonFlags(flags)
}

// The server init main logic
func runInit(cmd *cobra.Command, args []string) {
	util.CmdRunBegin()
	if len(args) > 0 {
		initCmd.Help()
		os.Exit(1)
	}
	server := lib.Server{
		HomeDir: filepath.Dir(cfgFileName),
		Config:  serverCfg,
	}
	err := server.Init(false)
	if err != nil {
		util.Fatal("Initialization failure: %s", err)
	}
	log.Info("Initialization was successful")
}
