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

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initCmd represents the init command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register user",
	Long:  "Register user with fabric-ca server",
}

func init() {
	registerCmd.Run = runRegister
	rootCmd.AddCommand(registerCmd)
	registerFlags := registerCmd.Flags()
	util.FlagString(registerFlags, "regfile", "f", "", "File containing registration info")
}

// The client register main logic
func runRegister(cmd *cobra.Command, args []string) {
	util.CmdRunBegin()
	if len(args) > 0 {
		registerCmd.Help()
		os.Exit(1)
	}

	regFile := viper.GetString("regfile")
	if regFile == "" {
		log.Error("A registeration request file is required to register a user")
		return
	}

	_ = regFile

	log.Infof("User Registered")
}
