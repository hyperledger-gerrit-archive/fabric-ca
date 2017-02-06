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
var reenrollCmd = &cobra.Command{
	Use:   "reenroll",
	Short: "Reenroll user",
	Long:  "Reenroll user with fabric-ca server",
}

func init() {
	reenrollCmd.Run = runReenroll
	rootCmd.AddCommand(reenrollCmd)
	reenrollFlags := reenrollCmd.PersistentFlags()
	util.FlagString(reenrollFlags, "csrfile", "f", "", "Certificate Signing Request information (Optional)")
}

// The client reenroll main logic
func runReenroll(cmd *cobra.Command, args []string) {
	util.CmdRunBegin()
	if len(args) > 0 {
		reenrollCmd.Help()
		os.Exit(1)
	}

	csrFile := viper.GetString("csrfile")
	_ = csrFile

	log.Infof("User Reenrolled")
}
