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

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// startCmd represents the enroll command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: fmt.Sprintf("Start the %s", shortName),
}

func init() {
	startCmd.Run = runStart
	rootCmd.AddCommand(startCmd)
	flags := startCmd.Flags()
	util.FlagInt(flags, "port", "p", getDefaultListeningPort(),
		"Listening port")
	util.FlagBool(flags, "tls.enabled", "s", false,
		"Enable TLS on the listening port")
	util.FlagString(flags, "tls.key", "", "key.pem",
		"PEM-encoded key file for TLS")
	util.FlagString(flags, "tls.cert", "", "cert.pem",
		"PEM-encoded certificate file for TLS")
}

// The server start main logic
func runStart(cmd *cobra.Command, args []string) {
	util.CmdRunBegin()
	if len(args) > 0 {
		startCmd.Help()
		os.Exit(1)
	}
	log.Infof("Starting the %s", shortName)
	log.Debugf("tls.key: '%s'", viper.GetString("tls.key"))
	log.Debugf("tls.cert: '%s'", viper.GetString("tls.cert"))
	log.Debugf("tls.enabled: %v", viper.GetBool("tls.enabled"))
	log.Infof("Listening on port %v ...", viper.GetInt("port"))
}
