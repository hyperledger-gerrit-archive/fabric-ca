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
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	csrFile string
)

// initCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll user",
	Long:  "Enroll user with fabric-ca server",
}

func init() {
	enrollCmd.Run = runEnroll
	rootCmd.AddCommand(enrollCmd)
	enrollFlags := enrollCmd.Flags()
	util.FlagString(enrollFlags, "user", "u", "", "user:pass for user being enrolled")
	enrollFlags.StringVarP(&csrFile, "csrfile", "f", "", "Certificate Signing Request information (Optional)")

}

// The client enroll main logic
func runEnroll(cmd *cobra.Command, args []string) {
	util.CmdRunBegin()
	if len(args) > 0 {
		enrollCmd.Help()
		os.Exit(1)
	}

	up := viper.GetString("user")

	if up == "" {
		util.Fatal("The '-u user:pass' option is required")
	}
	ups := strings.Split(up, ":")
	if len(ups) < 2 {
		util.Fatal("The value '%s' on the command line is missing a colon separator", up)
		return
	}
	if len(ups) > 2 {
		ups = []string{ups[0], strings.Join(ups[1:], ":")}
	}

	req := &api.EnrollmentRequest{
		Name:   ups[0],
		Secret: ups[1],
	}

	_ = req

	log.Infof("User Enrolled")
}
