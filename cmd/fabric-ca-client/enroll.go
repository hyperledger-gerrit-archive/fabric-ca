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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	csrFile string
)

// initCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll -u http://user:userpw@serverAddr:serverPort",
	Short: "Enroll user",
	Long:  "Enroll user with fabric-ca server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runEnroll()
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
}

// The client enroll main logic
func runEnroll() error {
	log.Debug("Entered Enroll")

	rawurl := viper.GetString("url")
	ID, err := clientCfg.Enroll(rawurl, filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return err
	}

	cfg := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
	if err != nil {
		return err
	}

	err = ID.Store()
	if err != nil {
		return fmt.Errorf("Failed to store enrollment information: %s", err)
	}

	log.Infof("Enrollment information was successfully stored in %s and %s",
		ID.GetMyKeyFile(), ID.GetMyCertFile())

	return nil
}
