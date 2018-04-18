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

package command

import (
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
)

const (
	// EnrollCmdUsage is the usage text for enroll command
	EnrollCmdUsage = "enroll -u http://user:userpw@serverAddr:serverPort"
	// EnrollCmdShortDesc is the short description for enroll command
	EnrollCmdShortDesc = "Enroll an identity"
	// EnrollCmdLongDesc is the long description for enroll command
	EnrollCmdLongDesc = "Enroll identity with Fabric CA server"
)

// enrollCmd represents enroll command
type enrollCmd struct {
	Command
	idemix bool
}

// NewEnrollCmd returns cobra.Command that represents enroll command
func NewEnrollCmd(c Command) *cobra.Command {
	enrollCmd := &enrollCmd{c, false}
	return enrollCmd.getCommand()
}

// getCommand returns cobra.Command object for enroll command
func (c *enrollCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     EnrollCmdUsage,
		Short:   EnrollCmdShortDesc,
		Long:    EnrollCmdLongDesc,
		PreRunE: c.preRunEnroll,
		RunE:    c.runEnroll,
	}
	cmd.Flags().BoolVar(&c.idemix, "idemix", false, "Get idemix credential")
	return cmd
}

// preRunEnroll is the PreRunE function for enroll cobra command
func (c *enrollCmd) preRunEnroll(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

// runEnroll is the RunE function for enroll cobra command
func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runEnroll")
	cfgFileName := c.GetCfgFileName()
	cfg := c.GetClientCfg()
	cfg.GetEnrollmentRequest().Idemix = c.idemix
	resp, err := cfg.Enroll(cfg.GetURL(), filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file at '%s'", cfgFileName)
	}

	cfgStr := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfgStr), 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write file at '%s'", cfgFileName)
	}

	// Store identity credentials
	err = ID.Store()
	if err != nil {
		return errors.WithMessage(err, "Failed to store enrollment information")
	}

	// Store CA chain
	err = storeCAChain(cfg, &resp.ServerInfo)
	if err != nil {
		return err
	}

	// Store CA idemix public key
	err = storeIssuerPublicKey(cfg, &resp.ServerInfo)
	if err != nil {
		return err
	}

	return nil
}
