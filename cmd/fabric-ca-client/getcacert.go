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
	"path"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

func newGetCACertCommand(c *ClientCmd) *cobra.Command {
	getCACertCmd := &cobra.Command{
		Use:   "getcacert -u http://serverAddr:serverPort -M <MSP-directory>",
		Short: "Get CA certificate chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("Unrecognized arguments found: %v\n%s", args, cmd.UsageString())
			}
			err := runGetCACert(c)
			if err != nil {
				return err
			}
			return nil
		},
	}
	return getCACertCmd
}

// The client "getcacert" main logic
func runGetCACert(c *ClientCmd) error {
	log.Debug("GetCACert entered")
	log.Debugf("c.clientCfg: %v\n", c.clientCfg)
	client := &lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	req := &api.GetCAInfoRequest{
		CAName: c.clientCfg.CAInfo.CAName,
	}

	si, err := client.GetCAInfo(req)
	if err != nil {
		return err
	}

	return storeCAChain(client.Config, si)
}

// Store the CAChain in the CACerts folder of MSP (Membership Service Provider)
func storeCAChain(config *lib.ClientConfig, si *lib.GetServerInfoResponse) error {
	mspDir := config.MSPDir
	log.Debugf("MSPDir:%s\n", mspDir)
	if !util.FileExists(mspDir) {
		return fmt.Errorf("Directory does not exist: %s", mspDir)
	}
	caCertsDir := path.Join(mspDir, "cacerts")
	err := os.MkdirAll(caCertsDir, 0755)
	if err != nil {
		return fmt.Errorf("Failed creating CA certificates directory: %s", err)
	}
	fname := strings.Replace(si.CAName, ".", "-", -1) + ".pem"
	path := path.Join(caCertsDir, fname)
	err = util.WriteFile(path, si.CAChain, 0644)
	if err != nil {
		return fmt.Errorf("Failed to create CA root file: %s", err)
	}
	log.Infof("Stored CA certificate chain at %s", path)
	return nil
}
