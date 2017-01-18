/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package client

import (
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
)

var reenrollUsageText = `fabric-ca client reenroll -- Reenroll with fabric-ca server

Usage of client enroll command:
   fabric-ca client reenroll FABRIC-CA-SERVER-ADDR

Arguments:
        FABRIC-CA-SERVER-ADDR:  Fabric CA server address
		  CSRJSON:                Certificate Signing Request JSON information (Optional)

Flags:
`

var reenrollFlags = []string{}

func reenrollMain(args []string, c cli.Config) error {
	log.Debug("Entering cli/client/reenrollMain")

	fcaServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	client, err := NewClient(fcaServer)
	if err != nil {
		return err
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return fmt.Errorf("Client is not yet enrolled: %s", err)
	}

	req := &api.ReenrollmentRequest{}

	if len(args) > 0 {
		path, _, err2 := cli.PopFirstArgument(args)
		if err2 != nil {
			return err2
		}
		req.CSR, err2 = client.LoadCSRInfo(path)
		if err2 != nil {
			return err2
		}
	}

	newID, err := id.Reenroll(req)
	if err != nil {
		return fmt.Errorf("failed to store enrollment information: %s", err)
	}

	err = newID.Store()
	if err != nil {
		return err
	}

	log.Infof("enrollment information was successfully stored in %s and %s",
		client.GetMyKeyFile(), client.GetMyCertFile())

	return nil
}

// ReenrollCommand is the enroll command
var ReenrollCommand = &cli.Command{UsageText: reenrollUsageText, Flags: reenrollFlags, Main: reenrollMain}
