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
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

var registerUsageText = `fabric-ca client register -- Register an ID with fabric-ca server and return an enrollment secret

Usage of client register command:
    Register a client with fabric-ca server:
        fabric-ca client register [-config config] REGISTER-REQUEST-FILE FABRIC-CA-SERVER-ADDR

Arguments:
        RRJSON:                   File contains registration info
        FABRIC-CA-SERVER-ADDR:    Fabric CA server address
Flags:
`

var registerFlags = []string{"config"}

func registerMain(args []string, c cli.Config) error {

	regFile, _, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	buf, err := util.ReadFile(regFile)
	if err != nil {
		return err
	}

	regReq := new(api.RegistrationRequest)
	err = json.Unmarshal(buf, regReq)
	if err != nil {
		return err
	}

	loadMyIdentity := true
	_, id, err := loadClient(loadMyIdentity, configFile)
	if err != nil {
		return err
	}

	resp, err := id.Register(regReq)
	if err != nil {
		return err
	}

	fmt.Printf("Password: %s\n", string(resp.Secret))

	return nil
}

// RegisterCommand is the register command
var RegisterCommand = &cli.Command{UsageText: registerUsageText, Flags: registerFlags, Main: registerMain}
