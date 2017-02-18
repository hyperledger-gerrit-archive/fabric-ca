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
	"path"
	"path/filepath"

	"github.com/hyperledger/fabric-ca/lib"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

// LoadClient loads client configuration file
func loadClient(loadIdentity bool, configFile string) (*lib.Client, *lib.Identity, error) {
	if configFile == "" {
		configFile = path.Join(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")), "client-config.json")
	}
	log.Infof("Fabric-ca Client Configuration File: %s", configFile)

	client, err := lib.NewClient(configFile)
	if err != nil {
		return nil, nil, err
	}

	if loadIdentity {
		id, err2 := client.LoadMyIdentity()
		if err != nil {
			return nil, nil, err2
		}
		return client, id, nil
	}

	return client, nil, err
}
