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

package server

import (
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/hyperledger/fabric-cop/util"
)

// bccspBackedSigner determines whether a file-backed local signer is supported.
func bccspBackedSigner(root *universal.Root, policy *config.Signing) (signer.Signer, bool, error) {
	skiFile := root.Config["key-file"]
	caFile := root.Config["cert-file"]

	if skiFile == "" {
		return nil, false, nil
	}

	if caFile == "" {
		return nil, false, nil
	}

	log.Debugf("Loading CA [%s] for SKI [%s] ", caFile, skiFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, false, err
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, false, err
	}

	caPrivateKey, err := util.GetSignerFromSKIFile(skiFile, CFG.csp)
	if err != nil {
		log.Debug("Failed to load %s: %s", skiFile, err)
		return nil, false, err
	}

	signer, err := local.NewSigner(caPrivateKey, parsedCa, signer.DefaultSigAlgo(caPrivateKey), policy)
	return signer, true, err
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func ocspSignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	key, err := util.GetSignerFromSKIFile(k, CFG.csp)
	if err != nil {
		return nil, err
	}

	return ocsp.NewSignerFromFileAndKey(c.CAFile, c.ResponderFile, key, time.Duration(c.Interval))
}
