/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package idemix

import "path/filepath"
import "github.com/hyperledger/fabric-ca/util"

// Config encapsulates Idemix related the configuration options
type Config struct {
	IssuerPublicKeyfile string `def:"IssuerPublicKey" help:"Name of the file that contains marshalled bytes of CA's Idemix public key"`
	IssuerSecretKeyfile string `def:"IssuerSecretKey" help:"Name of the file that contains CA's Idemix secret key"`
	RHPoolSize          int    `def:"100" help:"Specifies revocation handle pool size"`
	NonceExpiration     string `def:"15s" help:"Duration after which a nonce expires"`
	NonceSweepInterval  string `def:"15m" help:"Interval at which expired nonces are deleted"`
}

// InitConfig initializes Idemix configuration
func (c *Config) init(homeDir string) error {
	if c.IssuerPublicKeyfile == "" {
		c.IssuerPublicKeyfile = "IssuerPublicKey"
	} else {
		c.IssuerPublicKeyfile = filepath.Base(c.IssuerPublicKeyfile)
	}
	if c.IssuerSecretKeyfile == "" {
		c.IssuerSecretKeyfile = "msp/keystore/IssuerSecretKey"
	} else {
		c.IssuerSecretKeyfile = filepath.Join("msp/keystore/", filepath.Base(c.IssuerSecretKeyfile))
	}
	if c.RHPoolSize == 0 {
		c.RHPoolSize = DefaultRevocationHandlePoolSize
	}
	if c.NonceExpiration == "" {
		c.NonceExpiration = DefaultNonceExpiration
	}
	if c.NonceSweepInterval == "" {
		c.NonceSweepInterval = DefaultNonceSweepInterval
	}
	fields := []*string{

		&c.IssuerPublicKeyfile,
		&c.IssuerSecretKeyfile,
	}
	err := util.MakeFileNamesAbsolute(fields, homeDir)
	if err != nil {
		return err
	}
	return nil
}
