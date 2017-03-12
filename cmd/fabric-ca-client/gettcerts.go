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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initCmd represents the init command
var gettcertCmd = &cobra.Command{
	Use:   "gettcerts",
	Short: "get TCerts",
	Long:  "Get a batch of TCerts with fabric-ca server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		err := configInit(cmd.Name())
		if err != nil {
			return err
		}

		log.Debugf("Client configuration settings: %+v", clientCfg)

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runGetTCerts(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(gettcertCmd)
	gettcertFlags := gettcertCmd.Flags()
	util.FlagString(gettcertFlags, "number", "n", "", "Number of TCerts")
}

// The client GetTCert main logic
func runGetTCerts(cmd *cobra.Command) error {
	log.Debug("Entered runGetTCerts")
	num := viper.GetInt("number")

	keyFile := "/root/ca-key.pem"
	certFile := "/root/ca-cert.pem"
	mgr, err := tcert.LoadMgr(keyFile, certFile)
	if err != nil {
		return err
	}
	publicKeySet, publicKeyError := generatePublicKeys(num)
	if publicKeyError != nil {
		return publicKeyError
	}
	duration, durartionParseerror := time.ParseDuration("10h")
	if durartionParseerror != nil {
		return durartionParseerror
	}
	var Attrs = []tcert.Attribute{
		{
			Name:  "SSN",
			Value: "123-456-789",
		},
		{
			Name:  "Income",
			Value: "USD",
		},
	}
	ecert, err := tcert.LoadCert("/root/.fabric-ca-client/cert.pem")
	if err != nil {
		return err
	}
	resp, err := mgr.GetBatch(&tcert.GetBatchRequest{
		PreKey:         "S5i15SgeDdd1pYVmaeA92B30Gq1cY8HHpoMHN5qpEu+ioK0gdUsJP2XI4wK43AQh",
		ValidityPeriod: duration,
		EncryptAttrs:   true,
		Attrs:          Attrs,
		PublicKeys:     publicKeySet,
	}, ecert)
	if err != nil {
		return err
	}
	tcerts := resp.TCerts
	for i := 0; i < num; i++ {
		stri := strconv.Itoa(i)
		ioutil.WriteFile("/root/.fabric-ca-client/tcert-"+stri+".pem", tcerts[i].Cert, 0755)
	}
	return nil
}

func generatePublicKeys(num int) ([][]byte, error) {
	//Generate Key Pair and Crete Map
	var privKey *ecdsa.PrivateKey
	var publicKeyraw []byte
	var pemEncodedPublicKey []byte
	var privKeyError error
	var pemEncodingError error
	var set [][]byte
	for i := 0; i < num; i++ {
		privKey, privKeyError = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if privKeyError != nil {
			return nil, privKeyError
		}

		publicKeyraw, pemEncodingError = x509.MarshalPKIXPublicKey(privKey.Public())
		if pemEncodingError != nil {
			return nil, pemEncodingError
		}
		pemEncodedPublicKey = tcert.ConvertDERToPEM(publicKeyraw, "PUBLIC KEY")
		set = append(set, pemEncodedPublicKey)

		privKeyraw, pemEncodingError := x509.MarshalECPrivateKey(privKey)
		if pemEncodingError != nil {
			return nil, pemEncodingError
		}
		pemEncodedPrivateKey := tcert.ConvertDERToPEM(privKeyraw, "EC PRIVATE KEY")
		stri := strconv.Itoa(i)
		ioutil.WriteFile("/root/.fabric-ca-client/tkey-"+stri+".pem", pemEncodedPrivateKey, 0755)
	}
	log.Infof("TCerts was successfully stored in /root/.fabric-ca-client/")
	return set, nil
}
