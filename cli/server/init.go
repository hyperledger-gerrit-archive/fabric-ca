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
	"encoding/json"
	"errors"
	"io/ioutil"
	"path"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric/bccsp/factory"
)

var initUsageText = `fabric-ca server init CSRJSON -- generates a new private key and self-signed certificate
Usage:
        fabric-ca server init CSRJSON [ENROLLMENT-ID ENROLLMENT-SECRET ROOT-URL]
Arguments:
        CSRJSON:           JSON file containing the request
        ENROLLMENT-ID:     The enrollment ID to initialize an intermediate fabric-ca server
        ENROLLMENT-SECRET: The enrollment secret to initialize an intermediate fabric-ca server
        ROOT-URL:          The URL of the root/parent fabric-ca server
Flags:
`

var initFlags = []string{"u"}

// initMain creates the private key and self-signed certificate needed to start fabric-ca Server
func initMain(args []string, c cli.Config) (err error) {
	csrFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	csrFileBytes, err := cli.ReadStdin(csrFile)
	if err != nil {
		return err
	}

	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return err
	}

	bccsp, err := factory.GetDefault()
	if err != nil {
		return err
	}
	_ = bccsp
	//FIXME: replace the key generation and storage with BCCSP

	c.IsCA = true

	var key, cert []byte

	if len(args) == 0 {
		// Root CA initialization
		cert, _, key, err = initca.New(&req)
		if err != nil {
			return errors.New(err.Error())
		}
	} else {
		// Intermediate CA initialization uses additional arguments
		var args2 []string
		enrollmentID, args2, err2 := cli.PopFirstArgument(args)
		if err2 != nil {
			return err2
		}
		enrollmentSecret, args2, err2 := cli.PopFirstArgument(args2)
		if err2 != nil {
			return err2
		}
		serverURL, _, err2 := cli.PopFirstArgument(args2)
		if err2 != nil {
			return err2
		}
		client, err2 := lib.NewClient("")
		if err2 != nil {
			return err2
		}
		client.ServerURL = serverURL
		// Create an enrollment request with the
		ereq := &api.EnrollmentRequest{
			Name:   enrollmentID,
			Secret: enrollmentSecret,
			CSR: &api.CSRInfo{
				CA: &csr.CAConfig{PathLength: 0, PathLenZero: true},
			},
		}
		id, err2 := client.Enroll(ereq)
		if err2 != nil {
			return err2
		}
		ecert := id.GetECert()
		cert = ecert.Cert
		key = ecert.Key
	}

	s := new(Server)
	FCAHome, err := s.CreateHome()
	if err != nil {
		return errors.New(err.Error())
	}
	certerr := ioutil.WriteFile(path.Join(FCAHome, "server-cert.pem"), cert, 0755)
	if certerr != nil {
		log.Fatal("Error writing server-cert.pem to fabric-ca home directory")
	}
	keyerr := ioutil.WriteFile(path.Join(FCAHome, "server-key.pem"), key, 0755)
	if keyerr != nil {
		log.Fatal("Error writing server-key.pem to fabric-ca home directory")
	}

	return nil
}

// InitServerCommand assembles the definition of Command 'genkey -initca CSRJSON'
var InitServerCommand = &cli.Command{UsageText: initUsageText, Flags: initFlags, Main: initMain}
