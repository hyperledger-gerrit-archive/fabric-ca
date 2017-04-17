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
	"log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
)

// TestClient represents an application using the fabric-ca client
type TestClient struct {
	FabClient *lib.Client
	Identity  *lib.Identity
	numTests  int
	numErrors int
}

func (c *TestClient) runTests() {
	iter := 0
	for {
		it := getIdentityType(iter)
		iter++
		eid, err := genEnrollmentID(it)
		if err != nil {
			log.Printf("Failed to get enrollment ID: %v", err)
			continue
		}
		c.runTestSuite(eid)
		if c.numTests >= testCfg.NumReqsPerUser {
			log.Printf("Exiting client with %d errors, after running %d tests, ", c.numErrors, c.numTests)
			break
		}
	}
}

func (c *TestClient) runTestSuite(eid *EnrollmentID) {
	var enrRes lib.EnrollmentResponse
suite:
	for _, test := range testCfg.TestSeq {
		i := 0
		for {
			err := c.runTest(test, eid, &enrRes)
			if err != nil {
				c.numErrors++
				break suite
			}
			c.numTests++
			if test.Repeat <= 0 || i == test.Repeat {
				break
			}
			i++
		}
	}
}

func (c *TestClient) runTest(test Test, eid *EnrollmentID, enrRes *lib.EnrollmentResponse) (err error) {
	switch test.Name {
	case "enroll":
		_, err = c.enrollOnly(test.Req)
		if err != nil {
			log.Printf("Failed to enroll identity %s: %v", *eid.ID, err)
		}
	case "register":
		_, err = c.register(eid, getAffiliation())
		if err != nil {
			log.Printf("Failed to register identity %s: %v", *eid.ID, err)
		}
	case "re-enroll":
		err = c.reenroll(enrRes.Identity)
		if err != nil {
			log.Printf("Failed to reenroll identity %s: %v", *eid.ID, err)
		}
	case "get-tcerts":
		err = c.getTCerts(test.Req, enrRes.Identity)
		if err != nil {
			log.Printf("Failed to get TCert batch for identity %s: %v", *eid.ID, err)
		}
	case "revoke":
		err = c.revoke(test.Req, enrRes.Identity, "")
		if err != nil {
			log.Printf("Failed to revoke identity %s: %v", *eid.ID, err)
		}
	case "get-cacert":
		err = c.getCACert()
		if err != nil {
			log.Printf("Failed to get CA certificate: %v", err)
		}
	default:
		var r *lib.EnrollmentResponse
		r, err = c.registerAndEnroll(eid, getAffiliation())
		if err != nil {
			log.Printf("Failed to enroll identity %s: %v", *eid.ID, err)
		} else {
			*enrRes = *r
		}
	}
	return
}

// Registers the specified identity
func (c *TestClient) register(eid *EnrollmentID, afl string) (resp *api.RegistrationResponse, err error) {
	regReq := api.RegistrationRequest{
		Name:           *eid.ID,
		Type:           string(*eid.it),
		Affiliation:    afl,
		MaxEnrollments: 2,
	}
	resp, err = c.Identity.Register(&regReq)
	if err != nil {
		return
	}
	log.Printf("Successfully registered identity %s: %+v", *eid.ID, resp)
	return
}

// Enrolls the specified identity
func (c *TestClient) enrollOnly(req interface{}) (enrRes *lib.EnrollmentResponse, err error) {
	csr := c.FabClient.Config.CSR
	enrollReq := req.(api.EnrollmentRequest)
	if enrollReq.CSR == nil {
		csr.CN = enrollReq.Name
		enrollReq.CSR = &csr
	}
	enrRes, err = c.FabClient.Enroll(&enrollReq)
	if enrRes != nil {
		log.Printf("Successfully enrolled identity: %s", enrollReq.Name)
	}
	return
}

// Enrolls the specified identity
func (c *TestClient) enroll(eid *EnrollmentID, pass string) (enrRes *lib.EnrollmentResponse, err error) {
	csr := c.FabClient.Config.CSR
	csr.CN = *eid.ID
	enrollReq := api.EnrollmentRequest{
		Name:   *eid.ID,
		Secret: pass,
		CSR:    &csr,
	}
	enrRes, err = c.FabClient.Enroll(&enrollReq)
	if enrRes != nil {
		log.Printf("Successfully enrolled identity: %s", *eid.ID)
	}
	return
}

func (c *TestClient) registerAndEnroll(eid *EnrollmentID, afl string) (enrRes *lib.EnrollmentResponse, err error) {
	var regRes *api.RegistrationResponse
	regRes, err = c.register(eid, afl)
	if regRes != nil {
		enrRes, err = c.enroll(eid, regRes.Secret)
		if err == nil {
			log.Printf("Successfully registered and enrolled identity: %s", *eid.ID)
		}
	}
	return
}

// Returns TCert batch for the specified identity
func (c *TestClient) getTCerts(req interface{}, id *lib.Identity) error {
	log.Printf("req=%+v", req)
	tcertReq := req.(api.GetTCertBatchRequest)
	tcertReq.PreKey = id.GetName()
	_, err := id.GetTCertBatch(&tcertReq)
	if err == nil {
		log.Printf("Successfully retrieved TCert batch %d for the idenity: %s",
			tcertReq.Count, id.GetName())
	}
	return err
}

// Re-enrolls the specified identity
func (c *TestClient) reenroll(id *lib.Identity) error {
	csr := c.FabClient.Config.CSR
	enrRes, err := id.Reenroll(&api.ReenrollmentRequest{
		CSR: &csr,
	})
	if enrRes != nil {
		log.Printf("Successfully re-enrolled identity: %s", id.GetName())
	}
	return err
}

// Revokes the specified identity
func (c *TestClient) revoke(req interface{}, id *lib.Identity, reason string) (err error) {
	if c.Identity == nil {
		c.Identity, err = c.FabClient.LoadMyIdentity()
		if err != nil {
			return
		}
	}

	revokeReq := req.(api.RevocationRequest)
	if reason != "" {
		revokeReq.Reason = reason
	}
	var serial, aki, msg string
	serial, aki, err = lib.GetCertID(id.GetECert().Cert())
	if revokeReq.Name != "" {
		revokeReq.Name = id.GetName()
		msg = fmt.Sprintf("Successfully revoked Identity: %s", id.GetName())
	} else {
		if err != nil {
			return
		}
		msg = fmt.Sprintf("Successfully revoked ECert %s of Identity: %s", aki, id.GetName())
		revokeReq.AKI = aki
		revokeReq.Serial = serial
	}
	err = c.Identity.Revoke(&revokeReq)
	if err == nil {
		log.Printf(msg)
	}
	return
}

// Gets CA root of the fabric-ca-server
func (c *TestClient) getCACert() error {
	req := api.GetCAInfoRequest{
		CAName: "admin",
	}
	_, err := c.FabClient.GetCAInfo(&req)
	if err != nil {
		return err
	}
	log.Println("Successfully retrieved CA certificate")
	return err
}

func getTestClient(configHome *string, cfg *lib.ClientConfig, i *lib.Identity) *TestClient {
	return &TestClient{
		FabClient: &lib.Client{
			HomeDir: *configHome,
			Config:  cfg,
		},
		Identity: i,
	}
}
