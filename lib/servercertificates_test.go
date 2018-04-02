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
package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetCertificatesTimeInput(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	negativeTimeTestCases(t, admin)
	positiveTimeTestCases(t, admin)
}

func negativeTimeTestCases(t *testing.T, admin *Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "+30m",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for expiration start time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for expiration end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			StartTime: "+30m",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for revocation start time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for revocation end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-IOd",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30.5",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "2018-01-01T00:00:00",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")
}

func positiveTimeTestCases(t *testing.T, admin *Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "+30d",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse correct time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time without the time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01T00:00:00Z",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time")
}

func TestGetCertificatesFilters(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	attributeAuthChecks(t, client, admin)
}

func attributeAuthChecks(t *testing.T, client *Client, admin *Identity) {
	admin2, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "admin2",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register and enroll admin2")

	err = admin2.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.Error(t, err, "Should not be able to get certificates without proper attributes")

	admin3, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "admin3",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "Peer,Client",
			},
		},
	})
	util.FatalError(t, err, "Failed to register and enroll admin3")

	admin4, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "admin4",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Revoker",
				Value: "false",
			},
		},
	})
	util.FatalError(t, err, "Failed to register and enroll admin4")

	admin5, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "admin5",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Revoker",
				Value: "true",
			},
		},
	})
	util.FatalError(t, err, "Failed to register and enroll admin5")

	err = admin2.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.Error(t, err, "Should not be able to get certificates without proper attributes")

	err = admin3.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.NoError(t, err, "Should not have failed, caller has hf.Registrar.Roles attribute")

	err = admin4.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.Error(t, err, "Should not be able to get certificates without proper attributes, hf.Revoker=false")

	err = admin5.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.NoError(t, err, "Should not have failed, caller has hf.Revoker=true")
}
