/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	infoapi "github.com/hyperledger/fabric-ca/lib/common/info/api"
	"github.com/hyperledger/fabric/idemix"
)

// EnrollmentRequestNet is a request to enroll an identity and get idemix credential
type EnrollmentRequestNet struct {
	*idemix.CredRequest `json:"request"`
	CAName              string `json:"caname"`
}

// EnrollmentResponseNet is the response to the /idemix/credential request
type EnrollmentResponseNet struct {
	EnrollmentResponse `mapstructure:",squash"`
	CAInfo             infoapi.CAInfoResponseNet
}
