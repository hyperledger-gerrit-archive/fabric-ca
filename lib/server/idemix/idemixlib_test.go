/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"testing"

	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	fabidemix "github.com/hyperledger/fabric/idemix"
	"github.com/stretchr/testify/mock"
)

func TestIdemixPanic(t *testing.T) {
	var err error

	panicFunc := func(args mock.Arguments) {
		panic("panic occured")
	}

	idemixWrapper := new(mocks.Lib)
	idemixWrapper.On("GetRand").Run(panicFunc)
	idemixWrapper.On("NewCredential", (*fabidemix.IssuerKey)(nil), (*fabidemix.CredRequest)(nil), []*FP256BN.BIG(nil), (*amcl.RAND)(nil)).Run(panicFunc)

	libImpl := idemix.NewLibProvider(idemixWrapper)
	_, err = libImpl.GetRand()
	util.ErrorContains(t, err, "failure: panic occured", "GetRand have caugh panic, and returned an error")

	_, err = libImpl.NewCredential(nil, nil, nil, nil)
	util.ErrorContains(t, err, "failure: panic occured", "NewCredential have caugh panic, and returned an error")
}
