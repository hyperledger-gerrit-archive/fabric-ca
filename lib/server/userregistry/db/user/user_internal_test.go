/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package user

//import (
//	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/user/mocks"
//	. "github.com/onsi/ginkgo"
////	. "github.com/onsi/gomega"
//)

//var _ = Describe("user", func() {
//	var (
//		userRecord *UserRecord
//		mockUserDB *mocks.UserDB
//		u          *User
//	)

//	BeforeEach(func() {
//		mockUserDB = &mocks.UserDB{}

//		attributes := `[{"name": "hf.Registrar.Roles", "value": "peer", "ecert": false},{"name": "attr0", "value": "attr0Value", "ecert": false}]`
//		userRecord = &UserRecord{
//			Name:       "testuser",
//			Attributes: attributes,
//		}

//		u = NewDBUser(userRecord, mockUserDB)
//	})

//	Context("resetIncorrectLoginAttempts", func() {
//		// mockUserDB.GetReturns(nil)

//		// err := u.resetIncorrectLoginAttempts()
//		// Expect(err).NotTo(HaveOccurred())
//	})
//})
