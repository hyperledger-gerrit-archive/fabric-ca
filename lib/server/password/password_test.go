/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password_test

import (
	"os"

	"github.com/hyperledger/fabric-ca/lib/server/password"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("password", func() {
	var (
		passCfg *password.Config
		pass    *password.Password
	)

	BeforeEach(func() {
		passCfg = password.DefaultConfig()
		passCfg.SkipValidation = false
		pass = password.New(passCfg)
	})

	Context("when a password that meets all requirements is used", func() {
		It("passes all requirements validation", func() {
			err := pass.Validate("T3st1ng!")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("password generation", func() {
		var generatedPassword string

		Context("when generating a password", func() {
			It("passes all requirements validation", func() {
				generatedPassword = pass.Generate()
				err := pass.Validate(generatedPassword)
				Expect(err).NotTo(HaveOccurred())
			})

			It("generates a password of requested length", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "15")
				passCfg.MinLength = 15
				generatedPassword = password.New(passCfg).Generate()
				Expect(len(generatedPassword)).To(Equal(15))
			})
		})
	})

	Describe("password validation", func() {
		Context("when a password is using default configuration", func() {
			It("fails to pass validation if missing uppercase letter", func() {
				err := pass.Validate("t3st1ng!")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet uppercase letter requirement"))
			})

			It("fails to pass validation if missing lowercase letter", func() {
				err := pass.Validate("T3ST1NG!")
				Expect(err).To(HaveOccurred())

				Expect(err.Error()).To(ContainSubstring("Password failed to meet lowercase letter requirement"))
			})

			It("fails to pass validation if missing number", func() {
				err := pass.Validate("TeSTiNG!")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed requirement to contain both numbers and letters"))
			})

			It("fails to pass validation if missing special character", func() {
				err := pass.Validate("T3STiNGG")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet special character requirement"))
			})

			It("fails to pass validation if length is less than 8", func() {
				err := pass.Validate("T3sT!NG")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet length requirement"))
			})
		})

	})

	Describe("password validation with custom configuration", func() {
		Context("when lowercase/uppercase requirement is disabled", func() {
			BeforeEach(func() {
				passCfg.MixUpperLower = false
				pass = password.New(passCfg)
			})

			It("passes validation if missing uppercase letter", func() {
				err := pass.Validate("t3st1ng!")
				Expect(err).NotTo(HaveOccurred())
			})

			It("passes validation if missing lowercase letter", func() {
				err := pass.Validate("T3ST1NG!")
				Expect(err).NotTo(HaveOccurred())
			})

			It("fails to pass validation if missing letters", func() {
				err := pass.Validate("!1234567!")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when number requirement is disabled", func() {
			BeforeEach(func() {
				passCfg.MixAlphaNum = false
				pass = password.New(passCfg)
			})

			It("fails to pass validation if missing number", func() {
				err := pass.Validate("TeSTiNG!")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when number of special char requirement is set to 4 characters", func() {
			BeforeEach(func() {
				passCfg.MinSpecialChars = 4
				pass = password.New(passCfg)
			})

			It("fails to pass validation if missing required number of special chars", func() {
				err := pass.Validate("!@T3STiNG$!")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when length requirement is set to 5", func() {
			BeforeEach(func() {
				passCfg.MinLength = 5
				pass = password.New(passCfg)
			})

			It("fails to pass validation if password is 4 characters", func() {
				err := pass.Validate("!T3sT")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when there are multiple custom password requirement configuration", func() {
			BeforeEach(func() {
				passCfg.MixUpperLower = false
				passCfg.MinSpecialChars = 2
				passCfg.MixAlphaNum = false
				passCfg.MinLength = 5
				pass = password.New(passCfg)
			})

			It("passes validation if password meets requirements", func() {
				err := pass.Validate("TE$T!")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
