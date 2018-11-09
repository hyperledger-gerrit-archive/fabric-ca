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

	Context("when a password that meets all requirements is used", func() {
		It("passes all requirements validation", func() {
			err := password.New("T3st1ng!").Validate()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when generating a password", func() {
		It("passes all requirements validation", func() {
			pass := password.Generate()
			err := password.New(pass).Validate()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("password validation with no environment variables defined", func() {
		Context("when a password is using default requirements", func() {
			It("fails to pass validation if missing uppercase letter", func() {
				err := password.New("t3st1ng!").Validate()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password fails requirements, make sure that password provided meets following requirments:\n  At least 8 characters—the more characters, the better\n  A mixture of both uppercase and lowercase letters\n  A mixture of letters and numbers\n  Includes at least one special character, e.g., ! @ # ? ]"))
			})

			It("fails to pass validation if missing lowercase letter", func() {
				err := password.New("T3ST1NG!").Validate()
				Expect(err).To(HaveOccurred())
			})

			It("fails to pass validation if missing number", func() {
				err := password.New("TeSTiNG!").Validate()
				Expect(err).To(HaveOccurred())
			})

			It("fails to pass validation if missing special character", func() {
				err := password.New("T3STiNGG").Validate()
				Expect(err).To(HaveOccurred())
			})

			It("fails to pass validation if length is less than 8", func() {
				err := password.New("T3sT!NG").Validate()
				Expect(err).To(HaveOccurred())
			})

			It("fails to pass validation if using a forbidden character", func() {
				err := password.New("T3ST!NG{").Validate()
				Expect(err.Error()).To(ContainSubstring("Password contains one of the following forbidden characters: #,?,%,\\,/,:,{,},[,]"))
			})
		})
	})

	Describe("password validation with environment variables", func() {
		Context("when a password is using environment variable to disable lowercase/uppercase requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER")
			})

			It("passes validation if missing uppercase letter", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER", "false")
				err := password.New("t3st1ng!").Validate()
				Expect(err).NotTo(HaveOccurred())
			})

			It("fails to pass validation if missing lowercase letter", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER", "false")
				err := password.New("T3ST1NG!").Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to disable number requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM")
			})

			It("fails to pass validation if missing number", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM", "false")
				err := password.New("TeSTiNG!").Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to change number of special char requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS")
			})

			It("fails to pass validation if missing required number of special chars", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS", "4")
				err := password.New("!@T3STiNG$!").Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to length requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
			})

			It("fails to pass validation if password is too short", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "5")
				err := password.New("!T3sT").Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using multiple environment variable to alter password requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER")
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM")
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS")
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
			})

			It("passes validation if password meets requirements", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER", "false")
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS", "2")
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM", "false")
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "5")

				err := password.New("TE$T!").Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
