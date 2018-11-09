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
			err := password.Validate("T3st1ng!")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("password generation", func() {
		AfterEach(func() {
			os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
		})

		Context("when generating a password", func() {
			It("passes all requirements validation", func() {
				pass := password.Generate()
				err := password.Validate(pass)
				Expect(err).NotTo(HaveOccurred())
			})

			It("generates a password of requested length", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "15")
				pass, err := password.GenerateUsingEnvVar()
				Expect(err).NotTo(HaveOccurred())

				Expect(len(pass)).To(Equal(15))
			})
		})

		Context("when generating a password using a bad environment variabel", func() {
			It("throws an error", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "15s")
				_, err := password.GenerateUsingEnvVar()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("password validation with no environment variables defined", func() {
		Context("when a password is using default requirements", func() {
			It("fails to pass validation if missing uppercase letter", func() {
				err := password.Validate("t3st1ng!")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet uppercase letter requirement"))
			})

			It("fails to pass validation if missing lowercase letter", func() {
				err := password.Validate("T3ST1NG!")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet lowercase letter requirement"))
			})

			It("fails to pass validation if missing number", func() {
				err := password.Validate("TeSTiNG!")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed requirement to contain both numbers and letters"))
			})

			It("fails to pass validation if missing special character", func() {
				err := password.Validate("T3STiNGG")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet special character requirement"))
			})

			It("fails to pass validation if length is less than 8", func() {
				err := password.Validate("T3sT!NG")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password failed to meet length requirement"))
			})

			It("fails to pass validation if using a forbidden character", func() {
				err := password.Validate("T3ST1NG\\")
				Expect(err.Error()).To(ContainSubstring("Password contains the following forbidden character(s): \\"))
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
				err := password.Validate("t3st1ng!")
				Expect(err).NotTo(HaveOccurred())
			})

			It("passes validation if missing lowercase letter", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER", "false")
				err := password.Validate("T3ST1NG!")
				Expect(err).NotTo(HaveOccurred())
			})

			It("fails to pass validation if missing letters", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER", "false")
				err := password.Validate("!1234567!")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to disable number requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM")
			})

			It("fails to pass validation if missing number", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM", "false")
				err := password.Validate("TeSTiNG!")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to change number of special char requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS")
			})

			It("fails to pass validation if missing required number of special chars", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS", "4")
				err := password.Validate("!@T3STiNG$!")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when a password is using environment variable to set forbidden characters", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_FORBIDDEN_CHARS")
			})

			It("fails to pass validation if using a custom forbidden character", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_FORBIDDEN_CHARS", "!")
				err := password.Validate("T3sT!NG$")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Password contains the following forbidden character(s): !"))
			})
		})

		Context("when a password is using environment variable to length requirement", func() {
			AfterEach(func() {
				os.Unsetenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
			})

			It("fails to pass validation if password is too short", func() {
				os.Setenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", "5")
				err := password.Validate("!T3sT")
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

				err := password.Validate("TE$T!")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
