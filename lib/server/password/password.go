/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
)

const (
	characters    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$&*()-_=+,.;~"
	validateError = "Password fails requirements, make sure that password provided meets following requirments:\n  At least 8 characters—the more characters, the better\n  A mixture of both uppercase and lowercase letters\n  A mixture of letters and numbers\n  Includes at least one special character, e.g., ! @ # ? ]"
)

// Password defines that requirements for a valid password
type Password struct {
	pass               string
	meetUpperLowerrReq bool
	meetNumReq         bool
	meetSpecialReq     bool
	meetLenReq         bool
}

// New creates a new Password
func New(password string) *Password {
	return &Password{
		pass: password,
	}
}

// Validate validates that the password meets all requirements
func (p *Password) Validate() error {
	if p.containsForbiddenChars() {
		return errors.New("Password contains one of the following forbidden characters: #,?,%,\\,/,:,{,},[,]")
	}
	if p.meetsUpperLowerReq() && p.meetsNumberReq() && p.meetsSpecialCharReq() && p.meetsLengthReq() {
		return nil
	}
	return errors.New(validateError)
}

func (p *Password) meetsUpperLowerReq() bool {
	if !performCheck("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER") {
		return true
	}

	matchUpper := regexp.MustCompile(`[A-Z]`)
	meetsUpperReq := matchUpper.MatchString(p.pass)

	matchLower := regexp.MustCompile(`[a-z]`)
	meetsLowerReq := matchLower.MatchString(p.pass)

	if meetsUpperReq && meetsLowerReq {
		return true
	}

	log.Debug("Password failed lowercase/uppercase requirement")
	return false
}

func (p *Password) meetsNumberReq() bool {
	if !performCheck("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM") {
		return true
	}
	matchNumber := regexp.MustCompile(`[0-9]`)
	if matchNumber.MatchString(p.pass) {
		return true
	}
	log.Debug("Password failed number requirement")
	return false
}

func (p *Password) meetsSpecialCharReq() bool {
	minCharEnv := os.Getenv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS")
	minChar, err := strconv.Atoi(minCharEnv)
	if err != nil {
		minChar = 1
	}

	matchSpecial := regexp.MustCompile(`[\!\@\$\&\*\(\)\-_\=\+\,\.\;~]`)
	matches := matchSpecial.FindAllStringIndex(p.pass, -1)
	if len(matches) >= minChar {
		return true
	}
	log.Debug("Password failed minimum number of special characters requirement")
	return false
}

func (p *Password) meetsLengthReq() bool {
	minLenEnv := os.Getenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
	minLen, err := strconv.Atoi(minLenEnv)
	if err != nil {
		minLen = 8
	}
	if len(p.pass) >= minLen {
		return true
	}
	log.Debug("Password failed length requirement")
	return false
}

// These characters cause problems in the enrollment URL
func (p *Password) containsForbiddenChars() bool {
	forbiddenChars := regexp.MustCompile(`[\#\?\%\^\\\/\:\{\}\[\]]`)
	if forbiddenChars.MatchString(p.pass) {
		return true
	}
	return false
}

// Generate generates a password that meets requirements
func Generate() string {
	lenEnv := os.Getenv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH")
	length, err := strconv.Atoi(lenEnv)
	if err != nil {
		length = 12
	}
	for {
		passwordBuffer := new(bytes.Buffer)

		for j := 0; j < length; j++ {
			rnd := rand.Intn(len(characters))
			char := characters[rnd]
			passwordBuffer.WriteString(string(char))
		}

		err := New(passwordBuffer.String()).Validate()
		if err == nil {
			return passwordBuffer.String()
		}
	}
}

func performCheck(envVar string) bool {
	val := os.Getenv(envVar)
	if val != "" {
		if strings.ToLower(val) == "true" {
			return true
		}
		return false
	}
	return true
}
