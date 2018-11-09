/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/pkg/errors"
)

// Validate validates that the password meets all requirements
func Validate(pass string) error {
	err := validate(pass)
	if err != nil {
		return caerrors.NewHTTPErr(400, caerrors.ErrPasswordReq, "Password validation failed: %s", err)
	}
	return nil
}

func validate(pass string) error {
	var err error
	err = containsForbiddenChars(pass)
	if err != nil {
		return err
	}
	err = meetsUpperLowerReq(pass)
	if err != nil {
		return err
	}
	err = meetsNumberReq(pass)
	if err != nil {
		return err
	}
	err = meetsSpecialCharReq(pass)
	if err != nil {
		return err
	}
	err = meetsLengthReq(pass)
	if err != nil {
		return err
	}
	return nil
}

func meetsUpperLowerReq(pass string) error {
	if !checkBoolEnv("FABRIC_CA_SERVER_PASSWORD_MIX_UPPER_LOWER") {
		return nil
	}

	matchUpper := regexp.MustCompile(`[A-Z]`)
	meetsUpperReq := matchUpper.MatchString(pass)

	if !meetsUpperReq {
		log.Debug("Password failed uppercase requirement")
		return errors.New("Password failed to meet uppercase letter requirement")
	}

	matchLower := regexp.MustCompile(`[a-z]`)
	meetsLowerReq := matchLower.MatchString(pass)

	if !meetsLowerReq {
		log.Debug("Password failed lowercase requirement")
		return errors.New("Password failed to meet lowercase letter requirement")
	}

	return nil
}

func meetsNumberReq(pass string) error {
	if !checkBoolEnv("FABRIC_CA_SERVER_PASSWORD_MIX_ALPHA_NUM") {
		return nil
	}

	matchNumber := regexp.MustCompile(`(.*[a-zA-Z])(.*[0-9])|(.*[0-9])(.*[a-zA-Z])`)
	if matchNumber.MatchString(pass) {
		return nil
	}

	log.Debug("Password failed requirement to contain both numbers and letters")
	return errors.New("Password failed requirement to contain both numbers and letters")
}

func meetsSpecialCharReq(pass string) error {
	minChar, err := checkNumEnv("FABRIC_CA_SERVER_PASSWORD_MIN_SPECIAL_CHARS", 1)
	if err != nil {
		return err
	}

	matchSpecial := regexp.MustCompile(`[\!\@\$\&\*\(\)\-_\=\+\,\.\;~]`)
	matches := matchSpecial.FindAllString(pass, -1)
	if len(matches) >= minChar {
		return nil
	}

	log.Debug("Password failed minimum number of special characters requirement")
	return errors.Errorf("Password failed to meet special character requirement of %d, only found these special characters: %s", minChar, strings.Join(matches, ","))
}

func meetsLengthReq(pass string) error {
	minLen, err := checkNumEnv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", 8)
	if err != nil {
		return err
	}

	if len(pass) >= minLen {
		return nil
	}

	log.Debug("Password failed length requirement")
	return errors.New("Password failed to meet length requirement")
}

// These characters cause problems in the enrollment URL
// Characters such '#' and '?' cause issues as passwor characters in the url.
// These must always be forbidden. Other characters can be forbidden by
// setting the environment variable 'FABRIC_CA_SERVER_PASSWORD_FORBIDDEN_CHARS'.
func containsForbiddenChars(pass string) error {
	forbiddenCharsList := "#,?,%,^,/,:,{,},[,\\,]"

	val := os.Getenv("FABRIC_CA_SERVER_PASSWORD_FORBIDDEN_CHARS")
	var regExpStr string
	if val != "" {
		forbiddenCharsList = val + "," + forbiddenCharsList
		regExpStr = generateForbiddenCharRegExp(forbiddenCharsList)
	} else {
		regExpStr = generateForbiddenCharRegExp(forbiddenCharsList)
	}

	forbiddenChars, err := regexp.Compile(regExpStr)
	if err != nil {
		return err
	}
	matches := forbiddenChars.FindAllString(pass, -1)
	if len(matches) > 0 {
		return errors.Errorf("Password contains the following forbidden character(s): %s", strings.Join(matches, ","))
	}

	return nil
}

func generateForbiddenCharRegExp(chars string) string {
	fCharsBuffer := new(bytes.Buffer)
	fCharsBuffer.WriteString("[")

	fChars := strings.Split(chars, ",")
	for j := 0; j < len(fChars); j++ {
		c := strings.TrimSpace(fChars[j])
		o := fmt.Sprintf("\\\\%s", c)
		fCharsBuffer.WriteString(o)
	}

	fCharsBuffer.WriteString("]")
	return fCharsBuffer.String()
}

func checkBoolEnv(envVar string) bool {
	val := os.Getenv(envVar)

	if val != "" {
		if strings.ToLower(val) == "true" {
			return true
		}
		return false
	}

	return true
}

func checkNumEnv(envVar string, defaultVal int) (int, error) {
	val := os.Getenv(envVar)
	if val == "" {
		return defaultVal, nil
	}

	minChar, err := strconv.Atoi(val)
	if err != nil {
		return 0, errors.Wrapf(err, "Failed to parse environment variable '%s'", envVar)
	}

	return minChar, nil
}
