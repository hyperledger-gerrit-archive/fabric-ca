/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

import (
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/pkg/errors"
)

// Validate validates that the password meets all requirements
func (p *Password) Validate(pass string) error {
	if p.cfg.SkipValidation {
		return nil
	}
	err := p.validate(pass)
	if err != nil {
		return caerrors.NewHTTPErr(400, caerrors.ErrPasswordReq, "Password validation failed: %s", err)
	}
	return nil
}

func (p *Password) validate(pass string) error {
	var err error
	err = p.meetsUpperLowerReq(pass)
	if err != nil {
		return err
	}
	err = p.meetsNumberAlphaReq(pass)
	if err != nil {
		return err
	}
	err = p.meetsSpecialCharReq(pass)
	if err != nil {
		return err
	}
	err = p.meetsLengthReq(pass)
	if err != nil {
		return err
	}
	return nil
}

func (p *Password) meetsUpperLowerReq(pass string) error {
	if !p.cfg.MixUpperLower {
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

func (p *Password) meetsNumberAlphaReq(pass string) error {
	if !p.cfg.MixAlphaNum {
		return nil
	}

	matchNumber := regexp.MustCompile(`(.*[a-zA-Z])(.*[0-9])|(.*[0-9])(.*[a-zA-Z])`)
	if matchNumber.MatchString(pass) {
		return nil
	}

	log.Debug("Password failed requirement to contain both numbers and letters")
	return errors.New("Password failed requirement to contain both numbers and letters")
}

func (p *Password) meetsSpecialCharReq(pass string) error {
	minChar := p.cfg.MinSpecialChars
	matchSpecial := regexp.MustCompile(`[\!\@\#\$\%\^\&\*\(\\\)\-_\=\+\,\.\?\/\:\;\{\}\[\]~]`)
	matches := matchSpecial.FindAllString(pass, -1)
	if len(matches) >= minChar {
		return nil
	}

	log.Debug("Password failed minimum number of special characters requirement")
	return errors.Errorf("Password failed to meet special character requirement of %d, only found these special characters: %s", minChar, strings.Join(matches, ","))
}

func (p *Password) meetsLengthReq(pass string) error {
	minLen := p.cfg.MinLength
	if len(pass) >= minLen {
		return nil
	}

	log.Debug("Password failed length requirement")
	return errors.New("Password failed to meet length requirement")
}
