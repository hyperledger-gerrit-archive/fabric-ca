/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

import (
	"bytes"
	"math/rand"
)

const (
	characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$&*()-_=+,.;~"
)

// GenerateUsingEnvVar generates a password that a password of length specified
// by environment variable (default to 12) that meets all other password requirements
func GenerateUsingEnvVar() (string, error) {
	length, err := checkNumEnv("FABRIC_CA_SERVER_PASSWORD_MIN_LENGTH", 12)
	if err != nil {
		return "", err
	}

	pass := Generate(length)
	return pass, nil
}

// Generate generates a password that takes in an optional length parameters,
// otherwise length defaults to 12. This function returns a password without
// also returning an error type, thus removing the need for error handling by
// caller. Allowing the caller to generate a password when they are not considered
// with reading values in from an environment variable.
func Generate(passLength ...int) string {
	var length int
	if len(passLength) > 0 {
		length = passLength[0]
	} else {
		length = 12
	}

	for {
		passwordBuffer := new(bytes.Buffer)

		for j := 0; j < length; j++ {
			rnd := rand.Intn(len(characters))
			char := characters[rnd]
			passwordBuffer.WriteString(string(char))
		}

		err := Validate(passwordBuffer.String())
		if err == nil {
			return passwordBuffer.String()
		}
	}
}
