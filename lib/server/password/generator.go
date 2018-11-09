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

// Generate generates a password that meets all pankssword requirements
func (p *Password) Generate() string {
	length := p.cfg.MinLength
	for {
		passwordBuffer := new(bytes.Buffer)

		for j := 0; j < length; j++ {
			rnd := rand.Intn(len(characters))
			char := characters[rnd]
			passwordBuffer.WriteString(string(char))
		}

		err := p.Validate(passwordBuffer.String())
		if err == nil {
			return passwordBuffer.String()
		}
	}
}
