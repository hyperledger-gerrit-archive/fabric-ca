/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

type Password struct {
	cfg *Config
}

type Config struct {
	SkipValidation  bool
	MixUpperLower   bool
	MixAlphaNum     bool
	MinSpecialChars int
	MinLength       int
}

// New creates a new password object
func New(cfg *Config) *Password {
	return &Password{
		cfg: cfg,
	}
}

func Default() *Password {
	return &Password{
		cfg: DefaultConfig(),
	}
}

func DefaultConfig() *Config {
	return &Config{
		SkipValidation:  true, // TODO: Change to false in v2.0, only for 1.4 is this being disabled
		MixUpperLower:   true,
		MixAlphaNum:     true,
		MinSpecialChars: 1,
		MinLength:       8,
	}
}
