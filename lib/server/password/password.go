/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package password

// Password defines the password object
type Password struct {
	cfg *Config
}

// Config defines the configurations for a password object
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

// Default returns an instance of password using default configuration
func Default() *Password {
	return &Password{
		cfg: DefaultConfig(),
	}
}

// DefaultConfig defines the default configuraion
func DefaultConfig() *Config {
	return &Config{
		SkipValidation:  true, // TODO: Change to false in v2.0, only for 1.4 is this being disabled
		MixUpperLower:   true,
		MixAlphaNum:     true,
		MinSpecialChars: 1,
		MinLength:       8,
	}
}
