/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {

	cfgFileName = "../../testdata/default-config.yaml"
	viper.Set("boot", "admin:adminpwd")
	err := configInit()
	assert.NoError(t, err, "configInit should not have failed")

	// get the default signing profile
	signingProfile := serverCfg.CAcfg.Signing.Default
	ku, eku, unk := signingProfile.Usages()
	// expected key usage is digital signature
	assert.Equal(t, x509.KeyUsageDigitalSignature, ku, "Expected KeyUsageDigitalSignature")
	assert.Equal(t, 0, len(eku), "Found %d extended usages but expected 0", len(eku))
	assert.Equal(t, 0, len(unk), "Found %d unknown key usages", len(unk))

	// cleanup
	os.Remove(cfgFileName)

}
