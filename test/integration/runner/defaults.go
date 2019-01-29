/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"encoding/base32"
	"strings"
	"time"

	"github.com/hyperledger/fabric/common/util"
	"github.com/phayes/freeport"
)

const DefaultStartTimeout = 30 * time.Second

// DefaultNamer is the default naming function.
var DefaultNamer NameFunc = UniqueName

// A NameFunc is used to generate container names.
type NameFunc func() string

// UniqueName generates base-32 enocded UUIDs for container names.
func UniqueName() string {
	name := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(util.GenerateBytesUUID())
	return strings.ToLower(name)
}

// RandomPort selects a random free port for use
func RandomPort() (int, error) {
	port, err := freeport.GetFreePort()
	if err != nil {
		return 0, err
	}
	return port, err
}
