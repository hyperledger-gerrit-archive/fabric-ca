/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helpers

import (
	"encoding/base32"
	"strings"

	"github.com/hyperledger/fabric-ca/common/util"
)

// UniqueName generates base-32 enocded UUIDs for container names.
func UniqueName() string {
	name := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(util.GenerateBytesUUID())
	return strings.ToLower(name)
}
