/*
Copyright IBM Corp. 2018 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package idemix

import (
	"testing"

	"github.com/stretchr/testify/assert"

	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
)

func TestGetUnRevokedHandles(t *testing.T) {
	ra := &revocationAuthority{issuer: &issuer{name: "ca1", homeDir: ".", cfg: &Config{}}}
	info := &RevocationAuthorityInfo{
		Epoch:                1,
		LastHandleInPool:     100,
		NextRevocationHandle: 2,
		PrivateKey:           "",
		PublicKey:            "",
	}

	revokedCred := CredRecord{
		RevocationHandle: "10",
	}
	revokedCreds := []CredRecord{revokedCred}
	unrevokedHandles := ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 100, len(unrevokedHandles))

	revokedCred = CredRecord{
		RevocationHandle: util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(10))),
	}
	revokedCreds = []CredRecord{revokedCred}
	unrevokedHandles = ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 99, len(unrevokedHandles))
}
