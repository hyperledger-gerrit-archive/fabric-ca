/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package factory

import (
	"bytes"
	"github.com/hyperledger/fabric/bccsp"
	"testing"
)

type testConfig struct {
	hashFamily string
	hashOpt    bccsp.HashOpts
}

func TestHashHelpers(t *testing.T) {
	tests := []testConfig{
		{bccsp.SHA256, &bccsp.SHA256Opts{}},
		{bccsp.SHA2_256, &bccsp.SHA256Opts{}},
		{bccsp.SHA384, &bccsp.SHA384Opts{}},
		{bccsp.SHA2_384, &bccsp.SHA384Opts{}},
		{bccsp.SHA3_256, &bccsp.SHA3_256Opts{}},
		{bccsp.SHA3_384, &bccsp.SHA3_384Opts{}},
		{"My New Hash", nil},
	}
	msg := "my very long, authentic, unique and borrrrring message"
	for _, perm := range tests {
		optHash := bccsp.HashNameToOpts(perm.hashFamily)

		hash1, err1 := GetDefault().Hash([]byte(msg), perm.hashOpt)
		hash2, err2 := GetDefault().Hash([]byte(msg), optHash)

		if err1 != nil {
			t.Fatalf("Failed first Hash call with %s [%s]", perm.hashFamily, err1)
		}

		if err2 != nil {
			t.Fatalf("Failed second Hash call with %s [%s]", perm.hashFamily, err2)
		}

		if false == bytes.Equal(hash1, hash2) {
			t.Fatalf("Hashes are different!", perm.hashFamily, err2)
		}
	}
}
