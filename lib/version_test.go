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

package lib_test

import (
	"testing"

	"github.com/hyperledger/fabric-ca/lib"
	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	// Positive test cases
	cmpVersion(t, "1.1.1-xxxx", "1.1.1-yyy-zzz", 0)
	cmpVersion(t, "1.0.0", "1.1.0", 1)
	cmpVersion(t, "1.1.0", "1.1.0.0.0", 0)
	cmpVersion(t, "1.5.0.0.0", "1.5", 0)
	cmpVersion(t, "1.0.0", "1.0.0.1", 1)
	cmpVersion(t, "1.1.0", "1.0.0", -1)
	cmpVersion(t, "1.0.0.0.1", "1.0", -1)
	cmpLevels(t, "1.0.0", 0, 0, 0)
	cmpLevels(t, "1.0.4", 0, 0, 0)
	cmpLevels(t, "1.1.0", 1, 0, 0)
	cmpLevels(t, "1.1.1", 1, 0, 0)
	cmpLevels(t, "1.2.1", 1, 0, 0)
	// Negative test cases
	_, err := lib.CmpVersion("1.x.2.0", "1.7.8")
	if err == nil {
		t.Error("Expecting error at 1.x.2.0")
	}
	_, err = lib.CmpVersion("1.2.0", "x.1.7.8")
	if err == nil {
		t.Error("Expecting error at x.1.7.8")
	}
}

func cmpVersion(t *testing.T, v1, v2 string, expectedResult int) {
	result, err := lib.CmpVersion(v1, v2)
	if err != nil {
		t.Fatalf("Failed comparing versions: %s", err)
	}
	assert.Equal(t, expectedResult, result)
}

func cmpLevels(t *testing.T, version string, identity, affiliation, certificate int) {
	levels, err := lib.GetLevels(version)
	if err != nil {
		t.Fatalf("GetLevels failed: %s", err)
	}
	assert.Equal(t, levels.Identity, identity)
	assert.Equal(t, levels.Affiliation, affiliation)
	assert.Equal(t, levels.Certificate, certificate)
}
