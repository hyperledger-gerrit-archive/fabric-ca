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

package defaultImpl

import "testing"

func TestGenCert(t *testing.T) {
	cm := getCertMgr(t)
	if cm == nil {
		return
	}
	err := cm.GenCert("../../testdata/csr.json", "test", "/var/hyperledger/production/.cop/participant.json")
	if err != nil {
		t.Errorf("InitSelfSign failure: %v", err)
	}
}

func TestNoCSR(t *testing.T) {
	cm := getCertMgr(t)
	if cm == nil {
		return
	}

	// No CSR file specified
	err := cm.GenCert("", "test", "/var/hyperledger/production/.cop/participant.json")

	if err == nil {
		t.Error("No CSR file specified, should return error")
	}
}

func TestNoPrefix(t *testing.T) {
	cm := getCertMgr(t)
	if cm == nil {
		return
	}

	// No CSR file specified
	err := cm.GenCert("../../testdata/csr.json", "", "/var/hyperledger/production/.cop/participant.json")

	if err == nil {
		t.Error("No prefix specified, should return error")
	}
}

func TestNoParticipantFile(t *testing.T) {
	cm := getCertMgr(t)
	if cm == nil {
		return
	}

	// No CSR file specified
	err := cm.GenCert("../../testdata/csr.json", "test", "")

	if err == nil {
		t.Error("No Participant File specified, should return error")
	}
}

func getCertMgr(t *testing.T) *CertMgr {
	cm := NewCertMgr()
	if cm == nil {
		t.Error("Failed to create certificate manager")
	}
	return cm
}
