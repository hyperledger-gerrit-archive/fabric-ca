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

package tcert

import (
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/csputil"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
)

func TestTCertWithoutAttribute(t *testing.T) {
	log.Level = log.LevelDebug
	// Get a manager
	mgr := getMgr(t)
	if mgr == nil {
		return
	}
	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}
	req := &GetBatchRequest{
		Count:  1,
		PreKey: "anyroot",
	}
	resp, err := mgr.GetBatch(req, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 1 {
		t.Errorf("Returned incorrect number of TCerts: expecting 1 but found %d", len(resp.TCerts))
	}
}

func TestTCertWithAttributes(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager
	mgr := getMgr(t)
	if mgr == nil {
		return
	}
	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}
	var Attrs = []Attribute{
		{Name: "SSN", Value: "123-456-789"},
		{Name: "Income", Value: "USD"},
	}
	req := &GetBatchRequest{
		Count:        2,
		EncryptAttrs: true,
		Attrs:        Attrs,
		PreKey:       "anotherprekey",
	}
	resp, err := mgr.GetBatch(req, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 2 {
		t.Errorf("Returned incorrect number of certs: expecting 2 but found %d", len(resp.TCerts))
	}
}

func TestSelfSigned(t *testing.T) {
	log.Level = log.LevelDebug
	cf := getClientFactory(t, nil)
	if cf == nil {
		return
	}
	attrs := []Attribute{
		{Name: "SSN", Value: "123-456-789"},
		{Name: "Income", Value: "USD"},
	}
	cf.SetAttributes(attrs, false)
	tcert, err := cf.GenTCert()
	if err != nil {
		t.Fatalf("GetTCert failed: %s", err)
	}
	cert, err := tcert.GetCert()
	if err != nil {
		t.Fatalf("tcert.GetCert failed: %s", err)
	}
	_ = cert
	attrs, err = tcert.GetAttributes()
	if err != nil {
		t.Fatalf("tcert.GetAttributes failed: %s", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("Found %d attributes but expected 2", len(attrs))
	}
}

func TestTCertFlow(t *testing.T) {
	log.Level = log.LevelDebug
	// Initialize server factory
	sf := getServerFactory(t)
	if sf == nil {
		return
	}
	// Initialize client factory with same KDF
	cf := getClientFactory(t, sf.KDFKey())
	if cf == nil {
		return
	}
	// Set attributes on server's factory with encryption enabled
	sf.SetPreKey("root")
	attrs := []Attribute{
		{Name: "SSN", Value: "123-456-789"},
		{Name: "Income", Value: "USD"},
	}
	sf.SetAttributes(attrs, true) // true enables encryption
	// Generate a tcert on the server
	tcert, err := sf.GenTCert()
	if err != nil {
		t.Fatalf("Failed to gen tcert: %s", err)
	}
	// Generate a tcert on the server
	id, err := tcert.GetEnrollmentID()
	if err != nil {
		t.Fatalf("Failed to get enrollment ID: %s", err)
	}
	t.Logf("enrollment ID: %s", id)
	// Attribute-related tests
	attrs2, err := tcert.GetAttributes()
	if err != nil {
		t.Fatalf("tcert.GetAttributes failed: %s", err)
	}
	if len(attrs2) != 2 {
		t.Fatalf("Found %d attributes but expected 2", len(attrs))
	}
	if !tcert.HasAttribute("Income") {
		t.Fatal("Did not contain attribute Income")
	}
	if tcert.HasAttribute("bogus") {
		t.Fatal("Should not have found bogus attribute")
	}
	income, err := tcert.GetAttributeValue("Income")
	if err != nil {
		t.Fatalf("tcert.GetAttributeValue Income failed: %s", err)
	}
	if string(income) != "USD" {
		t.Fatalf("tcert.GetAttributeValue returned wrong value for Income attribute [%s]: %s", string(income), err)
	}
	_, err = tcert.GetAttributeValue("bogus")
	if err == nil {
		t.Fatal("tcert.GetAttributeValue of bogus attribute passed but should have failed")
	}
}

func getMgr(t *testing.T) *Mgr {
	keyFile := "../../testdata/ec-key.pem"
	certFile := "../../testdata/ec.pem"
	mgr, err := LoadMgr(keyFile, certFile, getCSP(t))
	if err != nil {
		t.Fatalf("Failed loading mgr: %s", err)
	}
	return mgr
}

func getServerFactory(t *testing.T) *Factory {
	csp := getCSP(t)
	if csp == nil {
		return nil
	}
	mgr, err := LoadMgr("../../testdata/ec-key.pem", "../../testdata/ec.pem", csp)
	if err != nil {
		t.Fatalf("Failed to load manager: %s", err)
	}
	cert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		t.Fatalf("LoadCert failed: %s", err)
	}
	factory, err := mgr.NewFactory(cert, nil)
	if err != nil {
		t.Fatalf("NewFactory failed: %s", err)
	}
	return factory
}

func getClientFactory(t *testing.T, kdfKey []byte) *Factory {
	csp := getCSP(t)
	if csp == nil {
		return nil
	}
	mgr, err := NewMgr(csp)
	if err != nil {
		t.Fatalf("NewMgr failed: %s", err)
	}
	ekey, _, ecert, err := csputil.LoadKeyAndCert(
		"../../testdata/ec-key.pem",
		"../../testdata/ec.pem",
		csp)
	if err != nil {
		t.Fatalf("LoadCertAndKey of ecert failed: %s", err)
	}
	factory, err := mgr.NewFactory(ecert, kdfKey)
	if err != nil {
		t.Fatalf("NewFactory failed: %s", err)
	}
	factory.SetPreKey("root")
	factory.SetECertPrivateKey(ekey)
	return factory
}

func getCSP(t *testing.T) bccsp.BCCSP {
	err := factory.InitFactories(nil)
	if err != nil {
		t.Fatalf("Failed to init BCCSP: %s", err)
	}
	return factory.GetDefault()
}
