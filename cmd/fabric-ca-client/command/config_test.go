/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/hyperledger/fabric-ca/lib"
)

func TestProcessAttributes(t *testing.T) {
	// test cases
	testAttrs := []string{
		"AttrList=peer,orderer,client,user",
		"AttrListWithECertAttr=peer,orderer,client,user:ecert",
		"AttrTrue=true",
		"AttrTrueWithECertAttr=true:ecert",
		"AttrFalse=false",
		"AttrStar=*",
		"AttrStarWithECertAttr=*:ecert",
		"AttrTrueWithInvalidAttr=true:invalid",
		"AttrTrueWithDuplicateAttrs=true:ecert:ecert",
	}
	clientCfg := lib.ClientConfig{}
	err := processAttributes(testAttrs, &clientCfg)
	if err != nil {
		t.Error(err)
	}
	for _, attr := range clientCfg.ID.Attributes {
		switch attr.Name {
		case "AttrList":
			if attr.Value != "peer,orderer,client,user" || attr.ECert != false {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrListWithECertAttr":
			if attr.Value != "peer,orderer,client,user" || attr.ECert != true {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrTrue":
			if attr.Value != "true" || attr.ECert != false {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrTrueWithECertAttr":
			if attr.Value != "true" || attr.ECert != true {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrFalse":
			if attr.Value != "false" || attr.ECert != false {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrStar":
			if attr.Value != "*" || attr.ECert != false {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrStarWithECertAttr":
			if attr.Value != "*" || attr.ECert != true {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrTrueWithInvalidAttr":
			if attr.Value != "true" || attr.ECert != false {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		case "AttrTrueWithDuplicateAttrs":
			if attr.Value != "true" || attr.ECert != true {
				t.Fatalf("Attr conversion of '%s' failed (value='%s', ecert='%v')",
					attr.Name, attr.Value, attr.ECert)
			}
		default:
			t.Fatal("Unknown test case")
		}
	}
}
