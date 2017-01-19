/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestGetUnecnryptedAttrFromCert(t *testing.T) {

	certBuff, err := ioutil.ReadFile("../../testdata/tcertwithunencryptedattr.pem")
	if err != nil {
		t.Errorf("Reading Cert file from directory failed with error : [%v]", err)
	}

	performTests(certBuff, nil, t)

}

func TestGetEcnryptedAttrFromCert(t *testing.T) {

	tcertJSONResponse, err := ioutil.ReadFile("../../testdata/tcert_response_enc_attr.json")
	if err != nil {
		t.Errorf("Reading TCert JSON response from directory failed with error : [%v]", err)
	}

	batchResponse := &GetBatchResponse{}
	error := json.Unmarshal(tcertJSONResponse, batchResponse)
	if error != nil {
		t.Errorf("JOSN Unmarshalling failed with error : [%v]", error)
	}

	tcerts := batchResponse.TCerts

	if len(tcerts) == 0 {
		t.Error("No TCert found in the response")
	}
	tcert := tcerts[0]
	cert := tcert.Cert
	keys := tcert.Keys

	performTests(cert, keys, t)

}

//	performTestSteps perform all necessary steps
func performTests(certBuff []byte, keys map[string][]byte, t *testing.T) {

	attrMgr, error := GetAttributeManagerInstance(certBuff, keys)
	if attrMgr == nil {
		t.Errorf("GetAttributeManagerInstance failed")
	}
	if error != nil {
		t.Errorf("GetAttributeManagerInstance instantiation failed with error : [%v]", error)
	}

	//Test for retrieving attribute names
	attributeNames := attrMgr.GetNames()
	if len(attributeNames) == 0 {
		t.Error("Error in retrieving TCert names")
	}

	//Get map of all attribute name/value pair
	attributes := attrMgr.GetAllValues()
	if attributes == nil {
		t.Error("Error in retrieving TCert Attribute Key/Value pair")
	}

	attributName := attributeNames[0]
	attributeValue, error := attrMgr.GetValue(attributName)
	if attributeValue == "" {
		t.Errorf("Error in retrieving Attribute value for attribute %s", attributName)
	}
	if error != nil {
		t.Errorf("Attribute Value retrieval failed with error : %s", error)
	}

	attributeNameList := []string{attributeNames[0], attributeNames[2], attributeNames[4]}
	attributes = attrMgr.GetValues(attributeNameList)

	if attributes == nil {
		t.Error("Attribute List cannot be retrieved")
	}

}
