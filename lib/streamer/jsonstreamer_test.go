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
package streamer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type element struct {
	Name string
	Type string
}

func TestJSONStreamer(t *testing.T) {
	cbFuncCalled := false

	testCB := func(decoder *json.Decoder) error {
		var ele element
		err := decoder.Decode(&ele)
		if err != nil {
			return err
		}
		cbFuncCalled = true
		t.Logf("t.Logf: %+v\n", ele)
		return nil
	}

	const jsonStream = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": {"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]}, "errors": [], "c": "cval", "d": "dval", "e": 1.234}`
	dec := json.NewDecoder(strings.NewReader(jsonStream))
	err := StreamJSONArray(dec, "result.identities", testCB)
	assert.NoError(t, err, "Failed to correctly stream JSON")
	assert.True(t, cbFuncCalled, "Callback function was not successfully called")

	const jsonStream_err = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": {"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]}, "errors": [{"code":20,"message":"Authorization failure"}], "c": "cval", "d": "dval", "e": 1.234}`
	dec = json.NewDecoder(strings.NewReader(jsonStream_err))
	err = StreamJSONArray(dec, "result.identities", testCB)
	assert.Error(t, err, "Should have returned the error in the JSON stream")

	const jsonStream_baderr = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": {"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]}, "errors": {"code":20,"message":"Authorization failure"}, "c": "cval", "d": "dval", "e": 1.234}`
	dec = json.NewDecoder(strings.NewReader(jsonStream_baderr))
	err = StreamJSONArray(dec, "result.identities", testCB)
	assert.Error(t, err, "Should have failed, errors is not array type")

	dec = json.NewDecoder(strings.NewReader(jsonStream))
	err = StreamJSONArray(dec, "a", nil)
	assert.Error(t, err, "Should have failed, 'a' is not an array")

	dec = json.NewDecoder(strings.NewReader(jsonStream))
	err = StreamJSONArray(dec, "f", testCB)
	assert.Error(t, err, "Should have failed, 'f' is not an element in the JSON object")

	const jsonStream2 = `"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]`
	dec = json.NewDecoder(strings.NewReader(jsonStream2))
	err = StreamJSONArray(dec, "identities", testCB)
	assert.Error(t, err, "Should have failed, missing opening '{'")

	const jsonStream3 = `["identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]`
	dec = json.NewDecoder(strings.NewReader(jsonStream3))
	err = StreamJSONArray(dec, "identities", testCB)
	assert.Error(t, err, "Should have failed, incorrect opening bracket")

	const jsonStream4 = `{"identities": [[]}`
	dec = json.NewDecoder(strings.NewReader(jsonStream4))
	err = StreamJSONArray(dec, "identities", testCB)
	assert.Error(t, err, "Should have failed, incorrect number of square brackets")

	const jsonStream5 = `{"a": "aval", "identities": [{]"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval}`
	dec = json.NewDecoder(strings.NewReader(jsonStream5))
	err = StreamJSONArray(dec, "c", testCB)
	assert.Error(t, err, "Should have failed, incorrect opening square bracket")

	const jsonStream6 = `{"a": "aval", "identities": []{"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval"}`
	dec = json.NewDecoder(strings.NewReader(jsonStream6))
	err = StreamJSONArray(dec, "c", testCB)
	assert.Error(t, err, "Should have failed, incorrect format of 'identities'")

	const jsonStream7 = `{"a"/ "aval", "identities": {"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval"}`
	dec = json.NewDecoder(strings.NewReader(jsonStream7))
	err = StreamJSONArray(dec, "c", testCB)
	assert.Error(t, err, "Should have failed, incorrect JSON syntax")
}
