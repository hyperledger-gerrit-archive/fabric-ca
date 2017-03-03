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

package util_test

import (
	"reflect"
	"testing"

	"github.com/hyperledger/fabric-ca/lib"
	. "github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// A test struct
type A struct {
	ASlice     []string          `component:"server" help:"Slice description"`
	AStr       string            `component:"server" def:"defval" help:"Str1 description"`
	AInt       int               `component:"server" def:"10" help:"Int1 description"`
	AB         B                 `component:"server" help:"FB description"`
	AStr2      string            `skip:"true"`
	AIntArray  []int             `component:"server" help:"IntArray description"`
	AMap       map[string]string `skip:"true"`
	ABPtr      *B                `component:"server" help:"FBP description"`
	AInterface interface{}       `skip:"true"`
}

// B test struct
type B struct {
	BStr  string `component:"server" help:"Str description"`
	BInt  int    `skip:"true"`
	BBool bool   `component:"server" def:"true" help:"Bool description"`
	BCPtr *C
}

// C test struct
type C struct {
	CBool bool   `component:"server" def:"true" help:"Bool description"`
	CStr  string `component:"server" help:"Str description"`
}

func printit(f *Field) error {
	//fmt.Printf("%+v\n", f)
	return nil
}

func TestRegisterFlags(t *testing.T) {
	tags := map[string]string{
		"help.fb.int": "This is an int field",
	}
	err := RegisterFlags(&pflag.FlagSet{}, &A{}, tags, "server", "")
	if err != nil {
		t.Errorf("Failed to register flags: %s", err)
	}
}

func TestParseObj(t *testing.T) {
	err := ParseObj(&A{}, printit)
	if err != nil {
		t.Errorf("Failed to parse foo: %s", err)
	}
	err = ParseObj(&A{}, nil)
	if err == nil {
		t.Error("Should have failed to parse but didn't")
	}
}

func TestCheckForMissingValues(t *testing.T) {

	src := &A{
		AStr:      "AStr",
		AStr2:     "AStr2",
		AIntArray: []int{1, 2, 3},
		AMap:      map[string]string{"Key1": "Val1", "Key2": "Val2"},
		AB: B{
			BStr: "BStr",
			BCPtr: &C{
				CBool: true,
				CStr:  "CStr",
			},
		},
		ABPtr: &B{
			BStr: "BStr",
			BCPtr: &C{
				CBool: false,
				CStr:  "CStr",
			},
		},
		AInterface: &C{
			CStr: "CStr",
		},
	}

	dst := &A{
		AStr2: "dstAStr2",
		AInt:  2,
	}

	CopyMissingValues(src, dst)

	if src.AStr != dst.AStr {
		t.Error("Failed to copy field AStr")
	}

	if src.AB.BStr != dst.AB.BStr {
		t.Error("Failed to copy field AB.BStr")
	}

	if src.ABPtr.BStr != dst.ABPtr.BStr {
		t.Error("Failed to copy field ABPtr.BStr")
	}

	if src.ABPtr.BCPtr.CStr != dst.ABPtr.BCPtr.CStr {
		t.Error("Failed to copy field ABPtr.BCPtr.CStr")
	}

	if !reflect.DeepEqual(src.AMap, dst.AMap) {
		t.Errorf("Failed to copy AMap: src=%+v, dst=%+v", src.AMap, dst.AMap)
	}

	for i := range src.AIntArray {
		sv := src.AIntArray[i]
		dv := dst.AIntArray[i]
		if sv != dv {
			t.Errorf("Failed to copy element %d of Int2 array (%d != %d)", i, sv, dv)
		}
	}

	if dst.AStr2 != "dstAStr2" {
		t.Errorf("Incorrectly replaced AStr2 with %s", dst.AStr2)
	}

	if dst.AInt != 2 {
		t.Errorf("Incorrectly replaced AInt with %d", dst.AInt)
	}
}

func TestViperUnmarshal(t *testing.T) {
	var err error

	cfg := &lib.CAConfig{}
	vp := viper.New()
	vp.SetConfigFile("../testdata/testviperunmarshal.yaml")
	err = vp.ReadInConfig()
	if err != nil {
		t.Errorf("Failed to read config file: %s", err)
	}

	sliceFields := []string{
		"db.tls",
	}
	err = ViperUnmarshal(cfg, sliceFields, vp)
	if err == nil {
		t.Error("Should have resulted in an error, as tls can't be casted to type string array")
	}

	sliceFields = []string{
		"db.tls.certfiles",
	}
	err = ViperUnmarshal(cfg, sliceFields, vp)
	if err != nil {
		t.Error("Failed to correctly process valid path to be type string array: ", err)
	}

}
