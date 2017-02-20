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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml = "test.yaml"
)

var (
	longUserName = util.RandomString(1025)
)

var (
	longFileName = util.RandomString(261)
)

var validTests = []struct {
	input []string // input
}{
	{[]string{cmdName, "init", "-u", "admin:a:d:m:i:n:p:w"}},
	{[]string{cmdName, "init", "-d"}},
}

// Create a config element in unexpected format
var badSyntaxYaml = "bad.yaml"
var e = ioutil.WriteFile(badSyntaxYaml, []byte("signing: true\n"), 0644)

// Unsupported file type
var unsupportedFileType = "config.txt"

var errorTests = []struct {
	input    []string // input
	expected string   // expected result
}{
	{[]string{cmdName, "init", "-c", testYaml}, "option is required"},
	{[]string{cmdName, "init", "-u", "user::"}, "Failed to read"},
	{[]string{cmdName, "init", "-c", badSyntaxYaml, "-u", "user:pass"}, "Incorrect format"},
	{[]string{cmdName, "init", "-c", testYaml, "-u", fmt.Sprintf("%s:foo", longUserName)}, "than 1024 characters"},
	{[]string{cmdName, "init", "-c", fmt.Sprintf("%s.yaml", longFileName), "-u", "user:pass"}, "file name too long"},
	{[]string{cmdName, "init", "-c", unsupportedFileType}, "Unsupported Config Type"},
	{[]string{cmdName, "init", "-c", testYaml, "-u", "user"}, "missing a colon"},
	{[]string{cmdName, "init", "-c", testYaml, "-u", "user:"}, "empty password"},
	{[]string{cmdName, "bogus", "-c", testYaml, "-u", "user:pass"}, "unknown command"},
}

// TestInit tests fabric-ca-server init
func TestInit(t *testing.T) {
	os.Unsetenv(homeEnvVar)

	for _, et := range errorTests {
		err := RunMain(et.input)
		if err != nil {
			matched, _ := regexp.MatchString(et.expected, err.Error())
			if !matched {
				t.Errorf("FAILED:\n \tin: %v;\n \tout: %v;\n \texpected: %v\n", et.input, err.Error(), et.expected)
			}
		} else {
			t.Errorf("FAILED:\n \tin: %v;\n \tout: <nil>\n \texpected: %v\n", et.input, et.expected)
		}
		err = os.Remove(testYaml)
		if err != nil {
			continue
		}
	}

	os.Setenv("CA_CFG_PATH", ".")
	for _, et := range validTests {
		err := RunMain(et.input)
		if err != nil {
			t.Errorf("FAILED:\n \tin: %v;\n \tout: <nil>\n \texpected: SUCCESS\n", et.input)
		}
	}

}

// TestStart tests fabric-ca-server start
func TestStart(t *testing.T) {
	blockingStart = false
	err := RunMain([]string{cmdName, "start"})
	if err != nil {
		t.Errorf("server start failed: %s", err)
	}
}

func TestClean(t *testing.T) {
	defYaml, _ := getDefaultConfigFile()
	os.Remove(defYaml)
	os.Remove(testYaml)
	os.Remove(badSyntaxYaml)
	os.Remove(unsupportedFileType)
	os.Remove("ca-key.pem")
	os.Remove("ca-cert.pem")
	os.Remove("fabric-ca-server.db")
}
