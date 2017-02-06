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

package util

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	_ "github.com/mattn/go-sqlite3"
)

func TestGetEnrollmentIDFromPEM(t *testing.T) {
	cert, err := ioutil.ReadFile(getPath("ec.pem"))
	if err != nil {
		t.Fatalf("TestGetEnrollmentIDFromPEM.ReadFile failed: %s", err)
	}
	_, err = GetEnrollmentIDFromPEM(cert)
	if err != nil {
		t.Fatalf("Failed to get enrollment ID from PEM: %s", err)
	}
}

func TestECCreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}

	ECtoken, err := CreateToken(csp, cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed: %s", err)
	}

	_, err = VerifyToken(csp, ECtoken, body)
	if err != nil {
		t.Fatalf("VerifyToken failed: %s", err)
	}
}

// This test case has been removed temporarily
// as BCCSP does not have support for RSA private key import
/*
func TestRSACreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}

	RSAtoken, err := CreateToken(csp, cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed with error : %s", err)
	}

	_, err = VerifyToken(csp, RSAtoken, body)
	if err != nil {
		t.Fatalf("VerifyToken failed with error : %s", err)
	}
}
*/

func TestCreateTokenDiffKey(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}
	_, err := CreateToken(csp, cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey passed but should have failed")
	}
}

// TestCreateTokenDiffKey2 has been commeted out right now
// As there BCCSP does not have support fot RSA private Key
// import. This will be uncommented when the support is in.
/*
func TestCreateTokenDiffKey2(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}
	_, err := CreateToken(csp, cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey2 passed but should have failed")
	}
}
*/

func TestEmptyToken(t *testing.T) {
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}
	_, err := VerifyToken(csp, "", body)
	if err == nil {
		t.Fatalf("TestEmptyToken passed but should have failed")
	}
}

func TestEmptyCert(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}
	_, err := CreateToken(csp, cert, []byte(""), body)
	if err == nil {
		t.Fatalf("TestEmptyCert passed but should have failed")
	}
}

func TestEmptyKey(t *testing.T) {
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}

	_, err := CreateToken(csp, []byte(""), privKey, body)
	if err == nil {
		t.Fatalf("TestEmptyKey passed but should have failed")
	}
}

func TestEmptyBody(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))

	csp, error := getDefaultBCCSPInstance()
	if error != nil {
		t.Errorf("Default BCCSP instance failed with error %s", error)
	}

	_, err := CreateToken(csp, cert, privKey, []byte(""))
	if err != nil {
		t.Fatalf("CreateToken failed: %s", err)
	}
}

func TestRandomString(t *testing.T) {
	str := RandomString(10)
	if str == "" {
		t.Fatalf("RandomString failure")
	}
}

func TestRemoveQuotes(t *testing.T) {
	str := RemoveQuotes(`"a"`)
	if str != "a" {
		t.Fatalf("TestRemoveQuotes failed")
	}
}

func TestRemoveQuotesNone(t *testing.T) {
	str := RemoveQuotes(`a`)
	if str != "a" {
		t.Fatalf("TestRemoveQuotesNone failed")
	}
}

func TestCreateHome(t *testing.T) {
	t.Log("Test Creating Home Directory")
	os.Unsetenv("COP_HOME")
	tempDir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Errorf("Failed to create temp directory [error: %s]", err)
	}
	os.Setenv("HOME", tempDir)

	_, err = CreateHome()
	if err != nil {
		t.Errorf("Failed to create home directory, error: %s", err)
	}

	dir := filepath.Join(tempDir, "fabric-cop")

	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to create home directory")
		}
	}

}

func TestGetDefaultHomeDir(t *testing.T) {
	os.Setenv("FABRIC_CA_HOME", "")
	os.Setenv("HOME", "")
	home := GetDefaultHomeDir()
	if home != "/var/hyperledger/fabric/dev/fabric-ca" {
		t.Errorf("Incorrect default home (%s) path retrieved", home)
	}

	os.Setenv("HOME", "/tmp")
	home = GetDefaultHomeDir()
	if home != "/tmp/fabric-ca" {
		t.Errorf("Incorrect $HOME (%s) path retrieved", home)
	}

	os.Setenv("FABRIC_CA_HOME", "/tmp")
	home = GetDefaultHomeDir()
	if home != "/tmp" {
		t.Errorf("Incorrect $FABRIC_CA_HOME (%s) path retrieved", home)
	}

}

func TestUnmarshal(t *testing.T) {
	byteArray := []byte(`{"text":"foo"}`)
	type test struct {
		text string
	}
	var Test test
	err := Unmarshal(byteArray, &Test, "testing unmarshal")
	if err != nil {
		t.Error("Failed to unmarshal, error: ", err)
	}
}

func TestMarshal(t *testing.T) {
	var x interface{}
	_, err := Marshal(x, "testing marshal")
	if err != nil {
		t.Error("Failed to marshal, error: ", err)
	}
}

func TestReadFile(t *testing.T) {
	_, err := ReadFile("../testdata/csr.json")
	if err != nil {
		t.Error("Failed to read file, error: ", err)
	}
}

func TestWriteFile(t *testing.T) {
	testData := []byte("foo")
	err := WriteFile("../testdata/test.txt", testData, 0777)
	if err != nil {
		t.Error("Failed to write file, error: ", err)
	}
	os.Remove("../testdata/test.txt")
}

func getPath(file string) string {
	return "../testdata/" + file
}

func TestStrContained(t *testing.T) {
	strs := []string{"one", "two", "three"}
	str := "one"
	result := StrContained(str, strs)
	if result != true {
		t.Error("Should have result in true")
	}
}

func TestFileExists(t *testing.T) {
	name := "../testdata/csr.json"

	exists := FileExists(name)
	if exists == false {
		t.Error("File does not exist")
	}
}

func TestMakeFileAbs(t *testing.T) {
	makeFileAbs(t, "", "", "")
	makeFileAbs(t, "/a/b/c", "", "/a/b/c")
	makeFileAbs(t, "c", "/a/b", "/a/b/c")
	makeFileAbs(t, "../c", "/a/b", "/a/c")
}

func makeFileAbs(t *testing.T, file, dir, expect string) {
	path, err := MakeFileAbs(file, dir)
	if err != nil {
		t.Errorf("Failed to make %s absolute: %s", file, err)
	}
	// make expected path platform specific to work on Windows
	if expect != "" {
		expect, _ = filepath.Abs(expect)
	}
	if path != expect {
		t.Errorf("Absolute of file=%s with dir=%s expected %s but was %s", file, dir, expect, path)
	}
}

func getDefaultBCCSPInstance() (bccsp.BCCSP, error) {
	defaultBccsp, bccspError := factory.GetDefault()
	if bccspError != nil {
		return nil, fmt.Errorf("BCCSP initialiazation failed with error : %s", bccspError)
	}
	if defaultBccsp == nil {
		return nil, errors.New("Cannot get default instance of BCCSP")
	}

	return defaultBccsp, nil
}
