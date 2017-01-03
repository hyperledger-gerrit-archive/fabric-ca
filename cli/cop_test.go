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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/idp"
)

type Admin struct {
	User       string
	Pass       []byte
	Type       string
	Group      string
	Attributes []idp.Attribute
}

const (
	CFG             string = "../testdata/testconfig.json"
	CSR             string = "../testdata/csr.json"
	REG             string = "../testdata/registerrequest.json"
	ClientTLSConfig string = "cop_client.json"
)

var (
	Registrar  = Admin{User: "admin", Pass: []byte("adminpw"), Type: "User", Group: "bank_a", Attributes: []idp.Attribute{idp.Attribute{Name: "hf.Registrar.DelegateRoles", Value: "client,validator,auditor"}}}
	testEnroll = cop.RegisterRequest{User: "testEnroll", Type: "client", Group: "bank_a", Attributes: []idp.Attribute{idp.Attribute{Name: "role", Value: "client"}}}
)

var serverStarted bool
var serverExitCode = 0
var dir string

// Test the server start command
func TestStartServer(t *testing.T) {
	fmt.Println("running TestStartServer ...")
	rtn := startServer()
	if rtn != 0 {
		t.Errorf("Failed to start server with return code: %d", rtn)
		t.FailNow()
	}
	clientConfig := filepath.Join(dir, ClientTLSConfig)
	os.Link("../testdata/cop_client.json", clientConfig)
	fmt.Println("passed TestStartServer")
}

func TestEnroll(t *testing.T) {
	fmt.Println("running TestEnroll ...")
	rtn := enroll("admin", "adminpw")
	if rtn != 0 {
		fmt.Printf("enroll failed: rtn=%d\n", rtn)
		t.Errorf("Failed to enroll with return code: %d", rtn)
	}
	fmt.Println("passed TestEnroll")
}

func TestRegister(t *testing.T) {
	fmt.Println("running TestRegister ...")
	rtn := register(REG)
	if rtn != 0 {
		fmt.Printf("Register failed: rtn=%d\n", rtn)
		t.Errorf("Failed to register with return code: %d", rtn)
	}
	fmt.Println("passed TestRegister")
}

func TestReenroll(t *testing.T) {
	fmt.Println("running TestReenroll ...")
	rtn := reenroll()
	if rtn != 0 {
		fmt.Printf("reenroll failed: rtn=%d\n", rtn)
		t.Errorf("Failed to reenroll with return code: %d", rtn)
	}
	fmt.Println("passed TestReenroll")
}

func TestCFSSL(t *testing.T) {
	fmt.Println("running TestCFSSL ...")
	rtn := cfssl()
	if rtn != 0 {
		fmt.Printf("TestCFSSL failed: rtn=%d\n", rtn)
		t.Errorf("Failed to test CFSSL with return code: %d", rtn)
	}
	fmt.Println("passed TestCFSSL")
}

func TestBogusCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "bogus"})
	if rtn == 0 {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

func startServer() int {
	var err error
	dir, err = ioutil.TempDir("", "cop")
	if err != nil {
		fmt.Printf("Failed to create temp directory [error: %s]", err)
		return serverExitCode
	}

	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	os.Setenv("COP_HOME", dir)
	serverExitCode = COPMain([]string{"cop", "server", "start", "-config", CFG})
}

func enroll(user, pass string) int {
	fmt.Printf("enrolling user '%s' with password '%s' ...\n", user, pass)
	rtn := COPMain([]string{"cop", "client", "enroll", user, pass, "https://localhost:8888", CSR})
	fmt.Printf("enroll result is '%d'\n", rtn)
	return rtn
}

func reenroll() int {
	fmt.Println("reenrolling ...")
	rtn := COPMain([]string{"cop", "client", "reenroll", "https://localhost:8888", CSR})
	fmt.Printf("reenroll result is '%d'\n", rtn)
	return rtn
}

func cfssl() int {
	fmt.Println("cfssl ...")
	rtn := COPMain([]string{"cop", "cfssl", "version"})
	fmt.Printf("cfssl result is '%d'\n", rtn)
	return rtn
}

func register(file string) int {
	fmt.Printf("register file '%s' ...\n", file)
	rtn := COPMain([]string{"cop", "client", "register", file, "https://localhost:8888", "loglevel=0"})
	fmt.Printf("register result is '%d'\n", rtn)
	return rtn
}
