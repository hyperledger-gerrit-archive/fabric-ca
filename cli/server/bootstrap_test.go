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

package server

import (
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

// var testDB *sqlx.DB
var bootCFG *Config

const (
	bootPath = "/tmp/bootstraptest"
)

func prepBootstrap() (*Bootstrap, error) {
	if _, err := os.Stat(bootPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(bootPath, 0755)
		}
	} else {
		os.RemoveAll(bootPath)
		os.MkdirAll(bootPath, 0755)
	}
	var err error

	cfg := new(cli.Config)
	cfg.ConfigFile = "../../testdata/testconfig.json"
	configInit(cfg)

	bootCFG = CFG
	bootCFG.Home = bootPath
	bootCFG.DataSource = bootCFG.Home + "/cop.db"

	CFG.UserRegistery, err = NewUserRegistry(bootCFG.DBdriver, bootCFG.DataSource)
	if err != nil {
		return nil, err
	}

	b := BootstrapDB()
	return b, nil
}

func TestAllBootstrap(t *testing.T) {
	b, err := prepBootstrap()
	if err != nil {
		t.Fatal("Failed to open connection to database")
	}

	testBootstrapGroup(b, t)
	testBootstrapUsers(b, t)

	os.RemoveAll(bootPath)
}

func testBootstrapGroup(b *Bootstrap, t *testing.T) {
	b.PopulateGroupsTable()

	_, err := b.cfg.UserRegistery.GetGroup("bank_b")

	if err != nil {
		t.Error("Failed bootstrapping groups table")
	}
}

func testBootstrapUsers(b *Bootstrap, t *testing.T) {
	b.PopulateUsersTable()

	_, err := b.cfg.UserRegistery.GetUser("admin")

	if err != nil {
		t.Error("Failed bootstrapping users table")
	}
}
