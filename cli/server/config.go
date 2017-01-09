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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cli/server/ldap"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"

	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Config is the fabric-ca config structure
type Config struct {
	Debug          bool             `json:"debug,omitempty"`
	Authentication bool             `json:"authentication,omitempty"`
	Users          map[string]*User `json:"users,omitempty"`
	DBdriver       string           `json:"driver"`
	DataSource     string           `json:"data_source"`
	UsrReg         UserReg          `json:"user_registry"`
	LDAP           *ldap.Config     `json:"ldap,omitempty"`
	CAFile         string           `json:"ca_cert"`
	KeyFile        string           `json:"ca_key"`
	TLSConf        TLSConfig        `json:"tls,omitempty"`
	TLSDisable     bool             `json:"tls_disable,omitempty"`
}

// UserReg defines the user registry properties
type UserReg struct {
	MaxEnrollments int `json:"max_enrollments"`
}

// TLSConfig defines the files needed for a TLS connection
type TLSConfig struct {
	TLSCertFile     string              `json:"tls_cert,omitempty"`
	TLSKeyFile      string              `json:"tls_key,omitempty"`
	MutualTLSCAFile string              `json:"mutual_tls_ca,omitempty"`
	DBClient        tls.ClientTLSConfig `json:"db_client,omitempty"`
}

// User information
type User struct {
	Pass       string          `json:"pass"` // enrollment secret
	Type       string          `json:"type"`
	Group      string          `json:"group"`
	Attributes []api.Attribute `json:"attrs,omitempty"`
}

// Constructor for fabric-ca config
func newConfig() *Config {
	c := new(Config)
	c.Authentication = true
	return c
}

// CFG is the fabric-ca specific config
var CFG *Config

// Init initializes the fabric-ca config given the CFSSL config
func configInit(cfg *cli.Config) {
	var err error
	configFile, err = filepath.Abs(cfg.ConfigFile)
	if err != nil {
		panic(err.Error())
	}
	configDir = filepath.Dir(configFile)
	log.Debugf("Initializing config file at %s", configFile)
	log.Debugf("Inbound CFSSL server config is: %+v", cfg)

	CFG = new(Config)
	CFG.Authentication = true

	body, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(body, CFG)
	if err != nil {
		panic(fmt.Sprintf("error parsing %s: %s", configFile, err.Error()))
	}

	CFG.CAFile = util.Abs(CFG.CAFile, configDir)
	CFG.KeyFile = util.Abs(CFG.KeyFile, configDir)
	CFG.TLSConf.TLSCertFile = util.Abs(CFG.TLSConf.TLSCertFile, configDir)
	CFG.TLSConf.TLSKeyFile = util.Abs(CFG.TLSConf.TLSKeyFile, configDir)
	CFG.TLSConf.MutualTLSCAFile = util.Abs(CFG.TLSConf.MutualTLSCAFile, configDir)
	tls.AbsTLSClient(&CFG.TLSConf.DBClient, configDir)

	if cfg.CAFile == "" {
		cfg.CAFile = CFG.CAFile
	}

	if cfg.KeyFile == "" {
		cfg.CAKeyFile = CFG.KeyFile
	}

	if cfg.DBConfigFile == "" {
		cfg.DBConfigFile = cfg.ConfigFile
	}

	if CFG.TLSConf.TLSCertFile != "" {
		cfg.TLSCertFile = CFG.TLSConf.TLSCertFile
	} else {
		cfg.TLSCertFile = CFG.CAFile
	}

	if CFG.TLSConf.TLSKeyFile != "" {
		cfg.TLSKeyFile = CFG.TLSConf.TLSKeyFile
	} else {
		cfg.TLSKeyFile = CFG.KeyFile
	}

	if CFG.TLSConf.MutualTLSCAFile != "" {
		cfg.MutualTLSCAFile = CFG.TLSConf.MutualTLSCAFile
	}

	if CFG.DBdriver == "" {
		msg := "No database specified, a database is needed to run fabric-ca server. Using default - Type: SQLite, Name: fabric-ca.db"
		log.Info(msg)
		CFG.DBdriver = sqlite
		CFG.DataSource = "fabric-ca.db"
	}

	if CFG.DBdriver == sqlite {
		CFG.DataSource = util.Abs(CFG.DataSource, configDir)
	}

	dbg := os.Getenv("FABRIC_CA_DEBUG")
	if dbg != "" {
		CFG.Debug = dbg == "true"
	}
	if CFG.Debug {
		log.Level = log.LevelDebug
	}

	log.Debugf("CFSSL server config is: %+v", cfg)
	log.Debugf("Fabric CA server config is: %+v", CFG)
}
