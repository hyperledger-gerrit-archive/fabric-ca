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
	"path"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	ocspConfig "github.com/cloudflare/cfssl/ocsp/config"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cli/server/ldap"
	libcsp "github.com/hyperledger/fabric-ca/lib/csp"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"

	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Config is the fabric-ca config structure
type Config struct {
	Debug          bool                      `mapstructure:"debug,omitempty"`
	Authentication bool                      `mapstructure:"authentication,omitempty"`
	CA             CAConfig                  `mapstructure:"ca"`
	UserRegistry   UserReg                   `mapstructure:"userRegistry"`
	Database       DatabaseConfig            `mapstructure:"database"`
	TLS            TLSConfig                 `mapstructure:"tls,omitempty"`
	Users          map[string]*User          `mapstructure:"users,omitempty"`
	Affiliations   map[string]interface{}    `mapstructure:"affiliations"`
	Signing        config.Signing            `mapstructure:"signing"`
	OCSP           ocspConfig.Config         `mapstructure:"ocsp"`
	AuthKeys       map[string]config.AuthKey `mapstructure:"auth_keys"`
	Remotes        map[string]string         `mapstructure:"remotes"`
	CSP            *libcsp.Config            `mapstructure:"csp,omitempty"`
}

// CAConfig is storing certificate and key
type CAConfig struct {
	CertFile string `mapstructure:"certFile"`
	KeyFile  string `mapstructure:"keyFile"`
}

// DatabaseConfig stores database configuration
type DatabaseConfig struct {
	Type       string              `mapstructure:"type"`
	Datasource string              `mapstructure:"datasource"`
	TLS        tls.ClientTLSConfig `mapstructure:"tls,omitempty"`
}

// UserReg defines the user registry properties
type UserReg struct {
	MaxEnrollments int          `mapstructure:"maxEnrollments"`
	LDAP           *ldap.Config `mapstructure:"ldap,omitempty"`
}

// TLSConfig defines the files needed for a TLS connection
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled,omitempty"`
	CAFile   string `mapstructure:"cafile,omitempty"` // Needed to support mutual TLS
	CertFile string `mapstructure:"certFile,omitempty"`
	KeyFile  string `mapstructure:"keyFile,omitempty"`
}

// User information
type User struct {
	// Name        string
	Pass        string          `mapstructure:"pass"` // enrollment secret
	Type        string          `mapstructure:"type"`
	Affiliation string          `mapstructure:"affiliation"`
	Attributes  []api.Attribute `mapstructure:"attrs,omitempty"`
}

const (
	serverConfigFile = "server-config.yaml"
)

// Constructor for fabric-ca config
func newConfig() *Config {
	c := new(Config)
	c.Authentication = true
	return c
}

// CFG is the fabric-ca specific config
var CFG Config

// Init initializes the fabric-ca config given the CFSSL config
func configInit(cfg *cli.Config) error {
	var err error

	CFG.Authentication = true

	if configFile == "" {
		log.Infof("No server config file provided. Looking in home directory: %s", util.GetDefaultHomeDir())
		configFile = path.Join(util.GetDefaultHomeDir(), serverConfigFile)
	}

	cfg.ConfigFile = configFile
	log.Debugf("Initializing config file at %s", configFile)

	if cfg.ConfigFile != "" {
		file := strings.Split(filepath.Base(cfg.ConfigFile), ".")
		fileName := file[0]
		fileExt := file[1]

		configFile, err = filepath.Abs(cfg.ConfigFile)
		if err != nil {
			return err
		}

		configDir = filepath.Dir(configFile)

		viper.SetConfigName(fileName) // name of config file (without extension)
		viper.SetConfigType(fileExt)

		viper.AddConfigPath(configDir) // path to look for the config file in

		err := viper.ReadInConfig()
		if err != nil {
			return err
		}

		err = viper.Unmarshal(&CFG)
		if err != nil {
			return err
		}

		log.Debugf("Inbound CFSSL server config is: %+v", cfg)

		var config = &config.Config{}
		config.Signing = &CFG.Signing
		config.OCSP = &CFG.OCSP
		config.Remotes = CFG.Remotes
		config.AuthKeys = CFG.AuthKeys

		cfg.CFG = config
	}

	CFG.CA.CertFile = util.Abs(CFG.CA.CertFile, configDir)
	CFG.CA.KeyFile = util.Abs(CFG.CA.KeyFile, configDir)
	CFG.TLS.CertFile = util.Abs(CFG.TLS.CertFile, configDir)
	CFG.TLS.KeyFile = util.Abs(CFG.TLS.KeyFile, configDir)
	CFG.TLS.CAFile = util.Abs(CFG.TLS.CAFile, configDir)

	if cfg.CAFile == "" {
		cfg.CAFile = CFG.CA.CertFile
	}

	if cfg.KeyFile == "" {
		cfg.CAKeyFile = CFG.CA.KeyFile
	}

	if cfg.DBConfigFile == "" {
		cfg.DBConfigFile = cfg.ConfigFile
	}

	if CFG.TLS.CertFile != "" {
		cfg.TLSCertFile = CFG.TLS.CertFile
	} else {
		cfg.TLSCertFile = CFG.CA.CertFile
	}

	if CFG.TLS.KeyFile != "" {
		cfg.TLSKeyFile = CFG.TLS.KeyFile
	} else {
		cfg.TLSKeyFile = CFG.CA.KeyFile
	}

	if CFG.TLS.CAFile != "" {
		cfg.MutualTLSCAFile = CFG.TLS.CAFile
	}

	if CFG.Database.Type == "" {
		msg := "No database specified, a database is needed to run fabric-ca server. Using default - Type: SQLite, Name: fabric-ca.db"
		log.Info(msg)
		CFG.Database.Type = sqlite
		CFG.Database.Datasource = "fabric-ca.db"
	}

	if CFG.Database.Type == sqlite {
		CFG.Database.Datasource = util.Abs(CFG.Database.Datasource, configDir)
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

	return nil
}
