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
	"fmt"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/ldap"
	"github.com/jmoiron/sqlx"
)

// InitUserRegistry is the factory method for the user registry.
// If LDAP is configured, then LDAP is used for the user registry;
// otherwise, the CFSSL DB which is used for the certificates table is used.
func InitUserRegistry(cfg *Config) error {
	log.Debug("Initialize User Registry")
	var err error

	if cfg.LDAP != nil {
		// LDAP is being used for the user registry
		lib.UserRegistry, err = ldap.NewClient(cfg.LDAP)
		if err != nil {
			return err
		}
	} else {
		// The database is being used for the user registry
		var exists bool

		switch cfg.DBdriver {
		case "sqlite3":
			db, exists, err = dbutil.NewUserRegistrySQLLite3(cfg.DataSource)
			if err != nil {
				return err
			}

		case "postgres":
			db, exists, err = dbutil.NewUserRegistryPostgres(cfg.DataSource, &cfg.TLSConf.DBClient)
			if err != nil {
				return err
			}

		case "mysql":
			db, exists, err = dbutil.NewUserRegistryMySQL(cfg.DataSource, &cfg.TLSConf.DBClient)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid 'DBDriver' in config file: %s", cfg.DBdriver)
		}

		dbAccessor := new(lib.Accessor)
		dbAccessor.SetDB(db)

		lib.UserRegistry = dbAccessor

		// If the DB doesn't exist, bootstrap the DB
		if !exists {
			err := bootstrapDB()
			if err != nil {
				return err
			}
		}

	}

	return nil

}

// InitCertificateAccessor extends CFSSL database APIs for Certificates table
func InitCertificateAccessor(db *sqlx.DB) certdb.Accessor {
	log.Debug("Initialize Certificate Accessor")
	lib.MyCertDBAccessor = lib.NewCertDBAccessor(db)
	return lib.MyCertDBAccessor
}
