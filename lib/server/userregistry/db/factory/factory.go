/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/mysql"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/postgres"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/sqlite"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

type DB interface {
	Connect() error
	Ping() error
	Create() (*sqlx.DB, error)
}

func New(dbType, datasource string, tlsConfig *tls.ClientTLSConfig, csp bccsp.BCCSP) (DB, error) {
	switch dbType {
	case "sqlite3":
		return sqlite.NewUserRegistry(datasource), nil
	case "postgres":
		return postgres.NewUserRegistry(datasource, tlsConfig), nil
	case "mysql":
		return mysql.NewUserRegistry(datasource, tlsConfig, csp), nil
	default:
		return nil, errors.Errorf("Invalid db.type in config file: '%s'; must be 'sqlite3', 'postgres', or 'mysql'", dbType)
	}
}
