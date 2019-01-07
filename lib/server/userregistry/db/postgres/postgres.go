/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/util"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // import to support Postgres
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/sqlx.go -fake-name Sqlx . Sqlx

// Sqlx is interface that defines db function needed by database creation
type Sqlx interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Rebind(query string) string
	Ping() error
}

// Postgres defines PostgreSQL database
type Postgres struct {
	SqlxDB Sqlx
	TLS    *tls.ClientTLSConfig

	datasource string
	dbName     string
}

// NewUserRegistry create a PosgreSQL based user registry
func NewUserRegistry(datasource string, clientTLSConfig *tls.ClientTLSConfig) *Postgres {
	log.Debugf("Using postgres database, connecting to database...")
	return &Postgres{
		datasource: datasource,
		TLS:        clientTLSConfig,
	}
}

// Connect connects to a PostgreSQL server
func (p *Postgres) Connect() error {
	datasource := p.datasource
	clientTLSConfig := p.TLS

	p.dbName = util.GetDBName(datasource)
	dbName := p.dbName
	log.Debugf("Database Name: %s", dbName)

	if strings.Contains(dbName, "-") || strings.HasSuffix(dbName, ".db") {
		return errors.Errorf("Database name '%s' cannot contain any '-' or end with '.db'", dbName)
	}

	if clientTLSConfig.Enabled {
		if len(clientTLSConfig.CertFiles) == 0 {
			return errors.New("No trusted root certificates for TLS were provided")
		}

		root := clientTLSConfig.CertFiles[0]
		datasource = fmt.Sprintf("%s sslrootcert=%s", datasource, root)

		cert := clientTLSConfig.Client.CertFile
		key := clientTLSConfig.Client.KeyFile
		datasource = fmt.Sprintf("%s sslcert=%s sslkey=%s", datasource, cert, key)
	}

	dbNames := []string{dbName, "postgres", "template1"}
	var sqlxdb *sqlx.DB
	var err error

	for _, dbName := range dbNames {
		connStr := getConnStr(datasource, dbName)
		log.Debugf("Connecting to PostgreSQL server, using connection string: %s", util.MaskDBCred(connStr))

		sqlxdb, err = sqlx.Connect("postgres", connStr)
		if err == nil {
			break
		}
		log.Warningf("Failed to connect to database '%s'", dbName)
	}

	if err != nil {
		return errors.Errorf("Failed to connect to Postgres database. Postgres requires connecting to a specific database, the following databases were tried: %s. Please create one of these database before continuing", dbNames)
	}

	p.SqlxDB = sqlxdb
	return nil
}

// Ping pings the database
func (p *Postgres) Ping() error {
	err := p.SqlxDB.Ping()
	if err != nil {
		return errors.Wrap(err, "Failed to ping to Postgres database")
	}
	return nil
}

// Create creates database and tables
func (p *Postgres) Create() (*sqlx.DB, error) {
	db, err := p.CreateDatabase()
	if err != nil {
		return nil, err
	}
	err = p.CreateTables()
	if err != nil {
		return nil, err
	}
	return db, nil
}

// CreateDatabase creates database
func (p *Postgres) CreateDatabase() (*sqlx.DB, error) {
	dbName := p.dbName
	datasource := p.datasource
	err := p.createPostgresDatabase()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres database")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, util.MaskDBCred(datasource))
	sqlxdb, err := sqlx.Open("postgres", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database '%s' in Postgres server", dbName)
	}
	p.SqlxDB = sqlxdb

	return sqlxdb, nil
}

// CreateTables creates table
func (p *Postgres) CreateTables() error {
	err := p.createPostgresTables()
	if err != nil {
		return errors.Wrap(err, "Failed to create Postgres tables")
	}
	return nil
}

func (p *Postgres) createPostgresDatabase() error {
	dbName := p.dbName
	log.Debugf("Creating Postgres Database (%s) if it does not exist...", dbName)

	query := "CREATE DATABASE " + dbName
	_, err := p.SqlxDB.Exec(query)
	if err != nil {
		if !strings.Contains(err.Error(), fmt.Sprintf("database \"%s\" already exists", dbName)) {
			return errors.Wrap(err, "Failed to execute create database query")
		}
	}

	return nil
}

// func (p *Postgres) GetDB() *sqlx.DB {
// 	return p.db
// }

// createPostgresDB creates postgres database
func (p *Postgres) createPostgresTables() error {
	db := p.SqlxDB
	log.Debug("Creating users table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024), level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating certificates table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating credentials table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle bytea NOT NULL, cred bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle))"); err != nil {
		return errors.Wrap(err, "Error creating credentials table")
	}
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY(epoch))"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	log.Debug("Creating nonces table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(255) NOT NULL UNIQUE, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY (val))"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate key") {
			return err
		}
	}
	return nil
}

// GetConnStr gets connection string without database
func getConnStr(datasource string, dbname string) string {
	re := regexp.MustCompile(`(dbname=)([^\s]+)`)
	connStr := re.ReplaceAllString(datasource, fmt.Sprintf("dbname=%s", dbname))
	return connStr
}
