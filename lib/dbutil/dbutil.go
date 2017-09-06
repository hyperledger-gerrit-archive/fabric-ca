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

package dbutil

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
)

// NewUserRegistrySQLLite3 returns a pointer to a sqlite database
func NewUserRegistrySQLLite3(datasource string) (*sqlx.DB, bool, error) {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", datasource)

	datasource = filepath.Join(datasource)
	exists := false

	if datasource != "" {
		// Check if database exists if not create it and bootstrap it based
		// on the config file
		_, err := os.Stat(datasource)
		if err != nil && os.IsNotExist(err) {
			log.Debugf("Database (%s) does not exist", datasource)
			err2 := createSQLiteDBTables(datasource)
			if err2 != nil {
				return nil, false, errors.WithMessage(err2, "Failed to create SQLite3 database")
			}
		} else {
			// database file exists. If os.Stat returned an error
			// other than IsNotExist error, which still means
			// file exists
			log.Debugf("Database (%s) exists", datasource)
			exists = true
		}
	}

	db, err := sqlx.Open("sqlite3", datasource+"?_busy_timeout=5000")
	if err != nil {
		return nil, false, err
	}

	// Set maximum open connections to one. This is to share one connection
	// across multiple go routines. This will serialize database operations
	// with in a single server there by preventing "database is locked"
	// error under load. The "Database is locked" error is still expected
	// when multiple servers are accessing the same database (but mitigated
	// by specifying _busy_timeout to 5 seconds). Since sqlite is
	// for development and test purposes only, and is not recommended to
	// be used in a clustered topology, setting max open connections to
	// 1 is a quick and effective solution
	// For more info refer to https://github.com/mattn/go-sqlite3/issues/274
	db.SetMaxOpenConns(1)
	log.Debug("Successfully opened sqlite3 DB")

	return db, exists, nil
}

func createSQLiteDBTables(datasource string) error {
	log.Debug("Creating SQLite Database...")
	log.Debug("Database location: ", datasource)
	db, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return errors.Wrap(err, "Failed to open SQLite database")
	}
	defer db.Close()

	log.Debug("Creating tables...")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Created users table")

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Created affiliation table")

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(64), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Created certificates table")

	return nil
}

// NewUserRegistryPostgres opens a connecton to a postgres database
func NewUserRegistryPostgres(datasource string, clientTLSConfig *tls.ClientTLSConfig) (*sqlx.DB, bool, error) {
	log.Debugf("Using postgres database, connecting to database...")

	var exists bool
	dbName := getDBName(datasource)
	log.Debug("Database Name: ", dbName)

	if strings.Contains(dbName, "-") || strings.HasSuffix(dbName, ".db") {
		return nil, false, errors.Errorf("Database name %s cannot contain any '-' or end with '.db'", dbName)
	}

	connStr := getConnStr(datasource)

	if clientTLSConfig.Enabled {
		if len(clientTLSConfig.CertFiles) > 0 {
			root := clientTLSConfig.CertFiles[0]
			connStr = fmt.Sprintf("%s sslrootcert=%s", connStr, root)
		}

		cert := clientTLSConfig.Client.CertFile
		key := clientTLSConfig.Client.KeyFile
		connStr = fmt.Sprintf("%s sslcert=%s sslkey=%s", connStr, cert, key)
	}

	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		return nil, false, errors.Wrap(err, "Failed to open Postgres database")
	}

	err = db.Ping()
	if err != nil {
		return nil, false, errors.Wrap(err, "Failed to connect to Postgres database")
	}

	// Check if database exists
	r, err2 := db.Exec("SELECT * FROM pg_catalog.pg_database where datname=$1", dbName)
	if err2 != nil {
		return nil, false, errors.Wrap(err2, "Failed to query 'pg_database' table")
	}

	found, _ := r.RowsAffected()
	if found == 0 {
		log.Debugf("Database (%s) does not exist", dbName)
		exists = false
		connStr = connStr + " dbname=" + dbName
		err = createPostgresDBTables(connStr, dbName, db)
		if err != nil {
			return nil, false, errors.WithMessage(err, "Failed to create Postgres database")
		}
	} else {
		log.Debugf("Database (%s) exists", dbName)
		exists = true
	}

	db, err = sqlx.Open("postgres", datasource)
	if err != nil {
		return nil, false, err
	}

	return db, exists, nil
}

// createPostgresDB creates postgres database
func createPostgresDBTables(datasource string, dbName string, db *sqlx.DB) error {
	log.Debugf("Creating Postgres Database (%s)...", dbName)
	query := "CREATE DATABASE " + dbName
	_, err := db.Exec(query)
	if err != nil {
		return errors.Wrap(err, "Failed to execute create database query")
	}

	database, err := sqlx.Open("postgres", datasource)
	if err != nil {
		return errors.Wrapf(err, "Failed to open database (%s) in Postgres server", dbName)
	}

	log.Debug("Creating Tables...")
	if _, err := database.Exec("CREATE TABLE users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Created users table")
	if _, err := database.Exec("CREATE TABLE affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Created affiliations table")
	if _, err := database.Exec("CREATE TABLE certificates (id VARCHAR(64), serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Created certificates table")
	return nil
}

// NewUserRegistryMySQL opens a connecton to a postgres database
func NewUserRegistryMySQL(datasource string, clientTLSConfig *tls.ClientTLSConfig, csp bccsp.BCCSP) (*sqlx.DB, bool, error) {
	log.Debugf("Using MySQL database, connecting to database...")

	var exists bool
	dbName := getDBName(datasource)
	log.Debug("Database Name: ", dbName)

	re := regexp.MustCompile(`\/([a-zA-z]+)`)
	connStr := re.ReplaceAllString(datasource, "/")

	if clientTLSConfig.Enabled {
		tlsConfig, err := tls.GetClientTLSConfig(clientTLSConfig, csp)
		if err != nil {
			return nil, false, errors.WithMessage(err, "Failed to get client TLS for MySQL")
		}

		mysql.RegisterTLSConfig("custom", tlsConfig)
	}

	db, err := sqlx.Open("mysql", connStr)
	if err != nil {
		return nil, false, errors.Wrap(err, "Failed to open MySQL database")
	}

	err = db.Ping()
	if err != nil {
		return nil, false, errors.Wrap(err, "Failed to connect to MySQL database")
	}

	// Check if database exists
	var name string
	err = db.QueryRow("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?", dbName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debugf("Database (%s) does not exist", dbName)
			exists = false
		} else {
			return nil, false, errors.Wrap(err, "Failed to query 'INFORMATION_SCHEMA.SCHEMATA table")
		}
	}

	if name == "" {
		err := createMySQLTables(datasource, dbName, db)
		if err != nil {
			return nil, false, errors.WithMessage(err, "Failed to create MySQL database")
		}
	} else {
		log.Debugf("Database (%s) exists", dbName)
		exists = true
	}

	db, err = sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, false, err
	}

	return db, exists, nil
}

func createMySQLTables(datasource string, dbName string, db *sqlx.DB) error {
	log.Debugf("Creating MySQL Database (%s)...", dbName)

	_, err := db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		return errors.Wrap(err, "Failed to execute create database query")
	}

	database, err := sqlx.Open("mysql", datasource)
	if err != nil {
		return errors.Wrapf(err, "Failed to open database (%s) in MySQL server", dbName)
	}
	log.Debug("Creating Tables...")
	if _, err := database.Exec("CREATE TABLE users (id VARCHAR(64) NOT NULL, token blob, type VARCHAR(64), affiliation VARCHAR(64), attributes TEXT, state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Created users table")
	if _, err := database.Exec("CREATE TABLE affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Created affiliations table")
	if _, err := database.Exec("CREATE TABLE certificates (id VARCHAR(64), serial_number varbinary(128) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, pem varbinary(4096) NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Created certificates table")

	return nil
}

// GetDBName gets database name from connection string
func getDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

// GetConnStr gets connection string without database
func getConnStr(datasource string) string {
	re := regexp.MustCompile(`(dbname=)([^\s]+)`)
	connStr := re.ReplaceAllString(datasource, "")
	return connStr
}
