/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/util"
	"github.com/jmoiron/sqlx"
)

//go:generate counterfeiter -o mocks/fabricCaDb.go -fake-name FabricCADB . FabricCADB

// FabricCADB is the interface that wrapper off SqlxDB
type FabricCADB interface {
	SqlxDB

	IsInitialized() bool
	SetDBInitialized(bool)
	// BeginTx has same behavior as MustBegin except it returns FabricCATx
	// instead of *sqlx.Tx
	BeginTx() FabricCATx
}

//go:generate counterfeiter -o mocks/sqlxDB.go -fake-name SqlxDB . SqlxDB

// SqlxDB is the interface with functions implemented by sqlx.DB
// object that are used by Fabric CA server
type SqlxDB interface {
	DriverName() string
	Select(dest interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
	NamedExec(query string, arg interface{}) (sql.Result, error)
	Get(dest interface{}, query string, args ...interface{}) error
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
	Rebind(query string) string
	MustBegin() *sqlx.Tx
	Close() error
	SetMaxOpenConns(n int)
	Ping() error
}

// CertRecord extends CFSSL CertificateRecord by adding an enrollment ID to the record
type CertRecord struct {
	ID    string `db:"id"`
	Level int    `db:"level"`
	certdb.CertificateRecord
}

// AffiliationRecord defines the properties of an affiliation
type AffiliationRecord struct {
	ID     int    `db:"id"`
	Name   string `db:"name"`
	Prekey string `db:"prekey"`
	Level  int    `db:"level"`
}

// DB is an adapter for sqlx.DB and implements FabricCADB interface
type DB struct {
	DB SqlxDB
	// Indicates if database was successfully initialized
	IsDBInitialized bool
}

// New creates an instance of DB
func New(db SqlxDB) *DB {
	return &DB{
		DB: db,
	}
}

// IsInitialized returns true if db is intialized, else false
func (db *DB) IsInitialized() bool {
	return db.IsDBInitialized
}

// SetDBInitialized sets the value for Isdbinitialized
func (db *DB) SetDBInitialized(b bool) {
	db.IsDBInitialized = b
}

// BeginTx implements BeginTx method of FabricCADB interface
func (db *DB) BeginTx() FabricCATx {
	return &TX{
		TX: db.DB.MustBegin(),
	}
}

// Select performs select sql statement
func (db *DB) Select(dest interface{}, query string, args ...interface{}) error {
	return db.DB.Select(dest, query, args...)
}

// Exec executes query
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.DB.Exec(query, args...)
}

// NamedExec executes query
func (db *DB) NamedExec(query string, args interface{}) (sql.Result, error) {
	return db.DB.NamedExec(query, args)
}

// Get executes query
func (db *DB) Get(dest interface{}, query string, args ...interface{}) error {
	return db.DB.Get(dest, query, args...)
}

// Queryx executes query
func (db *DB) Queryx(query string, args ...interface{}) (*sqlx.Rows, error) {
	return db.DB.Queryx(query, args...)
}

// MustBegin starts a transaction
func (db *DB) MustBegin() *sqlx.Tx {
	return db.DB.MustBegin()
}

// DriverName returns database driver name
func (db *DB) DriverName() string {
	return db.DB.DriverName()
}

// Rebind parses query to properly format query
func (db *DB) Rebind(query string) string {
	return db.DB.Rebind(query)
}

// Close closes db
func (db *DB) Close() error {
	return db.DB.Close()
}

// SetMaxOpenConns sets number of max open connections
func (db *DB) SetMaxOpenConns(n int) {
	db.DB.SetMaxOpenConns(n)
}

// Ping pings the database
func (db *DB) Ping() error {
	return db.DB.Ping()
}

// CurrentDBLevels returns current levels from the database
func CurrentDBLevels(db FabricCADB) (*util.Levels, error) {
	var err error
	var identityLevel, affiliationLevel, certificateLevel, credentialLevel, rcinfoLevel, nonceLevel int

	err = getProperty(db, "identity.level", &identityLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "affiliation.level", &affiliationLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "certificate.level", &certificateLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "credential.level", &credentialLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "rcinfo.level", &rcinfoLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "nonce.level", &nonceLevel)
	if err != nil {
		return nil, err
	}
	return &util.Levels{
		Identity:    identityLevel,
		Affiliation: affiliationLevel,
		Certificate: certificateLevel,
		Credential:  credentialLevel,
		RAInfo:      rcinfoLevel,
		Nonce:       nonceLevel,
	}, nil
}

func getProperty(db FabricCADB, propName string, val *int) error {
	err := db.Get(val, db.Rebind("Select value FROM properties WHERE (property = ?)"), propName)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return nil
	}
	return err
}
