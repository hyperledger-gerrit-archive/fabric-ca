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
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

type dbMigrator interface {
	migrateTable(db *DB, tableName string, curLevel int) error
}

func migrateDB(db *DB, srvLevels *Levels) error {
	var migrator dbMigrator
	switch db.DriverName() {
	case "sqlite3":
		migrator = sqliteMigrator{}
	case "mysql":
		migrator = mysqlMigrator{}
	case "postgres":
		migrator = postgresMigrator{}
	default:
		return errors.Errorf("Unsupported database type: %s", db.DriverName())
	}

	log.Debug("Check if database needs to be migrated")
	currentLevels, err := currentDBLevels(db)
	if err != nil {
		return err
	}

	if currentLevels.Identity < srvLevels.Identity {
		log.Debug("Upgrade identities table")
		err := migrator.migrateTable(db, "users", currentLevels.Identity)
		if err != nil {
			return err
		}
	}

	if currentLevels.Affiliation < srvLevels.Affiliation {
		log.Debug("Upgrade affiliation table")
		err := migrator.migrateTable(db, "affiliations", currentLevels.Affiliation)
		if err != nil {
			return err
		}
	}

	if currentLevels.Certificate < srvLevels.Certificate {
		log.Debug("Upgrade certificates table")
		err := migrator.migrateTable(db, "certificates", currentLevels.Certificate)
		if err != nil {
			return err
		}
	}
	return nil
}

type sqliteMigrator struct{}
type mysqlMigrator struct{}
type postgresMigrator struct{}

func (m sqliteMigrator) migrateTable(db *DB, tableName string, curLevel int) error {
	switch tableName {
	case "users":
		return doTransaction(db, m.migrateUsersTable, curLevel)
	case "certificates":
		return doTransaction(db, m.migrateCertificatesTable, curLevel)
	case "affiliations":
		return doTransaction(db, m.migrateAffiliationsTable, curLevel)
	default:
		return errors.Errorf("Don't know how to migrate table %s", tableName)
	}
}

func (m sqliteMigrator) migrateUsersTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE users RENAME TO users_old")
		if err != nil {
			return err
		}
		err = createSQLiteIdentityTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) SELECT id, token, type, affiliation, attributes, state, max_enrollments FROM users_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE users_old")
		if err != nil {
			return err
		}
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current certificates table to certificates_old and then creating a new certificates
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m sqliteMigrator) migrateCertificatesTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE certificates RENAME TO certificates_old")
		if err != nil {
			return err
		}
		err = createSQLiteCertificateTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem) SELECT id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem FROM certificates_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE certificates_old")
		if err != nil {
			return err
		}
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current affiliations table to affiliations_old and then creating a new user
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m sqliteMigrator) migrateAffiliationsTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE affiliations RENAME TO affiliations_old")
		if err != nil {
			return err
		}
		err = createSQLiteAffiliationTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO affiliations (name, prekey) SELECT name, prekey FROM affiliations_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE affiliations_old")
		if err != nil {
			return err
		}
	}
	return nil
}

func (m mysqlMigrator) migrateTable(db *DB, tableName string, curLevel int) error {
	log.Debug("Update MySQL database if using outdated schema")
	switch tableName {
	case "users":
		return doTransaction(db, m.migrateUsersTable, curLevel)
	case "certificates":
		return doTransaction(db, m.migrateCertificatesTable, curLevel)
	case "affiliations":
		return doTransaction(db, m.migrateAffiliationsTable, curLevel)
	default:
		return errors.Errorf("Don't know how to migrate table %s", tableName)
	}
}

func (m mysqlMigrator) migrateUsersTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE users MODIFY id VARCHAR(255), MODIFY type VARCHAR(256), MODIFY affiliation VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec("ALTER TABLE users MODIFY attributes TEXT")
		if err != nil {
			return err
		}
		_, err = tx.Exec("ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0 AFTER max_enrollments")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
	}
	return nil
}

func (m mysqlMigrator) migrateCertificatesTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0 AFTER pem")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec("ALTER TABLE certificates MODIFY id VARCHAR(255)")
		if err != nil {
			return err
		}
	}
	return nil
}

func (m mysqlMigrator) migrateAffiliationsTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0 AFTER prekey")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec("ALTER TABLE affiliations DROP INDEX name;")
		if err != nil {
			if !strings.Contains(err.Error(), "Error 1091") { // Indicates that index not found
				return err
			}
		}
		_, err = tx.Exec("ALTER TABLE affiliations ADD COLUMN id INT NOT NULL PRIMARY KEY AUTO_INCREMENT FIRST")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec("ALTER TABLE affiliations MODIFY name VARCHAR(1024), MODIFY prekey VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec("ALTER TABLE affiliations ADD INDEX name_index (name)")
		if err != nil {
			if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
				return err
			}
		}
	}
	return nil
}

func (m postgresMigrator) migrateTable(db *DB, tableName string, curLevel int) error {
	log.Debug("Update Postgres database if using outdated schema")
	switch tableName {
	case "users":
		return doTransaction(db, m.migrateUsersTable, curLevel)
	case "certificates":
		return doTransaction(db, m.migrateCertificatesTable, curLevel)
	case "affiliations":
		return doTransaction(db, m.migrateAffiliationsTable, curLevel)
	default:
		return errors.Errorf("Don't know how to migrate table %s", tableName)
	}
}

func (m postgresMigrator) migrateUsersTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		_, err := tx.Exec("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(255), ALTER COLUMN type TYPE VARCHAR(256), ALTER COLUMN affiliation TYPE VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec("ALTER TABLE users ALTER COLUMN attributes TYPE TEXT")
		if err != nil {
			return err
		}
		res := []struct {
			columnName string `db:"column_name"`
		}{}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='users' and column_name='level'"
		err = tx.Select(&res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err = tx.Exec("ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
	}
	return nil
}

func (m postgresMigrator) migrateCertificatesTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		res := []struct {
			columnName string `db:"column_name"`
		}{}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='certificates' and column_name='level'"
		err := tx.Select(&res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err := tx.Exec("ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
		_, err = tx.Exec("ALTER TABLE certificates ALTER COLUMN id TYPE VARCHAR(255)")
		if err != nil {
			return err
		}
	}
	return nil
}

func (m postgresMigrator) migrateAffiliationsTable(tx *sqlx.Tx, args ...interface{}) error {
	curLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if curLevel < 1 {
		res := []struct {
			columnName string `db:"column_name"`
		}{}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='affiliations' and column_name='level'"
		err := tx.Select(&res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err := tx.Exec("ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
		_, err = tx.Exec("ALTER TABLE affiliations ALTER COLUMN name TYPE VARCHAR(1024), ALTER COLUMN prekey TYPE VARCHAR(1024)")
		if err != nil {
			return err
		}
	}
	return nil
}
