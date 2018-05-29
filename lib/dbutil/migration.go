/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dbutil

import (
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/pkg/errors"
)

type dbMigrator interface {
	migrateUsersTable(tx FabricCATx, curLevel, srvLevel int) error
	migrateCertificatesTable(tx FabricCATx, curLevel, srvLevel int) error
	migrateAffiliationsTable(tx FabricCATx, curLevel, srvLevel int) error
	migrateCredentialsTable(tx FabricCATx, curLevel, srvLevel int) error
	migrateRAInfoTable(tx FabricCATx, curLevel, srvLevel int) error
	migrateNoncesTable(tx FabricCATx, curLevel, srvLevel int) error
}

// MigrateDB updates the database tables to use the latest schema and does
// data migration if needed
func MigrateDB(db *DB, srvLevels *Levels) error {
	var migrator dbMigrator
	switch db.DriverName() {
	case "sqlite3":
		migrator = sqliteMigrator{db}
	case "mysql":
		migrator = mysqlMigrator{db}
	case "postgres":
		migrator = postgresMigrator{db}
	default:
		return errors.Errorf("Unsupported database type: %s", db.DriverName())
	}

	log.Debug("Getting current levels to check if any tables need to be migrated")
	currentLevels, err := CurrentDBLevels(db)
	if err != nil {
		return err
	}

	rollback := func(tx FabricCATx) error {
		err := tx.Rollback()
		if err != nil {
			log.Errorf("Error encountered while rolling back database migration changes: %s", err)
			return err
		}
		return nil
	}

	tx := db.BeginTx()
	if currentLevels.Identity < srvLevels.Identity {
		log.Debug("Migrating identities table...")
		err := migrator.migrateUsersTable(tx, currentLevels.Identity, srvLevels.Identity)
		if err != nil {
			log.Errorf("Error encountered while migrating users table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	if currentLevels.Affiliation < srvLevels.Affiliation {
		log.Debug("Migrating affiliation table...")
		err := migrator.migrateAffiliationsTable(tx, currentLevels.Affiliation, srvLevels.Affiliation)
		if err != nil {
			log.Errorf("Error encountered while migrating affiliations table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	if currentLevels.Certificate < srvLevels.Certificate {
		log.Debug("Upgrade certificates table...")
		err := migrator.migrateCertificatesTable(tx, currentLevels.Certificate, srvLevels.Certificate)
		if err != nil {
			log.Errorf("Error encountered while migrating certificates table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	if currentLevels.Credential < srvLevels.Credential {
		log.Debug("Migrating credentials table...")
		err := migrator.migrateCredentialsTable(tx, currentLevels.Credential, srvLevels.Credential)
		if err != nil {
			log.Errorf("Error encountered while migrating credentials table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	if currentLevels.Nonce < srvLevels.Nonce {
		log.Debug("Migrating nonces table...")
		err := migrator.migrateNoncesTable(tx, currentLevels.Nonce, srvLevels.Nonce)
		if err != nil {
			log.Errorf("Error encountered while migrating nonces table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	if currentLevels.RAInfo < srvLevels.RAInfo {
		log.Debug("Migrating revocation_authority_info table...")
		err := migrator.migrateRAInfoTable(tx, currentLevels.RAInfo, srvLevels.RAInfo)
		if err != nil {
			log.Errorf("Error encountered while migrating revocation_authority_info table, rolling back changes: %s", err)
			rollback(tx)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing database migration changes")
	}
	return nil
}

type sqliteMigrator struct{ db *DB }
type mysqlMigrator struct{ db *DB }
type postgresMigrator struct{ db *DB }

func (m sqliteMigrator) migrateUsersTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	err := migrateUsers(tx, srvLevel)
	if err != nil {
		return err
	}
	_, err = tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current certificates table to certificates_old and then creating a new certificates
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m sqliteMigrator) migrateCertificatesTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current affiliations table to affiliations_old and then creating a new user
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m sqliteMigrator) migrateAffiliationsTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m sqliteMigrator) migrateCredentialsTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'credential.level')"), srvLevel)
	return err
}
func (m sqliteMigrator) migrateRAInfoTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'rcinfo.level')"), srvLevel)
	return err
}
func (m sqliteMigrator) migrateNoncesTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'nonce.level')"), srvLevel)
	return err
}

func (m mysqlMigrator) migrateUsersTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	err := migrateUsers(tx, srvLevel)
	if err != nil {
		return err
	}
	_, err = tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m mysqlMigrator) migrateCertificatesTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m mysqlMigrator) migrateAffiliationsTable(tx FabricCATx, curLevel, srvLevel int) error {
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

	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), srvLevel)
	if err != nil {
		return err
	}

	return nil
}

func (m mysqlMigrator) migrateCredentialsTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'credential.level')"), srvLevel)
	return err
}
func (m mysqlMigrator) migrateRAInfoTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'rcinfo.level')"), srvLevel)
	return err
}
func (m mysqlMigrator) migrateNoncesTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'nonce.level')"), srvLevel)
	return err
}

func (m postgresMigrator) migrateUsersTable(tx FabricCATx, curLevel int, srvLevel int) error {
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
	err := migrateUsers(tx, srvLevel)
	if err != nil {
		return err
	}
	_, err = tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m postgresMigrator) migrateCertificatesTable(tx FabricCATx, curLevel, srvLevel int) error {
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m postgresMigrator) migrateAffiliationsTable(tx FabricCATx, curLevel, srvLevel int) error {
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), srvLevel)
	if err != nil {
		return err
	}
	return nil
}

func (m postgresMigrator) migrateCredentialsTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'credential.level')"), srvLevel)
	return err
}
func (m postgresMigrator) migrateRAInfoTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'rcinfo.level')"), srvLevel)
	return err
}
func (m postgresMigrator) migrateNoncesTable(tx FabricCATx, curLevel, srvLevel int) error {
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'nonce.level')"), srvLevel)
	return err
}

func migrateUsers(tx FabricCATx, userLevel int) error {
	log.Debug("Checking and performing migration of user table data, if needed")
	users, err := getUserLessThanLevel(tx, userLevel)
	if err != nil {
		return err
	}

	for _, user := range users {
		currentLevel := user.GetLevel()
		if currentLevel < 1 {
			err := migrateUserToLevel1(tx, user)
			if err != nil {
				return err
			}
			currentLevel++
		}
	}

	return nil
}

// getUserLessThanLevel returns all identities that are less than the level specified
// Otherwise, returns no users if requested level is zero
func getUserLessThanLevel(tx FabricCATx, level int) ([]*DBUser, error) {
	if level == 0 {
		return []*DBUser{}, nil
	}

	rows, err := tx.Queryx(tx.Rebind("SELECT * FROM users WHERE (level < ?) OR (level IS NULL)"), level)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get identities that need to be updated")
	}

	allUsers := []*DBUser{}

	for rows.Next() {
		var user UserRecord
		rows.StructScan(&user)
		dbUser := NewDBUser(&user, nil)
		allUsers = append(allUsers, dbUser)
	}

	return allUsers, nil
}

func migrateUserToLevel1(tx FabricCATx, user *DBUser) error {
	log.Debugf("Migrating user '%s' to level 1", user.GetName())

	// Update identity to level 1
	_, err := user.GetAttribute("hf.Registrar.Roles") // Check if user a registrar
	if err == nil {
		_, err := user.GetAttribute("hf.Registrar.Attributes") // Check if user already has "hf.Registrar.Attributes" attribute
		if err != nil {
			addAttr := []api.Attribute{api.Attribute{Name: "hf.Registrar.Attributes", Value: "*"}}
			err := user.ModifyAttributesTx(tx, addAttr)
			if err != nil {
				return errors.WithMessage(err, "Failed to set attribute")
			}
		}
	}

	err = user.SetLevelTx(tx, 1)
	if err != nil {
		return errors.WithMessage(err, "Failed to update level of user")
	}

	return nil
}
