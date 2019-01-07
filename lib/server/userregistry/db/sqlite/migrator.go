/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/user"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/util"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/migratorTx.go -fake-name MigratorTx . MigratorTx

type MigratorTx interface {
	Create
	Get(dest interface{}, query string, args ...interface{}) error
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
}

type Migrator struct {
	Tx        MigratorTx
	CurLevels *util.Levels
	SrvLevels *util.Levels
}

func NewMigrator(tx MigratorTx, curLevels, srvLevels *util.Levels) *Migrator {
	return &Migrator{
		Tx:        tx,
		CurLevels: curLevels,
		SrvLevels: srvLevels,
	}
}

func (m *Migrator) MigrateUsersTable() error {
	tx := m.Tx
	// Future schema updates should add to the logic below to handle other levels
	curLevel := m.CurLevels.Identity
	if curLevel < 1 {
		log.Debug("Upgrade identity table to level 1")
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
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		_, err := tx.Exec("ALTER TABLE users RENAME TO users_old")
		if err != nil {
			return err
		}
		err = createSQLiteIdentityTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level) SELECT id, token, type, affiliation, attributes, state, max_enrollments, level FROM users_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE users_old")
		if err != nil {
			return err
		}
		curLevel++
	}

	users, err := user.GetUserLessThanLevel(tx, m.SrvLevels.Identity)
	if err != nil {
		return err
	}

	for _, u := range users {
		err := u.Migrate(tx)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), m.SrvLevels.Identity)
	if err != nil {
		return err
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current certificates table to certificates_old and then creating a new certificates
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m *Migrator) MigrateCertificatesTable() error {
	tx := m.Tx
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Certificate < 1 {
		log.Debug("Upgrade certificates table to level 1")
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), m.SrvLevels.Certificate)
	if err != nil {
		return err
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current affiliations table to affiliations_old and then creating a new user
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m *Migrator) MigrateAffiliationsTable() error {
	tx := m.Tx
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Affiliation < 1 {
		log.Debug("Upgrade affiliations table to level 1")
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), m.SrvLevels.Affiliation)
	if err != nil {
		return err
	}
	return nil
}

func (m *Migrator) MigrateCredentialsTable() error {
	_, err := m.Tx.Exec(m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'credential.level')"), m.SrvLevels.Credential)
	return err
}
func (m *Migrator) MigrateRAInfoTable() error {
	_, err := m.Tx.Exec(m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'rcinfo.level')"), m.SrvLevels.RAInfo)
	return err
}
func (m *Migrator) MigrateNoncesTable() error {
	_, err := m.Tx.Exec(m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'nonce.level')"), m.SrvLevels.Nonce)
	return err
}

func (m *Migrator) Rollback() error {
	err := m.Tx.Rollback()
	if err != nil {
		log.Errorf("Error encountered while rolling back database migration changes: %s", err)
		return err
	}
	return nil
}

func (m *Migrator) Commit() error {
	err := m.Tx.Commit()
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing database migration changes")
	}
	return nil
}
