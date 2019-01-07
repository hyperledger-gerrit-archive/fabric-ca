/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/user"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/util"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/migratorTx.go -fake-name MigratorTx . MigratorTx

type MigratorTx interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Get(dest interface{}, query string, args ...interface{}) error
	Rebind(query string) string
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
	Select(dest interface{}, query string, args ...interface{}) error
	Rollback() error
	Commit() error
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
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		_, err := tx.Exec("ALTER TABLE users ADD COLUMN incorrect_password_attempts INTEGER DEFAULT 0 AFTER level")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
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

func (m *Migrator) MigrateCertificatesTable() error {
	tx := m.Tx
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Certificate < 1 {
		log.Debug("Upgrade certificates table to level 1")
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
	_, err := tx.Exec(tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), m.SrvLevels.Certificate)
	if err != nil {
		return err
	}
	return nil
}

func (m *Migrator) MigrateAffiliationsTable() error {
	tx := m.Tx
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Affiliation < 1 {
		log.Debug("Upgrade affiliations table to level 1")
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
