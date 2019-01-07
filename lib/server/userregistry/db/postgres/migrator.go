/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

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
	res := []struct {
		columnName string `db:"column_name"`
	}{}
	if curLevel < 1 {
		log.Debug("Upgrade identity table to level 1")
		_, err := tx.Exec("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(255), ALTER COLUMN type TYPE VARCHAR(256), ALTER COLUMN affiliation TYPE VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec("ALTER TABLE users ALTER COLUMN attributes TYPE TEXT")
		if err != nil {
			return err
		}
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
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='users' and column_name='incorrect_password_attempts'"
		err := tx.Select(&res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err = tx.Exec("ALTER TABLE users ADD COLUMN incorrect_password_attempts INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
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
