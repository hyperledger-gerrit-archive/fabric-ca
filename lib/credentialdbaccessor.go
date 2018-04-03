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

package lib

import (
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"

	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
)

const (
	insertCredentialSQL = `
INSERT INTO credentials (id, revocation_handle, cred, ca_label, status, reason, expiry, revoked_at, level)
	VALUES (:id, :revocation_handle, :cred, :ca_label, :status, :reason, :expiry, :revoked_at, :level);`

	selectCredentialByIDSQL = `
SELECT %s FROM credentials
WHERE (id = ?);`

	selectCredentialSQL = `
SELECT %s FROM credentials
WHERE (revocation_handle = ?);`

	updateRevokeCredentialSQL = `
UPDATE credentials
SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason=:reason
WHERE (id = :id AND status != 'revoked');`

	deleteCredentialbyID = `
DELETE FROM credentials
		WHERE (id = ?);`
)

// CredentialRecord represents a credential database record
type CredentialRecord struct {
	ID               string    `db:"id"`
	RevocationHandle string    `db:"revocation_handle"`
	Cred             string    `db:"cred"`
	CALabel          string    `db:"ca_label"`
	Status           string    `db:"status"`
	Reason           int       `db:"reason"`
	Expiry           time.Time `db:"expiry"`
	RevokedAt        time.Time `db:"revoked_at"`
	Level            int       `db:"level"`
}

// CredDBAccessor accessor for credentials database table
type CredDBAccessor interface {
	InsertCredential(cr CredentialRecord) error
	GetCredential(revocationHandle string) ([]CredentialRecord, error)
	GetUnexpiredCredentials() ([]CredentialRecord, error)
	GetRevokedAndUnexpiredCredentials() ([]CredentialRecord, error)
	GetRevokedAndUnexpiredCredentialsByLabel(label string) ([]CredentialRecord, error)
	RevokeCredential(revocationHandle string, reasonCode int) error
}

// CredDBAccessor implements
type credDBAccessor struct {
	level int
	db    *sqlx.DB
}

// newCredDBAccessor returns a new Accessor.
func newCredDBAccessor(db *sqlx.DB, level int) *credDBAccessor {
	accessor := new(credDBAccessor)
	accessor.db = db
	accessor.level = level
	return accessor
}

func (d *credDBAccessor) checkDB() error {
	if d.db == nil {
		return errors.New("Database is not set")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *credDBAccessor) SetDB(db *sqlx.DB) {
	d.db = db
}

// InsertCredential puts a CredentialRecord into db.
func (d *credDBAccessor) InsertCredential(cr CredentialRecord) error {

	log.Debug("DB: Insert Credential")

	err := d.checkDB()
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(insertCredentialSQL, cr)
	if err != nil {
		return errors.Wrap(err, "Failed to insert record into database")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("Failed to insert the credential record; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in credentials table but affected %d",
			numRowsAffected)
	}

	return err
}

// GetCredentialsByID gets a CredentialRecord indexed by id.
func (d *credDBAccessor) GetCredentialsByID(id string) (crs []CredentialRecord, err error) {
	log.Debugf("DB: Get credential by ID (%s)", id)
	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	err = d.db.Select(&crs, fmt.Sprintf(d.db.Rebind(selectCredentialByIDSQL), sqlstruct.Columns(CredentialRecord{})), id)
	if err != nil {
		return nil, err
	}

	return crs, nil
}

// GetCredential gets a CredentialRecord indexed by revocationHandle.
func (d *credDBAccessor) GetCredential(revocationHandle string) (crs []CredentialRecord, err error) {
	log.Debugf("DB: Get credential by revocation handle (%s)", revocationHandle)
	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	err = d.db.Select(&crs, fmt.Sprintf(d.db.Rebind(selectCredentialSQL), sqlstruct.Columns(CredentialRecord{})), revocationHandle)
	if err != nil {
		return nil, err
	}

	return crs, nil
}

func (d *credDBAccessor) GetUnexpiredCredentials() ([]CredentialRecord, error) {
	return nil, errors.New("GetUnexpiredCredentials Not implemented")
}
func (d *credDBAccessor) GetRevokedAndUnexpiredCredentials() ([]CredentialRecord, error) {
	return nil, errors.New("GetRevokedAndUnexpiredCredentials Not implemented")
}
func (d *credDBAccessor) GetRevokedAndUnexpiredCredentialsByLabel(label string) ([]CredentialRecord, error) {
	return nil, errors.New("GetRevokedAndUnexpiredCredentialsByLabel Not implemented")
}
func (d *credDBAccessor) RevokeCredential(revocationHandle string, reasonCode int) error {
	return nil
}
