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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"golang.org/x/crypto/bcrypt"

	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Match to sqlx
func init() {
	sqlstruct.TagName = "db"
}

const (
	insertUser = `
INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES (:id, :token, :type, :affiliation, :attributes, :state, :max_enrollments);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
	SET token = :token, type = :type, affiliation = :affiliation, attributes = :attributes, state = :state
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertAffiliation = `
INSERT INTO affiliations (name, prekey)
	VALUES (?, ?)`

	deleteAffiliation = `DELETE FROM affiliations WHERE name LIKE ?`

	getAffiliation = `
SELECT name, prekey FROM affiliations
	WHERE (name = ?)`
)

// UserRecord defines the properties of a user
type UserRecord struct {
	Name           string `db:"id"`
	Pass           []byte `db:"token"`
	Type           string `db:"type"`
	Affiliation    string `db:"affiliation"`
	Attributes     string `db:"attributes"`
	State          int    `db:"state"`
	MaxEnrollments int    `db:"max_enrollments"`
}

// AffiliationRecord an affiliation entry in the database
type AffiliationRecord struct {
	Name   string `db:"name"`
	Parent string `db:"prekey"`
}

// Accessor implements db.Accessor interface.
type Accessor struct {
	db *sqlx.DB
}

// NewDBAccessor is a constructor for the database API
func NewDBAccessor() *Accessor {
	return &Accessor{}
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("Failed to correctly setup database connection")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *sqlx.DB) {
	d.db = db
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user spi.UserInfo) error {
	log.Debugf("DB: Add identity %s", user.Name)

	err := d.checkDB()
	if err != nil {
		return err
	}

	attrBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	// Hash the password before storing it
	pwd := []byte(user.Pass)
	pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Failed to hash password")
	}

	// Store the user record in the DB
	res, err := d.db.NamedExec(insertUser, &UserRecord{
		Name:           user.Name,
		Pass:           pwd,
		Type:           user.Type,
		Affiliation:    user.Affiliation,
		Attributes:     string(attrBytes),
		State:          user.State,
		MaxEnrollments: user.MaxEnrollments,
	})

	if err != nil {
		return errors.Wrapf(err, "Error adding identity '%s' to the database", user.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRowsAffected == 0 {
		return errors.Errorf("Failed to add identity %s to the database", user.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to add one record to the database, but %d records were added", numRowsAffected)
	}

	log.Debugf("Successfully added identity %s to the database", user.Name)

	return nil

}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) error {
	log.Debugf("DB: Delete identity %s", id)
	err := d.checkDB()
	if err != nil {
		return err
	}

	tx := d.db.MustBegin()
	defer txReturnFunc(tx, &err)

	err = deleteUserTx(id, 6, tx) // 6 (cessationofoperation) reason for certificate revocation
	if err != nil {
		return err
	}

	return nil
}

func deleteUserTx(id string, reason int, tx *sqlx.Tx) error {
	_, err := tx.Exec(deleteUser, id)
	if err != nil {
		return err
	}

	var record = new(CertRecord)
	record.ID = id
	record.Reason = reason
	_, err = tx.NamedExec(tx.Rebind(updateRevokeSQL), record)
	if err != nil {
		return err
	}

	return nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user spi.UserInfo) error {
	log.Debugf("DB: Update identity %s", user.Name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal user attributes")
	}

	// Hash the password before storing it
	pwd := []byte(user.Pass)
	pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Failed to hash password")
	}

	// Store the updated user entry
	res, err := d.db.NamedExec(updateUser, &UserRecord{
		Name:           user.Name,
		Pass:           pwd,
		Type:           user.Type,
		Affiliation:    user.Affiliation,
		Attributes:     string(attributes),
		State:          user.State,
		MaxEnrollments: user.MaxEnrollments,
	})

	if err != nil {
		return errors.Wrap(err, "Failed to update identity record")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("Failed to update any identity records")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected one identity record to be updated, but %d records were updated", numRowsAffected)
	}

	return err

}

// ModifyIdentity updates a identity in the database
func (d *Accessor) ModifyIdentity(id, update, newConfig string) error {
	log.Debugf("DB: Update identity '%s' value for '%s'", id, update)
	err := d.checkDB()
	if err != nil {
		return err
	}

	var supportedUpdateReq = map[string]string{
		"secret":         "token",
		"type":           "type",
		"maxenrollments": "max_enrollments",
		"attributes":     "attributes",
		"affiliation":    "affiliation",
	}

	updateReq, validRequest := supportedUpdateReq[update]
	if !validRequest {
		return errors.Errorf("Updating '%s' for a user is not allowed", update)
	}

	tx := d.db.MustBegin()
	defer txReturnFunc(tx, &err)

	// If updating secret, generate a hash for the secret
	transact := func() error {
		if updateReq == "token" {
			pwd := []byte(newConfig)
			pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
			if err != nil {
				return errors.Wrap(err, "Failed to hash password")
			}
			newConfig = string(pwd)
		}

		if updateReq == "attributes" {
			var newAttributes []api.Attribute
			json.Unmarshal([]byte(newConfig), &newAttributes)

			var userRec UserRecord
			err = tx.Get(&userRec, tx.Rebind(getUser), id)
			if err != nil {
				return dbGetError(err, "Failed to get user")
			}
			var attributes []api.Attribute
			json.Unmarshal([]byte(userRec.Attributes), &attributes)
			if len(attributes) != 0 {
				for _, newAttr := range newAttributes {
					for i := range attributes {
						if attributes[i].Name == newAttr.Name {
							attributes[i].Value = newAttr.Value
						} else {
							attributes = append(attributes, newAttr)
						}
					}
				}
			} else {
				attributes = newAttributes
			}

			attrBytes, err := json.Marshal(attributes)
			if err != nil {
				return err
			}
			newConfig = string(attrBytes)
		}

		query := fmt.Sprintf("UPDATE users SET %s = ? where (id = ?)", updateReq)
		res, err := tx.Exec(tx.Rebind(query), newConfig, id)
		if err != nil {
			return err
		}

		numRowsAffected, err := res.RowsAffected()
		if err != nil {
			return errors.Wrap(err, "Failed to get number of rows affected")
		}

		if numRowsAffected == 0 {
			return errors.Errorf("No rows were affected when updating the state of identity %s", id)
		}

		if numRowsAffected != 1 {
			return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
		}
		return nil
	}

	err = transact()
	if err != nil {
		return err
	}

	return nil
}

// GetUser gets user from database
func (d *Accessor) GetUser(id string, attrs []string) (spi.User, error) {
	log.Debugf("DB: Getting identity %s", id)

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var userRec UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return nil, dbGetError(err, "User")
	}

	return d.newDBUser(&userRec), nil
}

// GetUserInfo gets user information from database
func (d *Accessor) GetUserInfo(id string) (spi.UserInfo, error) {
	log.Debugf("DB: Getting information for identity %s", id)

	var userInfo spi.UserInfo

	err := d.checkDB()
	if err != nil {
		return userInfo, err
	}

	var userRec UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return userInfo, dbGetError(err, "User")
	}

	var attributes []api.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attributes)

	userInfo.Name = userRec.Name
	userInfo.Type = userRec.Type
	userInfo.Affiliation = userRec.Affiliation
	userInfo.State = userRec.State
	userInfo.MaxEnrollments = userRec.MaxEnrollments
	userInfo.Attributes = attributes

	return userInfo, nil
}

// InsertAffiliation inserts affiliation into database
func (d *Accessor) InsertAffiliation(name string, prekey string) error {
	log.Debugf("DB: Add affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return err
	}
	dbType := d.db.DriverName()
	// InnoDB store engine for MySQL does not allow more than 767 bytes
	// in a 'UNIQUE' column. To work around this, the UNIQUE constraint was removed
	// from the 'name' column in the affiliations table for MySQL to allow for up to 1024
	// characters to be stored. In doing this, a check is needed on MySQL to check
	// if the affiliation exists before adding it to prevent duplicate entries.
	if dbType == "mysql" {
		aff, _ := d.GetAffiliation(name)
		if aff != nil {
			log.Debugf("Affiliation '%s' already exists", name)
			return nil
		}
	}
	_, err = d.db.Exec(d.db.Rebind(insertAffiliation), name, prekey)
	if err != nil {
		if (!strings.Contains(err.Error(), "UNIQUE constraint failed") && dbType == "sqlite3") || (!strings.Contains(err.Error(), "duplicate key value") && dbType == "postgres") {
			return err
		}
		log.Debugf("Affiliation '%s' already exists", name)
		return nil
	}
	log.Debugf("Affiliation '%s' added", name)

	return nil
}

// DeleteAffiliation deletes affiliation from database
func (d *Accessor) DeleteAffiliation(name string, force bool) error {
	log.Debugf("DB: Delete affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	removeAffs := []string{name, name + ".%"}
	tx := d.db.MustBegin() // Start database transaction
	defer txReturnFunc(tx, &err)

	transact := func() error {
		for _, removeAff := range removeAffs {

			query := "SELECT id FROM users WHERE (affiliation LIKE ?)"
			ids := []string{}
			err = tx.Select(&ids, tx.Rebind(query), removeAff)
			if err != nil {
				return err
			}

			// If force removing of identities is not allowed, only delete affiliation if there are no identities that have that affiliation
			if !force && len(ids) != 0 {
				return errors.Errorf("Affiliation '%s' can't be removed because there are identities that are part of this affiliation", removeAff)
			}

			if force {
				log.Debugf("IDs '%s' to removed based on affiliation '%s' removal", ids, name)
				for _, id := range ids {
					log.Debugf("Removing identity '%s'", id)
					_, err = tx.Exec(tx.Rebind(deleteUser), id)
					if err != nil {
						return err
					}
					err = deleteUserTx(id, 3, tx) // 3 (affiliationchange) reason for certificate revocation
					if err != nil {
						return err
					}
				}
			}

			_, err = tx.Exec(tx.Rebind(deleteAffiliation), removeAff)
			if err != nil {
				return err
			}
		}
		return nil
	}

	err = transact()
	if err != nil {
		return err
	}

	return nil
}

// GetAffiliation gets affiliation from database
func (d *Accessor) GetAffiliation(name string) (spi.Affiliation, error) {
	log.Debugf("DB: Get affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var affiliation spi.AffiliationImpl

	err = d.db.Get(&affiliation, d.db.Rebind(getAffiliation), name)
	if err != nil {
		return nil, dbGetError(err, "Affiliation")
	}

	return &affiliation, nil
}

// ModifyAffiliation renames the affiliation and updates all identities to use the new affiliation
func (d *Accessor) ModifyAffiliation(oldAff, newAff string) error {
	log.Debugf("DB: Modify affiliation from '%s' to '%s'", oldAff, newAff)
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.GetAffiliation(oldAff)
	if err != nil {
		return errors.Errorf("Affiliation '%s' requesting to be modified does not exist", oldAff)
	}

	_, err = d.GetAffiliation(newAff)
	if err == nil {
		return errors.Errorf("Affiliation requested '%s' already exists", newAff)
	}

	tx := d.db.MustBegin() // Start database transaction
	defer txReturnFunc(tx, &err)

	transact := func() error {
		query := "SELECT name, prekey FROM affiliations WHERE (name LIKE ?)"
		var allOldAffiliations []AffiliationRecord
		err = tx.Select(&allOldAffiliations, tx.Rebind(query), oldAff+"%")
		if err != nil {
			return err
		}

		log.Debugf("Affiliations to be modified %+v", allOldAffiliations)

		for _, affiliation := range allOldAffiliations {
			oldPath := affiliation.Name
			oldParentPath := affiliation.Parent
			newPath := strings.Replace(oldPath, oldAff, newAff, 1)
			newParentPath := strings.Replace(oldParentPath, oldAff, newAff, 1)
			log.Debugf("oldPath: %s, newPath: %s, oldParentPath: %s, newParentPath: %s", oldPath, newPath, oldParentPath, newParentPath)

			query = "Update affiliations SET name = ?, prekey = ? WHERE (name = ?)"
			res := tx.MustExec(tx.Rebind(query), newPath, newParentPath, oldPath)
			numRowsAffected, err := res.RowsAffected()
			if err != nil {
				return errors.Errorf("Failed to get number of rows affected")
			}
			if numRowsAffected == 0 {
				return errors.Errorf("Failed to update any affiliation records for '%s'", oldPath)
			}

			query = "SELECT id FROM users WHERE (affiliation = ?)"
			var idsWithOldAff []string
			err = tx.Select(&idsWithOldAff, tx.Rebind(query), oldPath)
			if err != nil {
				return err
			}

			if len(idsWithOldAff) != 0 {
				log.Debugf("Identities %s to be updated to use new affiliation of '%s' from '%s'", idsWithOldAff, newPath, oldPath)
			}

			for _, id := range idsWithOldAff {
				query = "Update users SET affiliation = ? WHERE (id = ?)"
				res := tx.MustExec(tx.Rebind(query), newPath, id)
				numRowsAffected, err := res.RowsAffected()
				if err != nil {
					return errors.Errorf("Failed to get number of rows affected")
				}
				if numRowsAffected == 0 {
					return errors.Errorf("Failed to update identities record for '%s'", id)
				}
			}
		}
		return nil
	}

	err = transact()
	if err != nil {
		return err
	}

	return nil
}

// Creates a DBUser object from the DB user record
func (d *Accessor) newDBUser(userRec *UserRecord) *DBUser {
	var user = new(DBUser)
	user.Name = userRec.Name
	user.pass = userRec.Pass
	user.State = userRec.State
	user.MaxEnrollments = userRec.MaxEnrollments
	user.Affiliation = userRec.Affiliation
	user.Type = userRec.Type

	var attrs []api.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attrs)
	user.Attributes = attrs

	user.attrs = make(map[string]string)
	for _, attr := range attrs {
		user.attrs[attr.Name] = attr.Value
	}

	user.db = d.db
	return user
}

// DBUser is the databases representation of a user
type DBUser struct {
	spi.UserInfo
	pass  []byte
	attrs map[string]string
	db    *sqlx.DB
}

// GetName returns the enrollment ID of the user
func (u *DBUser) GetName() string {
	return u.Name
}

// Login the user with a password
func (u *DBUser) Login(pass string, caMaxEnrollments int) error {
	log.Debugf("DB: Login user %s with max enrollments of %d and state of %d", u.Name, u.MaxEnrollments, u.State)

	// Check the password by comparing to stored hash
	err := bcrypt.CompareHashAndPassword(u.pass, []byte(pass))
	if err != nil {
		return errors.Wrap(err, "Password mismatch")
	}

	if u.MaxEnrollments == 0 {
		return errors.Errorf("Zero is an invalid value for maximum enrollments on identity '%s'", u.Name)
	}

	if u.State == -1 {
		return errors.Errorf("User %s is revoked; access denied", u.Name)
	}

	// If max enrollment value of user is greater than allowed by CA, using CA max enrollment value for user
	if u.MaxEnrollments > caMaxEnrollments || (u.MaxEnrollments == -1 && caMaxEnrollments != -1) {
		log.Debugf("Max enrollment value (%d) of identity is greater than allowed by CA, using CA max enrollment value of %d", u.MaxEnrollments, caMaxEnrollments)
		u.MaxEnrollments = caMaxEnrollments
	}

	// If maxEnrollments is set to -1, user has unlimited enrollment
	// If the maxEnrollments is set (i.e. >= 1), make sure we haven't exceeded this number of logins.
	// The state variable keeps track of the number of previously successful logins.
	if u.MaxEnrollments != -1 && u.State >= u.MaxEnrollments {
		return errors.Errorf("The identity %s has already enrolled %d times, it has reached its maximum enrollment allowance", u.Name, u.MaxEnrollments)
	}

	log.Debugf("DB: identity %s successfully logged in", u.Name)

	return nil

}

// LoginComplete completes the login process by incrementing the state of the user
func (u *DBUser) LoginComplete() error {
	var stateUpdateSQL string
	var args []interface{}
	var err error

	state := u.State + 1
	args = append(args, u.Name)
	if u.MaxEnrollments == -1 {
		// unlimited so no state check
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ?)"
	} else {
		// state must be less than max enrollments
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ? AND state < ?)"
		args = append(args, u.MaxEnrollments)
	}
	res, err := u.db.Exec(u.db.Rebind(stateUpdateSQL), args...)
	if err != nil {
		return errors.Wrapf(err, "Failed to update state of identity %s to %d", u.Name, state)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	log.Debugf("Successfully incremented state for identity %s to %d", u.Name, state)
	return nil

}

// GetAffiliationPath returns the complete path for the user's affiliation.
func (u *DBUser) GetAffiliationPath() []string {
	affiliationPath := strings.Split(u.Affiliation, ".")
	return affiliationPath
}

// GetAttribute returns the value for an attribute name
func (u *DBUser) GetAttribute(name string) (string, error) {
	value, hasAttr := u.attrs[name]
	if !hasAttr {
		return "", errors.Errorf("User does not have attribute '%s'", name)
	}
	return value, nil
}

// GetAttributes returns the requested attributes
func (u *DBUser) GetAttributes(attrNames []string) []tcert.Attribute {
	var attrs []tcert.Attribute
	for _, name := range attrNames {
		value := u.attrs[name]
		attrs = append(attrs, tcert.Attribute{Name: name, Value: value})
	}
	return attrs
}

func dbGetError(err error, prefix string) error {
	if err.Error() == "sql: no rows in result set" {
		return errors.Errorf("%s not found", prefix)
	}
	return err
}

func txReturnFunc(tx *sqlx.Tx, err *error) error {
	if *err != nil {
		log.Debugf("Rolling back transaction, error ocurred: %s", *err)
		tx.Rollback()
		return *err
	}
	cerr := tx.Commit()
	if cerr != nil {
		log.Debug("Transaction failed to commit")
		*err = cerr
		return *err
	}
	log.Debug("Transaction committed")
	return nil
}
