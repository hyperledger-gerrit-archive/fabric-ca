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
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
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
	SET token = :token, type = :type, affiliation = :affiliation, attributes = :attributes, state = :state, max_enrollments = :max_enrollments
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertAffiliation = `
INSERT INTO affiliations (name, prekey)
	VALUES (?, ?)`

	deleteAffiliation = `
DELETE FROM affiliations
	WHERE (name = ?)`

	getAffiliationQuery = `
SELECT name, prekey FROM affiliations
	WHERE (name = ?)`

	getAllAffiliationsQuery = `
SELECT * FROM affiliations
		WHERE (name like ?)`
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
func (d *Accessor) InsertUser(user *spi.UserInfo) error {
	if user == nil {
		return errors.New("User is not defined")
	}
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
func (d *Accessor) DeleteUser(id string) (*spi.DbTxResult, error) {
	log.Debugf("DB: Delete identity %s", id)

	_, err := d.doTransaction(deleteUserTx, id)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func deleteUserTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	id := args[0].(string)
	_, err := tx.Exec(tx.Rebind(deleteUser), id)
	if err != nil {
		return nil, errors.Wrapf(err, "Error deleting identity '%s'", id)
	}

	_, err = tx.Exec(tx.Rebind(deleteCertificatebyID), id)
	if err != nil {
		return nil, errors.Wrapf(err, "Error deleting certificates for '%s'", id)
	}

	return nil, nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user *spi.UserInfo, updatePass bool) error {
	if user == nil {
		return errors.New("User is not defined")
	}

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
	if updatePass {
		pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
		if err != nil {
			return errors.Wrap(err, "Failed to hash password")
		}
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
		return nil, getError(err, "User")
	}

	return d.newDBUser(&userRec), nil
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

// DeleteAffiliation deletes affiliation from database. Using the force option with identity removal allowed
// this will also delete the identities associated with removed affiliations, and also delete the certificates
// for the identities removed
func (d *Accessor) DeleteAffiliation(name string, force, identityRemoval, isRegistrar bool) (*spi.DbTxResult, error) {
	log.Debugf("DB: Delete affiliation %s", name)

	_, err := d.GetAffiliation(name)
	if err != nil {
		return nil, err
	}

	result, err := d.doTransaction(d.deleteAffiliationTx, name, force, identityRemoval, isRegistrar)
	if err != nil {
		return nil, err
	}

	deletedInfo := result.(*spi.DbTxResult)

	return deletedInfo, nil
}

func (d *Accessor) deleteAffiliationTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	var err error

	name := args[0].(string)
	force := args[1].(bool)
	identityRemoval := args[2].(bool)
	isRegistar := args[3].(bool)

	query := "SELECT * FROM users WHERE (affiliation = ?)"
	ids := []UserRecord{}
	err = tx.Select(&ids, tx.Rebind(query), name)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to select users with affiliation '%s': %s", name, err)
	}

	subAffName := name + ".%"
	query = "SELECT * FROM users WHERE (affiliation LIKE ?)"
	subAffIds := []UserRecord{}
	err = tx.Select(&subAffIds, tx.Rebind(query), subAffName)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to select users with sub-affiliation of '%s': %s", name, err)
	}

	ids = append(ids, subAffIds...)
	idNames := []string{}
	for _, id := range ids {
		idNames = append(idNames, id.Name)
	}
	idNamesStr := strings.Join(idNames, ",")

	if len(ids) > 0 {
		if !isRegistar {
			return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Removing affiliation affects identities, but caller is not a registrar")
		}

		// Force enabled, delete any associated identities and certificates
		if force {
			log.Debugf("IDs '%s' to removed based on affiliation '%s' removal", idNamesStr, name)

			if !identityRemoval {
				return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Identity removal is not allowed on server")
			}

			// Delete all the identities in one database request
			query := "DELETE FROM users WHERE (id IN (?))"
			inQuery, args, err := sqlx.In(query, idNames)
			if err != nil {
				return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to construct query '%s': %s", query, err)
			}
			_, err = tx.Exec(tx.Rebind(inQuery), args...)
			if err != nil {
				return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to execute query '%s' for multiple identity removal: %s", query, err)
			}

			// Delete all the certificates associated with the removed identities above
			query = "DELETE FROM certificates WHERE (id IN (?))"
			inQuery, args, err = sqlx.In(query, idNames)
			if err != nil {
				return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to construct query '%s': %s", query, err)
			}
			_, err = tx.Exec(tx.Rebind(inQuery), args...)
			if err != nil {
				return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to execute query '%s' for multiple certificate removal: %s", query, err)
			}
		} else {
			// If force option is not specified, only delete affiliation if there are no identities that have that affiliation
			return nil, newAuthErr(ErrUpdateConfigRemoveAff, "The request to remove affiliation '%s' has the following identities associated: %s. Need to use 'force' to remove identities and affiliation", name, idNamesStr)
		}
	}

	aff := spi.AffiliationImpl{}
	err = tx.Get(&aff, tx.Rebind(getAffiliationQuery), name)
	if err != nil {
		return nil, getError(err, "Affiliation")
	}
	// Getting all the sub-affiliations that are going to be deleted
	allAffs := []spi.AffiliationImpl{}
	err = tx.Select(&allAffs, tx.Rebind("Select * FROM affiliations where (name LIKE ?)"), subAffName)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to select sub-affiliations of '%s': %s", allAffs, err)
	}
	allAffs = append(allAffs, aff)
	log.Debug("All affiliations to be removed: ", allAffs)

	// Delete the requested affiliation
	_, err = tx.Exec(tx.Rebind(deleteAffiliation), name)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to delete affiliation '%s': %s", name, err)
	}
	// Delete all the sub-affiliations
	_, err = tx.Exec(tx.Rebind("DELETE FROM affiliations where (name LIKE ?)"), subAffName)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveAffDB, "Failed to delete affiliations: %s", err)
	}

	// Return the identities and affiliations that were removed
	result := getResult(ids, allAffs, d)

	return result, nil
}

// GetAffiliation gets affiliation from database
func (d *Accessor) GetAffiliation(name string) (spi.Affiliation, error) {
	log.Debugf("DB: Get affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var affiliation spi.AffiliationImpl

	err = d.db.Get(&affiliation, d.db.Rebind(getAffiliationQuery), name)
	if err != nil {
		return nil, getError(err, "Affiliation")
	}

	return &affiliation, nil
}

// GetAllAffiliations gets the requested affiliation and any sub affiliations from the database
func (d *Accessor) GetAllAffiliations(name string) ([]spi.Affiliation, error) {
	log.Debugf("DB: Get affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var baseAffiliation spi.AffiliationImpl
	var affiliations []spi.AffiliationImpl
	var allAffiliations []spi.Affiliation

	if name == "" { // Requesting all affiliations
		err = d.db.Select(&affiliations, d.db.Rebind("SELECT * FROM affiliations"))
		if err != nil {
			return nil, err
		}
	} else {
		err = d.db.Get(&baseAffiliation, d.db.Rebind(getAffiliationQuery), name)
		if err != nil {
			return nil, getError(err, "Affiliation")
		}
		err = d.db.Select(&affiliations, d.db.Rebind(getAllAffiliationsQuery), name+".%")
		if err != nil {
			return nil, err
		}
		allAffiliations = append(allAffiliations, &baseAffiliation)
	}

	for _, aff := range affiliations {
		allAffiliations = append(allAffiliations, &spi.AffiliationImpl{
			Name:   aff.Name,
			Prekey: aff.Prekey,
		})
	}

	return allAffiliations, nil
}

// GetFilteredUsers returns all identities that fall under the affiliation and types
func (d *Accessor) GetFilteredUsers(affiliation, types string) ([]spi.User, error) {
	log.Debugf("DB: Get all identities per affiliation '%s' and types '%s'", affiliation, types)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	typesArray := strings.Split(types, ",")
	for i := range typesArray {
		typesArray[i] = strings.TrimSpace(typesArray[i])
	}

	var ids, subAffIds []UserRecord

	if affiliation == "" {
		query := "SELECT * FROM users WHERE (type IN (?))"
		query, args, err := sqlx.In(query, typesArray)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		err = d.db.Select(&ids, d.db.Rebind(query), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
	} else {
		query := "SELECT * FROM users WHERE (affiliation LIKE ?) AND (type IN (?))"
		inQuery, args, err := sqlx.In(query, affiliation, typesArray)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		err = d.db.Select(&ids, d.db.Rebind(inQuery), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		affiliation := affiliation + ".%"
		inQuery, args, err = sqlx.In(query, affiliation, typesArray)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		err = d.db.Select(&subAffIds, d.db.Rebind(inQuery), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
	}

	log.Debug("IDs of appropriate affiliations and type: ", ids)

	ids = append(ids, subAffIds...)
	allIds := []spi.User{}

	for _, id := range ids {
		dbUser := d.newDBUser(&id)
		allIds = append(allIds, dbUser)
	}

	return allIds, nil
}

// ModifyAffiliation renames the affiliation and updates all identities to use the new affiliation depending on
// the value of the "force" parameter
func (d *Accessor) ModifyAffiliation(oldAffiliation, newAffiliation string, force, isRegistrar bool) (*spi.DbTxResult, error) {
	log.Debugf("DB: Modify affiliation from '%s' to '%s'", oldAffiliation, newAffiliation)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	// Check to see if the affiliation being modifies exists in the affiliation table
	_, err = d.GetAffiliation(oldAffiliation)
	if err != nil {
		return nil, err
	}

	// Check to see if the new affiliation being requested exists in the affiliation table
	_, err = d.GetAffiliation(newAffiliation)
	if err == nil {
		return nil, newHTTPErr(400, ErrUpdateConfigModifyAff, "Affiliation '%s' already exists", newAffiliation)
	}

	result, err := d.doTransaction(d.modifyAffiliationTx, oldAffiliation, newAffiliation, force, isRegistrar)
	if err != nil {
		return nil, err
	}

	modifiedInfo := result.(*spi.DbTxResult)

	return modifiedInfo, nil
}

func (d *Accessor) modifyAffiliationTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	oldAffiliation := args[0].(string)
	newAffiliation := args[1].(string)
	force := args[2].(bool)
	isRegistar := args[3].(bool)

	// Get the affiliation record
	query := "SELECT name, prekey FROM affiliations WHERE (name = ?)"
	var oldAffiliationRecord spi.AffiliationImpl
	err := tx.Get(&oldAffiliationRecord, tx.Rebind(query), oldAffiliation)
	if err != nil {
		return nil, err
	}

	// Get the affiliation records for all sub affiliations
	query = "SELECT name, prekey FROM affiliations WHERE (name LIKE ?)"
	var allOldAffiliations []spi.AffiliationImpl
	err = tx.Select(&allOldAffiliations, tx.Rebind(query), oldAffiliation+".%")
	if err != nil {
		return nil, err
	}

	allOldAffiliations = append(allOldAffiliations, oldAffiliationRecord)

	log.Debugf("Affiliations to be modified %+v", allOldAffiliations)
	var idsWithOldAff []UserRecord
	var allIds []UserRecord

	// Iterate through all the affiliations found and update to use new affiliation path
	for _, affiliation := range allOldAffiliations {
		oldPath := affiliation.Name
		oldParentPath := affiliation.Prekey
		newPath := strings.Replace(oldPath, oldAffiliation, newAffiliation, 1)
		newParentPath := strings.Replace(oldParentPath, oldAffiliation, newAffiliation, 1)
		log.Debugf("oldPath: %s, newPath: %s, oldParentPath: %s, newParentPath: %s", oldPath, newPath, oldParentPath, newParentPath)

		// Select all users that are using the old affiliation
		query = "SELECT * FROM users WHERE (affiliation = ?)"
		err = tx.Select(&idsWithOldAff, tx.Rebind(query), oldPath)
		if err != nil {
			return nil, err
		}

		if len(idsWithOldAff) > 0 {
			if !isRegistar {
				return nil, newAuthErr(ErrMissingRegAttr, "Modifying affiliation affects identities, but caller is not a registrar")
			}
			// Get the list of names of the identities that need to be updated to use new affiliation
			ids := []string{}
			for _, id := range idsWithOldAff {
				ids = append(ids, id.Name)
			}

			if force {
				log.Debugf("Identities %s to be updated to use new affiliation of '%s' from '%s'", ids, newPath, oldPath)

				query := "Update users SET affiliation = ? WHERE (id IN (?))"
				inQuery, args, err := sqlx.In(query, newPath, ids)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to construct query '%s'", query)
				}
				_, err = tx.Exec(tx.Rebind(inQuery), args...)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to execute query '%s' for multiple certificate removal", query)
				}
			} else {
				// If force option is not specified, can only modify affiliation if there are no identities that have that affiliation
				idNamesStr := strings.Join(ids, ",")
				return nil, newHTTPErr(400, ErrUpdateConfigModifyAff, "The request to modify affiliation '%s' has the following identities associated: %s. Need to use 'force' to remove identities and affiliation", oldAffiliation, idNamesStr)
			}
		}

		// Update the affiliation record in the database to use new affiliation path
		query = "Update affiliations SET name = ?, prekey = ? WHERE (name = ?)"
		res := tx.MustExec(tx.Rebind(query), newPath, newParentPath, oldPath)
		numRowsAffected, err := res.RowsAffected()
		if err != nil {
			return nil, errors.Errorf("Failed to get number of rows affected")
		}
		if numRowsAffected == 0 {
			return nil, errors.Errorf("Failed to update any affiliation records for '%s'", oldPath)
		}

		for _, id := range idsWithOldAff {
			allIds = append(allIds, id)
		}
	}

	// Return the identities and affiliations that were modified
	result := getResult(allIds, allOldAffiliations, d)

	return result, nil
}

func (d *Accessor) doTransaction(doit func(tx *sqlx.Tx, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	err := d.checkDB()
	if err != nil {
		return nil, err
	}
	tx := d.db.MustBegin()
	result, err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encounted while rolling back transaction: %s", err2)
			return nil, err
		}
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Error encountered while committing transaction")
	}

	return result, nil
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

	user.attrs = make(map[string]api.Attribute)
	for _, attr := range attrs {
		user.attrs[attr.Name] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}

	user.db = d.db
	return user
}

// DBUser is the databases representation of a user
type DBUser struct {
	spi.UserInfo
	pass  []byte
	attrs map[string]api.Attribute
	db    *sqlx.DB
}

// GetName returns the enrollment ID of the user
func (u *DBUser) GetName() string {
	return u.Name
}

// GetType returns the type of the user
func (u *DBUser) GetType() string {
	return u.Type
}

// GetMaxEnrollments returns the max enrollments of the user
func (u *DBUser) GetMaxEnrollments() int {
	return u.MaxEnrollments
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
func (u *DBUser) GetAttribute(name string) (*api.Attribute, error) {
	value, hasAttr := u.attrs[name]
	if !hasAttr {
		return nil, errors.Errorf("User does not have attribute '%s'", name)
	}
	return &value, nil
}

// GetAttributes returns the requested attributes. Return all the user's
// attributes if nil is passed in
func (u *DBUser) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	var attrs []api.Attribute
	if attrNames == nil {
		for _, value := range u.attrs {
			attrs = append(attrs, value)
		}
		return attrs, nil
	}

	for _, name := range attrNames {
		value, hasAttr := u.attrs[name]
		if !hasAttr {
			return nil, errors.Errorf("User does not have attribute '%s'", name)
		}
		attrs = append(attrs, value)
	}
	return attrs, nil
}

// Revoke will revoke the user, setting the state of the user to be -1
func (u *DBUser) Revoke() error {
	stateUpdateSQL := "UPDATE users SET state = -1 WHERE (id = ?)"

	res, err := u.db.Exec(u.db.Rebind(stateUpdateSQL), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to update state of identity %s to -1", u.Name)
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

	log.Debugf("Successfully incremented state for identity %s to -1", u.Name)

	return nil
}

func getError(err error, getType string) error {
	if err.Error() == "sql: no rows in result set" {
		return newHTTPErr(404, ErrDBGet, "Failed to get %s: %s", getType, err)
	}
	return newHTTPErr(500, ErrConnectingDB, "Failed to process database request: %s", err)
}

// Return the identities and affiliations that were modified
func getResult(ids []UserRecord, affs []spi.AffiliationImpl, d *Accessor) *spi.DbTxResult {
	// Collect all the identities that were modified
	identities := []spi.User{}
	for _, id := range ids {
		identities = append(identities, d.newDBUser(&id))
	}

	// Collect the name of all affiliations that were modified
	affiliations := []spi.Affiliation{}
	for _, aff := range affs {
		newAff := &spi.AffiliationImpl{
			Name:   aff.Name,
			Prekey: aff.Prekey,
		}
		affiliations = append(affiliations, newAff)
	}

	return &spi.DbTxResult{
		Affiliations: affiliations,
		Identities:   identities,
	}
}
