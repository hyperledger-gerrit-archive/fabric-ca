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
INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level)
	VALUES (:id, :token, :type, :affiliation, :attributes, :state, :max_enrollments, :level);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
	SET token = :token, type = :type, affiliation = :affiliation, attributes = :attributes, state = :state, level = :level
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertAffiliation = `
INSERT INTO affiliations (name, prekey, level)
	VALUES (?, ?, ?)`

	deleteAffiliation = `
DELETE FROM affiliations
	WHERE (name = ?)`

	getAffiliation = `
SELECT * FROM affiliations
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
	Level          int    `db:"level"`
}

// AffiliationRecord defines the properties of an affiliation
type AffiliationRecord struct {
	Name   string `db:"name"`
	Prekey string `db:"prekey"`
	Level  int    `db:"level"`
}

// Accessor implements db.Accessor interface.
type Accessor struct {
	db *sqlx.DB
}

// NewDBAccessor is a constructor for the database API
func NewDBAccessor(db *sqlx.DB) *Accessor {
	return &Accessor{
		db: db,
	}
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
		Level:          user.Level,
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

	return d.doTransaction(deleteUserTx, id)
}

func deleteUserTx(tx *sqlx.Tx, args ...interface{}) error {
	id := args[0].(string)
	_, err := tx.Exec(tx.Rebind(deleteUser), id)
	if err != nil {
		return errors.Wrapf(err, "Error deleting identity '%s'", id)
	}

	_, err = tx.Exec(tx.Rebind(deleteCertificatebyID), id)
	if err != nil {
		return errors.Wrapf(err, "Error deleting certificates for '%s'", id)
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
		Level:          user.Level,
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
		return nil, getUserError(dbGetError(err, "User"))
	}

	return d.newDBUser(&userRec), nil
}

// InsertAffiliation inserts affiliation into database
func (d *Accessor) InsertAffiliation(name string, prekey string, level int) error {
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
	_, err = d.db.Exec(d.db.Rebind(insertAffiliation), name, prekey, level)
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
func (d *Accessor) DeleteAffiliation(name string) error {
	log.Debugf("DB: Delete affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteAffiliation, name)
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

	var affiliationRecord AffiliationRecord
	err = d.db.Get(&affiliationRecord, d.db.Rebind(getAffiliation), name)
	if err != nil {
		return nil, dbGetError(err, "Affiliation")
	}

	affiliation := spi.NewAffiliation(affiliationRecord.Name, affiliationRecord.Prekey, affiliationRecord.Level)

	return affiliation, nil
}

// GetProperties returns the properties from the database
func (d *Accessor) GetProperties(names []string) (map[string]string, error) {
	log.Debugf("DB: Get properties %s", names)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	type property struct {
		Name  string `db:"property"`
		Value string `db:"value"`
	}

	properties := []property{}

	query := "SELECT * FROM properties WHERE (property IN (?))"
	inQuery, args, err := sqlx.In(query, names)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to construct query '%s' for properties '%s'", query, names)
	}
	err = d.db.Select(&properties, d.db.Rebind(inQuery), args...)
	if err != nil {
		return nil, dbGetError(err, "Properties")
	}

	propertiesMap := make(map[string]string)
	for _, prop := range properties {
		propertiesMap[prop.Name] = prop.Value
	}

	return propertiesMap, nil
}

// GetUserLessThanLevel returns all identities that are less than the level specified
// Otherwise, returns no users if requested level is zero
func (d *Accessor) GetUserLessThanLevel(level int) ([]spi.User, error) {
	var users []UserRecord

	if level == 0 {
		return []spi.User{}, nil
	}

	err := d.db.Select(&users, d.db.Rebind("SELECT * FROM users WHERE (level < ?) OR (level IS NULL)"), level)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get identities that need to be updated")
	}

	allUsers := []spi.User{}

	for _, user := range users {
		dbUser := d.newDBUser(&user)
		allUsers = append(allUsers, dbUser)
	}

	return allUsers, nil
}

// GetFilteredUsers returns all identities that fall under the affiliation and types
func (d *Accessor) GetFilteredUsers(affiliation, types string) (*sqlx.Rows, error) {
	log.Debugf("DB: Get all identities per affiliation '%s' and types '%s'", affiliation, types)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	typesArray := strings.Split(types, ",")
	for i := range typesArray {
		typesArray[i] = strings.TrimSpace(typesArray[i])
	}

	if affiliation == "" {
		query := "SELECT * FROM users WHERE (type IN (?))"
		query, args, err := sqlx.In(query, typesArray)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		rows, err := d.db.Queryx(d.db.Rebind(query), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		return rows, nil
	}

	subAffiliation := affiliation + ".%"
	query := "SELECT * FROM users WHERE ((affiliation = ?) OR (affiliation LIKE ?)) AND (type IN (?))"
	inQuery, args, err := sqlx.In(query, affiliation, subAffiliation, typesArray)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
	}
	rows, err := d.db.Queryx(d.db.Rebind(inQuery), args...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
	}

	return rows, nil

}

func (d *Accessor) doTransaction(doit func(tx *sqlx.Tx, args ...interface{}) error, args ...interface{}) error {
	err := d.checkDB()
	if err != nil {
		return err
	}
	tx := d.db.MustBegin()
	err = doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encounted while rolling back transaction: %s", err2)
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing transaction")
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
	user.Level = userRec.Level

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

// GetLevel returns the level of the user
func (u *DBUser) GetLevel() int {
	return u.Level
}

// SetLevel sets the level of the user
func (u *DBUser) SetLevel(level int) error {
	query := "UPDATE users SET level = ? where (id = ?)"
	id := u.GetName()
	res, err := u.db.Exec(u.db.Rebind(query), level, id)
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

// ModifyAttributes adds a new attribute, modifies existing attribute, or delete attribute
func (u *DBUser) ModifyAttributes(attrs []api.Attribute) error {
	log.Debugf("Modify Attributes: %+v", attrs)
	userAttrs, _ := u.GetAttributes(nil)
	var attr api.Attribute
	for _, attr = range attrs {
		log.Debugf("Attribute request: %+v", attr)
		found := false
		for i := range userAttrs {
			if userAttrs[i].Name == attr.Name {
				if attr.Value == "" {
					log.Debugf("Deleting attribute: %+v", userAttrs[i])
					if i == len(userAttrs)-1 {
						userAttrs = userAttrs[:len(userAttrs)-1]
					} else {
						userAttrs = append(userAttrs[:i], userAttrs[i+1:]...)
					}
				} else {
					log.Debugf("Updating existing attribute from '%+v' to '%+v'", userAttrs[i], attr)
					userAttrs[i].Value = attr.Value
				}
				found = true
				break
			}
		}
		if !found && attr.Value != "" {
			log.Debugf("Adding '%+v' as new attribute", attr)
			userAttrs = append(userAttrs, attr)
		}
	}

	attrBytes, err := json.Marshal(userAttrs)
	if err != nil {
		return err
	}

	query := "UPDATE users SET attributes = ? where (id = ?)"
	id := u.GetName()
	res, err := u.db.Exec(u.db.Rebind(query), string(attrBytes), id)
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

func dbGetError(err error, prefix string) error {
	if err.Error() == "sql: no rows in result set" {
		return errors.Errorf("%s not found", prefix)
	}
	return err
}

func getUserError(err error) error {
	if err.Error() == "not found" {
		return newHTTPErr(404, ErrGettingUser, "Failed to get user: %s", err)
	}
	return newHTTPErr(504, ErrConnectingDB, "Failed to process database request: %s", err)
}
