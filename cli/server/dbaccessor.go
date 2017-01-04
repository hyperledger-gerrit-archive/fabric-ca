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

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/spi"
	"github.com/hyperledger/fabric-cop/idp"

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
INSERT INTO users (id, token, type, user_group, attributes, state, max_enrollments)
	VALUES (:id, :token, :type, :user_group, :attributes, :state, :max_enrollments);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
	SET token = :token, type = :type, user_group = :user_group, attributes = :attributes
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertGroup = `
INSERT INTO groups (name, parent_id)
	VALUES (?, ?)`

	deleteGroup = `
DELETE FROM groups
	WHERE (name = ?)`

	getGroup = `
SELECT name, parent_id FROM groups
	WHERE (name = ?)`
)

// UserRecord defines the properties of a user
type UserRecord struct {
	Name           string `db:"id"`
	Pass           string `db:"token"`
	Type           string `db:"type"`
	Group          string `db:"user_group"`
	Attributes     string `db:"attributes"`
	State          int    `db:"state"`
	MaxEnrollments int    `db:"max_enrollments"`
}

// GroupRecord defines the properties of a group
type GroupRecord struct {
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
	Prekey   string `db:"prekey"`
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
		return errors.New("unknown db object, please check SetDB method")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *sqlx.DB) {
	d.db = db
	return
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user spi.UserInfo) error {
	log.Debugf("DB: Insert User (%s) to database", user.Name)

	err := d.checkDB()
	if err != nil {
		return err
	}

	attrBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(insertUser, &UserRecord{
		Name:           user.Name,
		Pass:           user.Pass,
		Type:           user.Type,
		Group:          user.Group,
		Attributes:     string(attrBytes),
		State:          user.State,
		MaxEnrollments: user.MaxEnrollments,
	})

	if err != nil {
		log.Error("Error during inserting of user, error: ", err)
		return err
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "Failed to insert the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	log.Debugf("User %s inserted into database successfully", user.Name)

	return nil

}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) error {
	log.Debugf("DB: Delete User (%s)", id)
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteUser, id)
	if err != nil {
		return err
	}

	return nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user spi.UserInfo) error {
	log.Debugf("DB: Update User (%s) in database", user.Name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(updateUser, &UserRecord{
		Name:           user.Name,
		Pass:           user.Pass,
		Type:           user.Type,
		Group:          user.Group,
		Attributes:     string(attributes),
		State:          user.State,
		MaxEnrollments: user.MaxEnrollments,
	})

	if err != nil {
		log.Errorf("Failed to update user record [error: %s]", err)
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "Failed to update the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err

}

// GetUser gets user from database
func (d *Accessor) GetUser(id string, attrs []string) (spi.User, error) {
	log.Debugf("Getting user %s from the database", id)

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var userRec UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return nil, err
	}

	return d.newDBUser(&userRec), nil
}

// GetUserInfo gets user information from database
func (d *Accessor) GetUserInfo(id string) (spi.UserInfo, error) {
	log.Debugf("Getting user %s information from the database", id)

	var userInfo spi.UserInfo

	err := d.checkDB()
	if err != nil {
		return userInfo, err
	}

	var userRec UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return userInfo, err
	}

	var attributes []idp.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attributes)

	userInfo.Name = userRec.Name
	userInfo.Pass = userRec.Pass
	userInfo.Type = userRec.Type
	userInfo.Group = userRec.Group
	userInfo.State = userRec.State
	userInfo.MaxEnrollments = userRec.MaxEnrollments
	userInfo.Attributes = attributes

	return userInfo, nil
}

// InsertGroup inserts group into database
func (d *Accessor) InsertGroup(name string, parentID string) error {
	log.Debugf("DB: Insert Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return err
	}
	_, err = d.db.Exec(d.db.Rebind(insertGroup), name, parentID)
	if err != nil {
		return err
	}

	/*
		preKeyString := crypto.CreateRootPreKey()

		_, err = d.db.Exec("UPDATE groups SET prekey = ? WHERE (name = ?)", preKeyString, name)
		if err != nil {
			return err
		}
	*/

	return nil
}

// DeleteGroup deletes group from database
func (d *Accessor) DeleteGroup(name string) error {
	log.Debugf("DB: Delete Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteGroup, name)
	if err != nil {
		return err
	}

	return nil
}

// GetGroup gets group from database
func (d *Accessor) GetGroup(name string) (spi.Group, error) {
	log.Debugf("DB: Get Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var groupInfo spi.GroupInfo

	err = d.db.Get(&groupInfo, d.db.Rebind(getGroup), name)
	if err != nil {
		return nil, err
	}

	return &groupInfo, nil
}

// GetRootGroup gets root group from database
func (d *Accessor) GetRootGroup() (spi.Group, error) {
	log.Debugf("DB: Get root group")
	err := d.checkDB()
	if err != nil {
		return nil, err
	}
	// TODO: IMPLEMENT
	return nil, errors.New("NOT YET IMPLEMENTED")
}

// Creates a DBUser object from the DB user record
func (d *Accessor) newDBUser(userRec *UserRecord) *DBUser {
	var user = new(DBUser)
	user.Name = userRec.Name
	user.Pass = userRec.Pass
	user.State = userRec.State
	user.MaxEnrollments = userRec.MaxEnrollments
	user.Group = userRec.Group
	user.Type = userRec.Type

	var attrs []idp.Attribute
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
	attrs map[string]string
	db    *sqlx.DB
}

// GetName returns the enrollment ID of the user
func (u *DBUser) GetName() string {
	return u.Name
}

// Login the user with a password
func (u *DBUser) Login(pass string) error {
	log.Debugf("DB: Login user %s with max enrollments of %d and state of %d", u.Name, u.MaxEnrollments, u.State)

	// Check the password
	if u.Pass != pass {
		log.Errorf("Incorrect password for %s", u.Name)
		return cop.NewError(cop.AuthorizationFailure, "Incorrect username/password provided)")
	}

	// If the maxEnrollments is set (i.e. >= 0), make sure we haven't exceeded this number of logins.
	// The state variable keeps track of the number of previously successful logins.
	if u.MaxEnrollments >= 0 {

		// If maxEnrollments is set to 0, user has unlimited enrollment
		if u.MaxEnrollments != 0 {
			if u.State >= u.MaxEnrollments {
				return fmt.Errorf("The maximum number of enrollments is %d", u.MaxEnrollments)
			}
		}

		// Not exceeded, so attempt to increment the count
		state := u.State + 1
		res, err := u.db.Exec(u.db.Rebind("UPDATE users SET state = ? WHERE (id = ?)"), state, u.Name)
		if err != nil {
			return fmt.Errorf("Failed to update state of user %s to %d: %s", u.Name, state, err)
		}

		numRowsAffected, err := res.RowsAffected()

		if err != nil {
			return fmt.Errorf("db.RowsAffected failed: %s", err)
		}

		if numRowsAffected == 0 {
			return fmt.Errorf("no rows were affected when updating the state of user %s", u.Name)
		}

		if numRowsAffected != 1 {
			return fmt.Errorf("%d rows were affected when updating the state of user %s", numRowsAffected, u.Name)
		}

		log.Debugf("Successfully incremented state for user %s to %d", u.Name, state)
	}

	log.Debugf("DB: user %s successfully logged in", u.Name)

	return nil

}

// GetAffiliationPath returns the complete path for the user's affiliation.
func (u *DBUser) GetAffiliationPath() []string {
	affiliationPath := strings.Split(u.Group, "/")
	return affiliationPath
}

// GetAttribute returns the value for an attribute name
func (u *DBUser) GetAttribute(name string) string {
	return u.attrs[name]
}
