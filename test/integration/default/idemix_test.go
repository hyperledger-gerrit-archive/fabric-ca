/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defserver

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	"github.com/stretchr/testify/assert"
)

const (
	// SelectCredentialByIDSQL is the SQL for getting credentials of a user
	SelectCredentialByIDSQL = `
SELECT %s FROM credentials
WHERE (id = ?);`

	TempDir = "/tmp/idemixtest"
)

// CredRecord represents a credential database record
type CredRecord struct {
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

func TestIdemixRevoke(t *testing.T) {
	var err error

	os.Setenv("FABRIC_CA_CLIENT_HOME", TempDir)
	defer os.RemoveAll(TempDir)

	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	// Register and enroll a new user with idemix credential
	err = command.RunMain([]string{cmdName, "register", "--id.name", "idemixUser", "--id.secret", "idemix", "-d"})
	util.FatalError(t, err, "Failed to register user")

	idemixClientHome, err := ioutil.TempDir("", "idemix")
	util.FatalError(t, err, "Failed to create temp dir")

	err = command.RunMain([]string{cmdName, "enroll", "-u", "http://idemixUser:idemix@localhost:7054", "--enrollment.type", "idemix", "-H", idemixClientHome, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	idemixClientHome2, err := ioutil.TempDir("", "idemix2")
	util.FatalError(t, err, "Failed to create temp dir")

	err = command.RunMain([]string{cmdName, "enroll", "-u", "http://idemixUser:idemix@localhost:7054", "--enrollment.type", "idemix", "-H", idemixClientHome2, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	crs := getCredentialsForUser(t, "idemixUser")

	err = command.RunMain([]string{cmdName, "revoke", "--type", "idemix", "--idemixrh", crs[0].RevocationHandle, "-d"})
	assert.NoError(t, err, "Failed to revoke Idemix credential by revocation handle")

	// Register and enroll a new user with caller idemix credential being revoked
	err = command.RunMain([]string{cmdName, "register", "--id.name", "shouldFailUser", "-H", idemixClientHome, "-d"})
	assert.Error(t, err, "Should fail to register user")
	assert.Contains(t, err.Error(), "Authorization failure")

	err = command.RunMain([]string{cmdName, "revoke", "--type", "idemix", "--name", "idemixUser", "-d"})
	assert.NoError(t, err, "Failed to revoke 'idemixUser'")

	// Register and enroll a new user with caller being revoked
	err = command.RunMain([]string{cmdName, "register", "--id.name", "shouldFailUser2", "-H", idemixClientHome2, "-d"})
	assert.Error(t, err, "Should fail to register user")
	assert.Contains(t, err.Error(), "Authorization failure")
}

func getCredentialsForUser(t *testing.T, id string) []CredRecord {
	db, err := sqlx.Open("sqlite3", filepath.Join(defaultServerHomeDir, "fabric-ca-server.db"))
	util.FatalError(t, err, "Failed to open db")
	crs := []CredRecord{}
	err = db.Select(&crs, fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{})), id)
	util.FatalError(t, err, "Failed to execute db query: %s", err)
	return crs
}
