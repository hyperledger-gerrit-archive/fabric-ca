/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres_test

import (
	"path/filepath"

	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/postgres"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/postgres/mocks"
	"github.com/hyperledger/fabric-ca/lib/tls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
)

const (
	testdataDir = "../../../../../testdata"
)

var _ = Describe("Postgres", func() {
	var db *postgres.Postgres

	BeforeEach(func() {
		tls := &tls.ClientTLSConfig{
			Enabled:   true,
			CertFiles: []string{filepath.Join(testdataDir, "root.pem")},
		}
		db = postgres.NewUserRegistry("host=localhost port=5432 user=root password=rootpw dbname=fabric_ca", tls)
	})

	Context("open connection to database", func() {
		It("fails to connect if the contains incorrect syntax", func() {
			db = postgres.NewUserRegistry("hos) (t=localhost port=5432 user=root password=rootpw dbname=fabric-ca", nil)
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("Database name 'fabric-ca' cannot contain any '-' or end with '.db'"))

			db = postgres.NewUserRegistry("host=localhost port=5432 user=root password=rootpw dbname=fabric_ca.db", nil)
			err = db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("Database name 'fabric_ca.db' cannot contain any '-' or end with '.db'"))
		})

		It("fails to open database connection of root cert files missing from tls config", func() {
			db.TLS.CertFiles = nil
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("No trusted root certificates for TLS were provided"))
			Expect(db.SqlxDB).To(BeNil())
		})

		It("fail to open database connection if unable to ping database", func() {
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to connect to Postgres database. Postgres requires connecting to a specific database, the following databases were tried: [fabric_ca postgres template1]"))
		})
	})

	Context("pinging database", func() {
		var mockSqlxDB *mocks.Sqlx

		BeforeEach(func() {
			mockSqlxDB = &mocks.Sqlx{}
		})

		It("returns an error if unable to ping database", func() {
			mockSqlxDB.PingReturns(errors.New("ping error"))
			db.SqlxDB = mockSqlxDB

			err := db.Ping()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to ping to Postgres database: ping error"))
		})

		It("returns no error if able to ping database", func() {
			db.SqlxDB = mockSqlxDB

			err := db.Ping()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("creating fabric ca database", func() {
		var mockSqlxDB *mocks.Sqlx

		BeforeEach(func() {
			mockSqlxDB = &mocks.Sqlx{}
		})

		It("returns an error if unable execute create fabric ca database sql", func() {
			mockSqlxDB.ExecReturns(nil, errors.New("error creating database"))
			db.SqlxDB = mockSqlxDB
			_, err := db.CreateDatabase()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres database: Failed to execute create database query: error creating database"))
		})

		It("creates the fabric ca database", func() {
			db.SqlxDB = mockSqlxDB

			_, err := db.CreateDatabase()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("creating tables", func() {
		var mockSqlxDB *mocks.Sqlx

		BeforeEach(func() {
			mockSqlxDB = &mocks.Sqlx{}
		})

		It("returns an error if unable to create users table", func() {
			mockSqlxDB.ExecReturnsOnCall(0, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating users table: unable to create table"))
		})

		It("returns an error if unable to create affiliations table", func() {
			mockSqlxDB.ExecReturnsOnCall(1, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating affiliations table: unable to create table"))
		})

		It("returns an error if unable to create certificates table", func() {
			mockSqlxDB.ExecReturnsOnCall(2, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating certificates table: unable to create table"))
		})

		It("returns an error if unable to create credentails table", func() {
			mockSqlxDB.ExecReturnsOnCall(3, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating credentials table: unable to create table"))
		})

		It("returns an error if unable to create revocation_authority_info table", func() {
			mockSqlxDB.ExecReturnsOnCall(4, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating revocation_authority_info table: unable to create table"))
		})

		It("returns an error if unable to create nonces table", func() {
			mockSqlxDB.ExecReturnsOnCall(5, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating nonces table: unable to create table"))
		})

		It("returns an error if unable to create properties table", func() {
			mockSqlxDB.ExecReturnsOnCall(6, nil, errors.New("unable to create table"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating properties table: unable to create table"))
		})

		It("returns an error if unable to insert default value in properties table", func() {
			mockSqlxDB.ExecReturnsOnCall(7, nil, errors.New("unable to insert default values"))

			db.SqlxDB = mockSqlxDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: unable to insert default values"))
		})

		It("creates the fabric ca tables", func() {
			db.SqlxDB = mockSqlxDB

			err := db.CreateTables()
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
