/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db_test

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/util"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/gomega"
)

func TestDB(t *testing.T) {
	gt := NewGomegaWithT(t)

	mockDB := genMockDB()
	fabDB := db.New(mockDB)
	gt.Expect(fabDB).To(Not(BeNil()))

	tx := fabDB.BeginTx()
	gt.Expect(tx).To(Equal(&sqlx.Tx{}))

	fabDB.IsDBInitialized = true
	b := fabDB.IsInitialized()
	gt.Expect(b).To(Equal(true))

	fabDB.SetDBInitialized(false)
	gt.Expect(fabDB.IsDBInitialized).To(Equal(false))

	// Select
	err := fabDB.Select(nil, "")
	gt.Expect(err.Error()).To(Equal("Select Error"))
	err = fabDB.Select(nil, "query")
	gt.Expect(err).NotTo(HaveOccurred())

	// Exec
	res, err := fabDB.Exec("query")
	gt.Expect(err).NotTo(HaveOccurred())
	rows, err := res.RowsAffected()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(rows).To(Equal(int64(2)))
	_, err = fabDB.Exec("")
	gt.Expect(err.Error()).To(Equal("Exec Error"))

	// NamedExec
	res, err = fabDB.NamedExec("query", nil)
	gt.Expect(err).NotTo(HaveOccurred())
	rows, err = res.RowsAffected()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(rows).To(Equal(int64(3)))
	_, err = fabDB.NamedExec("", nil)
	gt.Expect(err.Error()).To(Equal("NamedExec Error"))

	// Get
	err = fabDB.Get(nil, "query")
	gt.Expect(err).NotTo(HaveOccurred())
	err = fabDB.Get(nil, "")
	gt.Expect(err.Error()).To(Equal("Get Error"))

	// Queryx
	r, err := fabDB.Queryx("query")
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(r).To(Equal(&sqlx.Rows{}))
	_, err = fabDB.Queryx("")
	gt.Expect(err.Error()).To(Equal("Queryx Error"))

	// DriverName
	driverName := fabDB.DriverName()
	gt.Expect(driverName).To(Equal("sqlite"))

	// Rebind
	query := fabDB.Rebind("Select * from")
	gt.Expect(query).To(Equal("Select * from"))
}

func TestCurrentDBLevels(t *testing.T) {
	gt := NewGomegaWithT(t)

	mockFabricCADB := &mocks.FabricCADB{}
	mockFabricCADB.GetReturns(errors.New("failed to get levels"))

	_, err := db.CurrentDBLevels(mockFabricCADB)
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("failed to get levels"))

	mockFabricCADB = &mocks.FabricCADB{}
	levels, err := db.CurrentDBLevels(mockFabricCADB)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(levels).To(Equal(&util.Levels{0, 0, 0, 0, 0, 0}))
}

func genMockDB() *mocks.SqlxDB {
	mockDB := &mocks.SqlxDB{}

	mockDB.On("MustBegin").Return(&sqlx.Tx{})
	mockDB.On("Select", nil, "").Return(errors.New("Select Error"))
	mockDB.On("Select", nil, "query").Return(nil)

	mockResult := &mocks.Result{}
	mockResult.On("RowsAffected").Return(int64(2), nil)
	mockDB.On("Exec", "query").Return(mockResult, nil)
	mockDB.On("Exec", "").Return(nil, errors.New("Exec Error"))

	mockResult = &mocks.Result{}
	mockResult.On("RowsAffected").Return(int64(3), nil)
	mockDB.On("NamedExec", "query", nil).Return(mockResult, nil)
	mockDB.On("NamedExec", "", nil).Return(nil, errors.New("NamedExec Error"))

	mockDB.On("Get", nil, "query").Return(nil)
	mockDB.On("Get", nil, "").Return(errors.New("Get Error"))

	mockDB.On("Queryx", "query").Return(&sqlx.Rows{}, nil)
	mockDB.On("Queryx", "").Return(nil, errors.New("Queryx Error"))

	mockDB.On("DriverName").Return("sqlite")

	mockDB.On("Rebind", "Select * from").Return("Select * from")
	return mockDB
}
