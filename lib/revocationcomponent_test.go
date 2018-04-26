/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package lib_test

import (
	"fmt"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib"
	dmocks "github.com/hyperledger/fabric-ca/lib/dbutil/mocks"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestGetRCInfoFromDBError(t *testing.T) {
	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})
	rcinfos := []RevocationComponentInfo{}
	db := new(dmocks.FabricCADB)
	db.On("Select", &rcinfos, "SELECT * FROM revocation_component_info").Return(errors.New("Failed to execute select query"))
	ca.On("DB").Return(db)
	_, err := NewRevocationComponent(ca, 1)
	assert.Error(t, err)
}

func TestGetRCInfoFromNewDBSelectError(t *testing.T) {
	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})

	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationComponentInfo{}
	f := getSelectFunc(t, true, true)
	db.On("Select", &rcInfos, SelectRCInfo).Return(f)
	ca.On("DB").Return(db)
	_, err := NewRevocationComponent(ca, 1)
	assert.Error(t, err)
}

func TestGetRCInfoFromNewDBInsertError(t *testing.T) {
	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})

	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationComponentInfo{}
	f := getSelectFunc(t, true, false)
	db.On("Select", &rcInfos, SelectRCInfo).Return(f)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(nil, errors.New("Inserting Revocation component info into DB failed"))
	ca.On("DB").Return(db)
	_, err := NewRevocationComponent(ca, 1)
	assert.Error(t, err)
}

func TestGetNewRevocationHandleSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, true, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to get revocation component info from DB")
}

func TestGetNewRevocationHandleNoData(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, false)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No revocation component info found in DB")
}

func TestGetNewRevocationHandleExecError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to update revocation component info")
}

func TestGetNewRevocationHandleRollbackError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(errors.New("Rollback error"))

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encounted while rolling back transaction")
}

func TestGetNewRevocationHandleCommitError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(errors.New("Error commiting"))
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while committing transaction")
}

func TestGetNewRevocationHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 2, int(*rh))
}

func TestGetNewRevocationHandleLastHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextAndLastHandle).Return(UpdateNextAndLastHandle)
	tx.On("Exec", UpdateNextAndLastHandle, 100, 200, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 99, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 100, int(*rh))
}

func getRevocationComponent(t *testing.T, db *dmocks.FabricCADB) *RevocationComponent {
	ca := new(mocks.IdemixCA)
	ca.On("GetConfig").Return(&CAConfig{
		CA: CAInfo{
			Name: "",
		},
	})

	f := getSelectFunc(t, true, false)

	rcInfosForSelect := []RevocationComponentInfo{}
	db.On("Select", &rcInfosForSelect, SelectRCInfo).Return(f)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(nil, nil)
	ca.On("DB").Return(db)
	rc, err := NewRevocationComponent(ca, 1)
	if err != nil {
		t.Fatalf("Failed to get revocation component instance: %s", err.Error())
	}
	return rc
}

func getSelectFunc(t *testing.T, newDB bool, isError bool) func(interface{}, string, ...interface{}) error {
	return func(dest interface{}, query string, args ...interface{}) error {
		rcInfos, _ := dest.(*[]RevocationComponentInfo)
		if newDB {
			rcInfo := RevocationComponentInfo{
				Epoch:                0,
				NextRevocationHandle: 0,
				LastHandleInPool:     0,
				Level:                0,
			}
			*rcInfos = append(*rcInfos, rcInfo)
		}
		if isError {
			return errors.New("Failed to get RevocationComponentInfo from DB")
		}
		return nil
	}
}

func getTxSelectFunc(t *testing.T, rcs *[]RevocationComponentInfo, nextRH int, isError bool, isAppend bool) func(interface{}, string, ...interface{}) error {
	return func(dest interface{}, query string, args ...interface{}) error {
		rcInfos := dest.(*[]RevocationComponentInfo)
		rcInfo := RevocationComponentInfo{
			Epoch:                1,
			NextRevocationHandle: nextRH,
			LastHandleInPool:     100,
			Level:                1,
		}
		if isAppend {
			*rcInfos = append(*rcInfos, rcInfo)
			*rcs = append(*rcs, rcInfo)
		}

		if isError {
			return errors.New("Failed to get RevocationComponentInfo from DB")
		}

		fmt.Println("rcInfos:", rcInfos)
		return nil
	}
}
