/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory_test

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/factory"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/mysql"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/postgres"
	"github.com/hyperledger/fabric-ca/lib/server/userregistry/db/sqlite"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	gt := NewGomegaWithT(t)

	db, err := factory.New("sqlite3", "fabric_ca.db", "", nil, nil, &disabled.Provider{})
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(sqlite.NewUserRegistry("fabric_ca.db", "", &disabled.Provider{})))

	db, err = factory.New("postgres", "fabric_ca_postgres", "", nil, nil, &disabled.Provider{})
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(postgres.NewUserRegistry("fabric_ca_postgres", "", nil, &disabled.Provider{})))

	db, err = factory.New("mysql", "fabric_ca_mysql", "", nil, nil, &disabled.Provider{})
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(mysql.NewUserRegistry("fabric_ca_mysql", "", nil, nil, &disabled.Provider{})))

	db, err = factory.New("fake", "fabric_ca_mysql", "", nil, nil, &disabled.Provider{})
	gt.Expect(err).To(HaveOccurred())

	os.Remove("fabric_ca.db")
}
