#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

TESTCASE="backwards_comp"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

export FABRIC_CA_SERVER_HOME="/tmp/$TESTCASE"
export CA_CFG_PATH="/tmp/$TESTCASE"

TESTCONFIG="$FABRIC_CA_SERVER_HOME/testconfig.yaml"

function genConfig {
  local identityLevel=$1
  : ${identityLevel:=""}
  local affiliationLevel=$2
  : ${affiliationLevel:=""}
  local certificateLevel=$3
  : ${certificateLevel:=""}
    postgresTls='sslmode=disable'
   case "$FABRIC_TLS" in
      true) postgresTls='sslmode=require'; mysqlTls='?tls=custom' ;;
   esac

   mkdir -p $FABRIC_CA_SERVER_HOME
   echo "identity version: $identityLevel"
   # Create base configuration using mysql
   cat > $TESTCONFIG <<EOF
debug: true

registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

  # Contains identity information which is used when LDAP is disabled
  identities:
     - name: a
       pass: b
       type: client
       affiliation: ""
       maxenrollments: -1
       attrs:
          hf.Registrar.Roles: "client,user,peer,validator,auditor"
          hf.Registrar.DelegateRoles: "client,user,validator,auditor"
          hf.Revoker: true
          hf.IntermediateCA: true

affiliations:
   org1:
      - department1
      - department2
   org2:
      - department1

levels:
EOF

  if [ "$identityLevel" != "" ]; then
    echo "  identity: $identityLevel" >> $TESTCONFIG
  fi
  if [ "$affiliationLevel" != "" ]; then
    echo "  affiliation: $affiliationLevel" >> $TESTCONFIG
  fi
  if [ "$certificateLevel" != "" ]; then
    echo "  certificate: $certificateLevel" >> $TESTCONFIG
  fi
}

function resetDB {
  local dbtype=$1
  case "$driver" in
    sqlite3)
      rm -rf $FABRIC_CA_SERVER_HOME/fabric_ca ;;
    postgres)
      psql -d postgres -c "DROP DATABASE fabric_ca" ;;
    mysql)
      mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE fabric_ca" ;;
    *)
      echo "Invalid database type"
      exit 1
      ;;
  esac
}

# Starting server with a configuration file that is a higher version than the server executable fail
genConfig "9" "9" "9"
fabric-ca-server start -b a:b -c $TESTCONFIG -d
if test $? -ne 1; then
    ErrorMsg "Should have failed to start server"
fi

for driver in sqlite3 postgres mysql; do

  case "$driver" in
  sqlite3)
    rm -rf $FABRIC_CA_SERVER_HOME
    mkdir -p $FABRIC_CA_SERVER_HOME
    sqlite3 $FABRIC_CA_SERVER_HOME/fabric_ca 'CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property));'
    sqlite3 $FABRIC_CA_SERVER_HOME/fabric_ca 'INSERT INTO properties (property, value) Values ("identity", "9");'
    ;;
  postgres)
    psql -d postgres -c "DROP DATABASE fabric_ca"
    psql -d postgres -c "CREATE DATABASE fabric_ca"
    psql -d fabric_ca -c "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    psql -d fabric_ca -c "INSERT INTO properties (property, value) Values ('identity', '9')"
    ;;
  mysql)
    mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE fabric_ca"
    mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE fabric_ca"
    mysql --host=localhost --user=root --password=mysql --database=fabric_ca -e "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    mysql --host=localhost --user=root --password=mysql --database=fabric_ca -e "INSERT INTO properties (property, value) Values ('identity', '9')"
    ;;
  *)
    echo "Invalid database type"
    exit 1
    ;;
  esac

   $SCRIPTDIR/fabric-ca_setup.sh -I -D -d $driver
   if ! test $? -eq 0; then
    ErrorMsg "Should have failed to initialize server"
   fi
   $SCRIPTDIR/fabric-ca_setup.sh -K

   resetDB $driver

done

CleanUp $RC
exit $RC