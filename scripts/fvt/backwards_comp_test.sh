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
DBNAME=fabric_ca

function genConfig {
  local version=$1
  : ${version:=""}
  local dbname=$2
  : ${dbname:="sqlite"}
    postgresTls='sslmode=disable'
   case "$FABRIC_TLS" in
      true) postgresTls='sslmode=require'; mysqlTls='?tls=custom' ;;
   esac

   mkdir -p $FABRIC_CA_SERVER_HOME
   # Create base configuration using mysql
   cat > $TESTCONFIG <<EOF
debug: true

db:
  type: mysql
  datasource: root:mysql@tcp(localhost:$MYSQL_PORT)/$DBNAME$mysqlTls
  tls:
     enabled: $FABRIC_TLS
     certfiles:
       - $TLS_ROOTCERT
     client:
       certfile: $TLS_CLIENTCERT
       keyfile: $TLS_CLIENTKEY

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
EOF

  if [ "$version" != "" ]; then
    sed -i "1s/^/version: \"$version\"\n/" $TESTCONFIG
  fi

  if [ $dbname = "sqlite3" ]; then
    sed -i "s/type: mysql/type: sqlite3/
        s/datasource:.*/datasource: $DBNAME/" $TESTCONFIG
  fi

  if [ $dbname = "postgres" ]; then
    sed -i "s/type: mysql/type: postgres/
        s/datasource:.*/datasource: host=localhost port=$POSTGRES_PORT user=postgres password=postgres dbname=$DBNAME $postgresTls/" $TESTCONFIG
  fi

}

function resetDB {
  if [ $driver = "sqlite3" ]; then
    rm -rf $FABRIC_CA_SERVER_HOME/$DBNAME
  fi

  if [ $driver = "postgres" ]; then
    psql -d postgres -c "DROP DATABASE $DBNAME"
  fi

  if [ $driver = "mysql" ]; then 
    mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE $DBNAME"
  fi 
}

function createDB {
  if [ $driver = "sqlite3" ]; then
    mkdir -p $FABRIC_CA_SERVER_HOME
  fi

  if [ $driver = "postgres" ]; then
    psql -d postgres -c "CREATE DATABASE $DBNAME"
  fi

  if [ $driver = "mysql" ]; then 
    mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE $DBNAME"
  fi 
}

function loadUsers {
   if [ $driver = "sqlite3" ]; then
    mkdir -p $FABRIC_CA_SERVER_HOME
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER);'
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1');"
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1');"

      sed -i "s/type: mysql/type: sqlite3/
          s/datasource:.*/datasource: $DBNAME/" $TESTCONFIG
   fi

   if [ $driver = "postgres" ]; then
     psql -d postgres -c "CREATE DATABASE $DBNAME"
     psql -d $DBNAME -c "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"
     psql -d $DBNAME -c "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
     psql -d $DBNAME -c "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"

     sed -i "s/type: mysql/type: postgres/
          s/datasource:.*/datasource: host=localhost port=$POSTGRES_PORT user=postgres password=postgres dbname=$DBNAME $postgresTls/" $TESTCONFIG
   fi

   if [ $driver = "mysql" ]; then 
     mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE $DBNAME"
     mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"
     mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
     mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
	VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
   fi 
}

function validateUsers {
  local result=$1
  : ${result:= 0}
  if [ $driver = "sqlite3" ]; then
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'registrar');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 1; then
      ErrorMsg "Failed to correctly migrate user 'registar' on sqlite"
    fi
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'notregistrar');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 0; then
      ErrorMsg "Failed to correctly migrate user 'notregistar' on sqlite"
    fi
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'a');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq $result; then
      ErrorMsg "Failed to correctly migrate user 'a' on sqlite"
    fi
  fi

  if [ $driver = "postgres" ]; then
    psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'registrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 1; then
      ErrorMsg "Failed to correctly migrate user 'registrar' on postgres"
    fi
    psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'notregistrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 0; then
      ErrorMsg "Failed to correctly migrate user 'notregistrar' on postgres"
    fi
    psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'a')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq $result; then
      ErrorMsg "Failed to correctly migrate user 'a' on postgres"
    fi
  fi

  if [ $driver = "mysql" ]; then
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'registrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 1; then
      ErrorMsg "Failed to correctly migrate user 'registrar' on mysql"
    fi
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'notregistrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq 0; then
      ErrorMsg "Failed to correctly migrate user 'notregistrar' on mysql"
    fi
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'a')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
    if test $? -eq $result; then
      ErrorMsg "Failed to correctly migrate user 'a' on mysql"
    fi
  fi
}

version=$(grep "BASE_VERSION .*" $FABRIC_CA/Makefile)
baseversion=${version#*=} # Getting only the version value
serverversion=${baseversion//[[:blank:]]/} # Remove any spaces
echo "server version: $serverversion"

# Starting server with a configuration file that is a higher version than the server executable fail
genConfig "9.9.9.9"
fabric-ca-server start -b a:b -c $TESTCONFIG -d
if test $? -ne 1; then
    ErrorMsg "Should have failed to start server"
fi

for driver in sqlite3 postgres mysql; do
 
   # Initializing a server with a database that has a higher version than the server executable
   resetDB
   createDB

  if [ $driver = "sqlite3" ]; then
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property));'
    sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'INSERT INTO properties (property, value) Values ("version", "9.9.9.9");'
  fi

  if [ $driver = "postgres" ]; then
    psql -d $DBNAME -c "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    psql -d $DBNAME -c "INSERT INTO properties (property, value) Values ('version', '9.9.9.9')"
  fi

  if [ $driver = "mysql" ]; then 
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO properties (property, value) Values ('version', '9.9.9.9')"
  fi 
  
  $SCRIPTDIR/fabric-ca_setup.sh -I -D -d $driver
  if ! test $? -eq 0; then
    ErrorMsg "Should have failed to initialize server"
  fi
  $SCRIPTDIR/fabric-ca_setup.sh -K

  resetDB 

  # Testing with a configuration file that does not have "version" present at all
  # Server should start up and update the configuration file and migrate database to 
  # the latest version by updating all registrar users with the 'hf.Registrar.Attribute'
  # attribute
  genConfig "" $driver
  loadUsers

  $SCRIPTDIR/fabric-ca_setup.sh -I -S -D -g $TESTCONFIG
  if test $? -eq 1; then
    ErrorMsg "Failed to start server"
  fi
  $SCRIPTDIR/fabric-ca_setup.sh -K
  grep "$serverversion" $FABRIC_CA_SERVER_HOME/runFabricCaFvt.yaml
  if test $? -ne 0; then
    ErrorMsg "Failed to correctly add version to file"
  fi

  validateUsers 1

  # Starting server with latest version on the configuration file, all registrar currently
  # in database will be migrated any new users defined in the configuration will be loaded as is
  # and will not have migration performed on them
  genConfig $serverversion $driver
  resetDB
  loadUsers

  $SCRIPTDIR/fabric-ca_setup.sh -I -S -D -g $TESTCONFIG
  if test $? -eq 1; then
    ErrorMsg "Failed to start server"
  fi
  $SCRIPTDIR/fabric-ca_setup.sh -K

  validateUsers
  resetDB
done

# Testing with a configuration file that has an older version
# Server should start up and update the configuration file
# for all the CAs that are started
rm -rf $FABRIC_CA_SERVER_HOME/*
mkdir -p $FABRIC_CA_SERVER_HOME/ca/ca1
mkdir $FABRIC_CA_SERVER_HOME/ca/ca2

genConfig "0.0.0.0"
sed -i "s/type: mysql/type: sqlite3/
    s/datasource:.*/datasource: $DBNAME/" $TESTCONFIG

cp $TESTCONFIG $FABRIC_CA_SERVER_HOME/ca/ca1/testconfig_ca1.yaml
echo "
ca:
  name: ca1
  
csr:
  cn: ca1" >> $FABRIC_CA_SERVER_HOME/ca/ca1/testconfig_ca1.yaml

cp $TESTCONFIG $FABRIC_CA_SERVER_HOME/ca/ca2/testconfig_ca2.yaml
echo "
ca:
  name: ca2

csr:
  cn: ca2" >> $FABRIC_CA_SERVER_HOME/ca/ca2/testconfig_ca2.yaml

fabric-ca-server start -b a:b -c $TESTCONFIG -d --cafiles $FABRIC_CA_SERVER_HOME/ca/ca1/testconfig_ca1.yaml --cafiles $FABRIC_CA_SERVER_HOME/ca/ca2/testconfig_ca2.yaml &
sleep 5
pid=$(pidof fabric-ca-server)
killserver $pid

grep "$serverversion" $TESTCONFIG > /dev/null
if test $? -ne 0; then
    ErrorMsg "Failed to correctly add version to default CA file"
fi
grep "$serverversion" $FABRIC_CA_SERVER_HOME/ca/ca1/testconfig_ca1.yaml > /dev/null
if test $? -ne 0; then
    ErrorMsg "Failed to correctly add version to ca1 file"
fi
grep "$serverversion" $FABRIC_CA_SERVER_HOME/ca/ca2/testconfig_ca2.yaml > /dev/null
if test $? -ne 0; then
    ErrorMsg "Failed to correctly add version to ca2 file"
fi

CleanUp $RC
exit $RC