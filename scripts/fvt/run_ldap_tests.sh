#!/bin/bash 
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0

trap "kill $HTTP_PID; CleanUp" INT

$($FABRIC_TLS) && TLS="-T"

# Add a user
function addUser {
   local ldapHost="localhost" 
   local ldapPort="10389"
   local ldifFile="$TESTDATA/add-user.ldif"
   local ldapAdmin="cn=admin,dc=example,dc=com"
   local ldapAdminPwd="admin"
   local ldapUser="uid=jsmith,dc=example,dc=com"
   local ldapUserPwd="jsmithpw"
   ldapadd    -h $ldapHost -p $ldapPort \
              -cxD $ldapAdmin  -w $ldapAdminPwd -f $ldifFile
   ldappasswd -h $ldapHost -p $ldapPort \
              -xD $ldapAdmin  -w $ldapAdminPwd \
               $ldapUser   -s $ldapUserPwd
   return $?
}

# Run the LDAP test cases
function runTests {
   echo "Running LDAP test cases ..."
   cd $FABRIC_CA/lib/ldap
   go test . -cover | tee /tmp/ldap-test.results
   echo "LDAP test cases are complete"
}

addUser || ErrorExit "Failed to add user"
runTests
$FABRIC_CA/scripts/check_test_results /tmp/ldap-test.results
RC=$?
CleanUp $RC
exit $RC
