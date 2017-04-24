#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

trap "kill $HTTP_PID; CleanUp" INT

$($FABRIC_TLS) && TLS="-T"

# Run the LDAP test cases
function runTests {
   echo "Running LDAP test cases ..."
   cd $FABRIC_CA/lib/ldap
   go test . -cover | tee /tmp/ldap-test.results
   echo "LDAP test cases are complete"
}

runTests
$FABRIC_CA/scripts/check_test_results /tmp/ldap-test.results
RC=$?
CleanUp $RC
exit $RC
