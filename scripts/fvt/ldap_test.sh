#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
export CA_CFG_PATH="/tmp/ldap"
export UDIR="/tmp/users"

rm -rf $UDIR
mkdir -p $UDIR

users1=( admin admin2 revoker revoker2 nonrevoker nonrevoker2 notadmin expiryUser testUser testUser2 )
users2=( testUser3 )

$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -a -D -X -S -n1

for u in ${users1[*]}; do
   export CA_CFG_PATH=$UDIR
   enroll $u ${u}pw
   test $? -ne 0 && ErrorMsg "Failed to enroll $u"
done

# Sleep for more than the idle connection timeout limit of 1 second
sleep 3

for u in ${users2[*]}; do
   export CA_CFG_PATH=$UDIR
   enroll $u ${u}pw
   test $? -ne 0 && ErrorMsg "Failed to enroll $u"
done

# User 'revoker' revokes identity 'testUser'
URI=$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT
export FABRIC_CA_CLIENT_HOME=$UDIR/revoker
$FABRIC_CA_CLIENTEXEC revoke -u $URI -e testUser $TLSOPT
test "$?" -eq 0 || ErrorMsg "User 'revoker' failed to revoke user 'testUser'"

echo "HERE"
echo "export FABRIC_CA_CLIENT_HOME=$UDIR/revoker"
echo "$FABRIC_CA_CLIENTEXEC revoke -u $URI -e testUser $TLSOPT"

#rm -rf $UDIR
CleanUp $RC
exit $RC
