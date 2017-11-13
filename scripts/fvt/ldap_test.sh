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

checkUserCert() {
   # Make sure the "dn" attribute is in the user's certificate
   USER=$1
   CERTFILE=$UDIR/$USER/msp/signcerts/cert.pem
   ATTRS=$(openssl x509 -noout -text -in $CERTFILE | grep '{"attrs":{'| grep '"hf.Revoker"' | grep '"uid"')
   test "$ATTRS" == "" && ErrorMsg "Failed to find hf.Revoker and uid attributes in certificate for user $USER"
}

for u in ${users1[*]}; do
   export CA_CFG_PATH=$UDIR
   enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorMsg "Failed to enroll $u"
   checkUserCert $u
done

# Sleep for more than the idle connection timeout limit of 1 second
sleep 3

for u in ${users2[*]}; do
   export CA_CFG_PATH=$UDIR
   enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorMsg "Failed to enroll $u"
   checkUserCert $u
done

URI=$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT

# User 'revoker' revokes the ecert of user 'testUser'
echo "User 'revoker' is revoking the ecert of user 'testUser' ..."
certFile=$UDIR/testUser/msp/signcerts/cert.pem
AKI=$(openssl x509 -noout -text -in $certFile |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')
RSN1=$(openssl x509 -noout -serial -in $certFile | awk -F'=' '{print toupper($2)}')
export FABRIC_CA_CLIENT_HOME=$UDIR/revoker
$FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $RSN1 $TLSOPT
test "$?" -eq 0 || ErrorMsg "User 'revoker' failed to revoke user 'testUser'"

# User 'admin2' revokes the ecert of user 'testUser2'
echo "User 'admin2' is revoking the ecert of user 'testUser2' ..."
certFile=$UDIR/testUser2/msp/signcerts/cert.pem
AKI=$(openssl x509 -noout -text -in $certFile |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')
RSN2=$(openssl x509 -noout -serial -in $certFile | awk -F'=' '{print toupper($2)}')
$FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $RSN2 $TLSOPT -H $UDIR/admin2
test "$?" -eq 0 || ErrorMsg "User 'admin2' failed to revoke user 'testUser2'"

# User 'notadmin' not authorized to revoke
echo "User 'notadmin' is attempting to revoke the ecert of user 'nonrevoker' ..."
certFile=$UDIR/nonrevoker/msp/signcerts/cert.pem
AKI=$(openssl x509 -noout -text -in $certFile |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')
SN=$(openssl x509 -noout -serial -in $certFile | awk -F'=' '{print toupper($2)}')
$FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $SN $TLSOPT -H $UDIR/notadmin 2>&1| grep 'does not have authority to revoke'
test "$?" -eq 0 || ErrorMsg "User 'notadmin' not authorized (hf.Revoker) to revoke 'nonrevoker'"

# User 'admin' can generate crl
crlfile=$UDIR/admin/msp/crls/crl.pem
echo "User 'admin' is generating a crl ... "
$FABRIC_CA_CLIENTEXEC gencrl -u $URI -H $UDIR/admin $TLSOPT
test "$?" -eq 0 || ErrorMsg "User 'admin' failed to generate a crl"
revoked=$(openssl crl -in $crlfile -noout -text | egrep -c "$RSN1|$RSN2")
test "$revoked" -ne 2 && ErrorMsg "Wrong number of revoked certificates in $crlfile"

# User 'notadmin' cannot generate crl'
echo "User 'notadmin' is attempting to generate a crl ... "
$FABRIC_CA_CLIENTEXEC gencrl -u $URI -H $UDIR/notadmin $TLSOPT 2>&1| grep 'Authorization failure'
test "$?" -eq 0 || ErrorMsg "User 'notadmin' should not generate a crl"


CleanUp $RC
exit $RC
