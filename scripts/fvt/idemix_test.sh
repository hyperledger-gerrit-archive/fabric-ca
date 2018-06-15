#!/bin/bash

#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
CA_CFG_PATH="/tmp/idemixTesting"
. $SCRIPTDIR/fabric-ca_utils
RC=0

USERNAME="admin"
USERPSWD="adminpw"

function idemixCleanUp() {
    psql -d postgres -c "DROP DATABASE fabric_ca"
    mysql --host=localhost --user=root --password=mysql -e "drop database fabric_ca;"
    rm -rf $CA_CFG_PATH
}

#####################################################################
# Testing Idemix with Postgres
#####################################################################

### Start Fabric CA Server with PosgreSQL Database ###
idemixCleanUp
RHPOOLSIZE=10

export FABRIC_CA_SERVER_IDEMIX_RHPOOLSIZE=$RHPOOLSIZE
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres
pollFabricCa

setTLS
###### Get Idemix Public Key ######

$FABRIC_CA_CLIENTEXEC getcainfo -H $CA_CFG_PATH/$USERNAME -u $PROTO${CA_HOST_ADDRESS}:$PROXY_PORT $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'getcainfo' command"

PUBKEY="$CA_CFG_PATH/$USERNAME/msp/IssuerPublicKey"
if [ ! -f $PUBKEY ]; then
    ErrorMsg "Issuer Public Key was not stored in the correct location"
fi

###### Get Idemix Credential ######

$FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME}:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME --enrollment.type idemix -d $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command"

CLIENTCERT="$CA_CFG_PATH/$USERNAME/msp/user/SignerConfig"
if [ ! -f $CLIENTCERT ]; then
    ErrorMsg "Idemix credential was not stored in the correct location"
fi

###### Issue other commands using Idemix Credential ######

$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name testuser1 -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"

$FABRIC_CA_CLIENTEXEC affiliation list -H $CA_CFG_PATH/$USERNAME -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'affiliation list' command"

$FABRIC_CA_CLIENTEXEC identity list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'identity list' command"

$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'certificate list' command"

$FABRIC_CA_CLIENTEXEC gencrl -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'gencrl' command"

$FABRIC_CA_CLIENTEXEC gencsr --csr.cn testGenCSR -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'gencsr' command"

###### Revoking an identity that has both x509 and Idemix credentials #######

USERNAME2="admin2"
USERPSWD2="adminpw2"

$FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME2}:$USERPSWD2@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME2 --enrollment.type idemix $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'admin2' - idemix"

$FABRIC_CA_CLIENTEXEC revoke --revoke.name admin2 -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'revoke' command"

$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME2 --id.name testuser2 -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 1 || ErrorMsg "Should fail to complete 'register' command, the user with an Idemix credential has been revoked"

###### Use up the RH Pool with idemix enrollments ######

# Starting count at 3 because already enrolled 2 users above (admin and admin2)
for i in $(seq 3 $((RHPOOLSIZE)))
    do
    $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name user$i --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"
    $FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}user$i:user$i@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/user$i --enrollment.type idemix $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'user$i' - idemix"
done

# Epoch verification is currently disabled in 1.1, even thought a RH Pool Size was exhausted
# and a new Epoch verification was generated this should fail since caller has an outdated CRI
# in it's singerConfig. This will start to fail when Epoch verification is enabled again.
$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name newUser --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"

$SCRIPTDIR/fabric-ca_setup.sh -K

#####################################################################
# Testing Idemix with MySQL
#####################################################################

### Start Fabric CA Server with MySQL Database ###
RHPOOLSIZE=10

export FABRIC_CA_SERVER_IDEMIX_RHPOOLSIZE=$RHPOOLSIZE
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d mysql
pollFabricCa

setTLS
###### Get Idemix Public Key ######

$FABRIC_CA_CLIENTEXEC getcainfo -H $CA_CFG_PATH/$USERNAME -u $PROTO${CA_HOST_ADDRESS}:$PROXY_PORT $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'getcainfo' command"

PUBKEY="$CA_CFG_PATH/$USERNAME/msp/IssuerPublicKey"
if [ ! -f $PUBKEY ]; then
    ErrorMsg "Issuer Public Key was not stored in the correct location"
fi

###### Get Idemix Credential ######

$FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME}:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME --enrollment.type idemix -d $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command"

CLIENTCERT="$CA_CFG_PATH/$USERNAME/msp/user/SignerConfig"
if [ ! -f $CLIENTCERT ]; then
    ErrorMsg "Idemix credential was not stored in the correct location"
fi

###### Issue other commands using Idemix Credential ######

$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name testuser1 -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"

$FABRIC_CA_CLIENTEXEC affiliation list -H $CA_CFG_PATH/$USERNAME -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'affiliation list' command"

$FABRIC_CA_CLIENTEXEC identity list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'identity list' command"

$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'certificate list' command"

$FABRIC_CA_CLIENTEXEC gencrl -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'gencrl' command"

$FABRIC_CA_CLIENTEXEC gencsr --csr.cn testGenCSR -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'gencsr' command"

###### Revoking an identity that has both x509 and Idemix credentials #######

USERNAME2="admin2"
USERPSWD2="adminpw2"

$FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME2}:$USERPSWD2@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME2 --enrollment.type idemix $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'admin2' - idemix"

$FABRIC_CA_CLIENTEXEC revoke --revoke.name admin2 -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'revoke' command"

$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME2 --id.name testuser2 -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 1 || ErrorMsg "Should fail to complete 'register' command, the user with an Idemix credential has been revoked"

###### Use up the RH Pool with idemix enrollments ######

# Starting count at 3 because already enrolled 2 users above (admin and admin2)
for i in $(seq 3 $((RHPOOLSIZE)))
    do
    $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name user$i --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"
    $FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}user$i:user$i@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/user$i --enrollment.type idemix $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'user$i' - idemix"
done

# Epoch verification is currently disabled in 1.1, even thought a RH Pool Size was exhausted
# and a new Epoch verification was generated this should fail since caller has an outdated CRI
# in it's singerConfig. This will start to fail when Epoch verification is enabled again.
$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name newUser --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"

$SCRIPTDIR/fabric-ca_setup.sh -K

idemixCleanUp
CleanUp $RC
exit $RC
