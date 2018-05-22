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

USERNAME="admin"
USERPSWD="adminpw"

#####################################################################
# Testing Idemix with Postgres
#####################################################################

### Start Fabric CA Server with MySQL Database ###

psql -d fabric_ca -c "TRUNCATE TABLE users"
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres
pollFabricCa

###### Get Idemix Public Key ######

$FABRIC_CA_CLIENTEXEC getcainfo -H $CA_CFG_PATH/$USERNAME
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'getcainfo' command"
fi
PUBKEY="$CA_CFG_PATH/$USERNAME/msp/IssuerPublicKey"
if [ ! -f $PUBKEY ]; then
    ErrorMsg "Issuer Public Key was not stored in the correct location"
fi

###### Get Idemix Credential ######

$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME --enrollment.type idemix
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'enroll' command"
fi
CLIENTCERT="$CA_CFG_PATH/$USERNAME/msp/user/SignerConfig"
if [ ! -f $CLIENTCERT ]; then
    ErrorMsg "Idemix credential was not stored in the correct location"
fi

###### Issue other commands using Idemix Credential ######

$FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name testuser1 -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'register' command"
fi

$FABRIC_CA_CLIENTEXEC affiliation list -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'register' command"
fi

$FABRIC_CA_CLIENTEXEC identity list -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'identity' command"
fi

$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'certificate' command"
fi

$FABRIC_CA_CLIENTEXEC gencrl -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'gencrl' command"
fi

$FABRIC_CA_CLIENTEXEC gencsr --csr.cn testGenCSR -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'gencsr' command"
fi

psql -d fabric_ca -c "TRUNCATE TABLE certificates"

$FABRIC_CA_CLIENTEXEC reenroll --csr.cn testGenCSR -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 1 ]; then
    ErrorMsg "Reenroll should have failed, since identity has no x509 credentials"
fi

USERNAME2="admin2"
USERPSWD2="adminpw2"

$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME2:$USERPSWD2@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME2 --enrollment.type idemix
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'enroll' command for 'admin2' - idemix"
fi

$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME2:$USERPSWD2@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME2
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'enroll' command for 'admin2' - x509"
fi

$FABRIC_CA_CLIENTEXEC revoke --revoke.name admin2 -H $CA_CFG_PATH/$USERNAME -d
if [ $? != 0 ]; then
    ErrorMsg "Failed to complete 'revoke' command"
fi
###### Get Idemix CRI ######

$SCRIPTDIR/fabric-ca_setup.sh -K
