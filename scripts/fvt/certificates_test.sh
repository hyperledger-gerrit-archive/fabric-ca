#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:="certificates"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0

USERNAME="admin"
USERPSWD="adminpw"

DBNAME=fabric_ca

function postgresDBCleanup() {
    psql -d $DBNAME -c "TRUNCATE TABLE certificates" &> /dev/null
}

function populatePostgresCertsTable() {
    # Expired and Not Revoked
    insertCertsTable "user1" "1111" "2222" "11/18/2017" "01/01/0001"
    insertCertsTable "user2" "1112" "2223" "1/18/2018" "01/01/0001"
    insertCertsTable "user3" "1111" "2223" "1/18/2018" "01/01/0001"
    insertCertsTable "user3" "1111" "2224" "1/18/2018" "01/01/0001"
    insertCertsTable "user4" "1113" "2224" "1/25/2018" "01/01/0001"

    # Not Expired and Not Revoked
    NewDate=$(date "+%Y-%m-%d %H:%M:%S" -d "+20 days")
    insertCertsTable "user5" "1114" "2225" "$NewDate" "01/01/0001"

    # Revoked and Not Expired
    insertCertsTable "user5" "1115" "2225" "$NewDate" "2/18/2018"
    insertCertsTable "user6" "1116" "2225" "$NewDate" "2/18/2017"
    insertCertsTable "user7" "1117" "2225" "$NewDate" "1/18/2018"

    # Revoked and Expired
    insertCertsTable "user8" "1118" "2225" "1/30/2018" "1/18/2018"
}

function insertCertsTable() {
    local id="$1"
    local serial="$2"
    local aki="$3"
    local expiry="$4"
    local revokedAt="$5"

    # Generate certificates with the common name set to a user
    echo "Generating certificate for $id"
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=$id"
    pem=`cat cert.pem`

    # Store the generated certificate in the certificates table
    psql -d $DBNAME -c "INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level) VALUES ('$id', '$serial', '$aki', 'ca', 'active', '0', '$expiry', '$revokedAt', '$pem', '1')"
}

#####################################################################
# Testing Certificates API with Postgres
#####################################################################

###### Start Fabric CA Server with Postgres Database #######

postgresDBCleanup
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres
pollFabricCa
populatePostgresCertsTable

#### Enroll user first, so subsequent commands can be called ####
$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME
if [ $? != 0 ]; then
    ErrorMsg "Failed to enroll user"
fi

#### Test various filters for the list certificates commands #####

## List all certificates ##
$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command"

## List certificate by ID ##

$FABRIC_CA_CLIENTEXEC certificate list --id user1 -H $CA_CFG_PATH/$USERNAME | grep "user1"
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'id' filter"

## List certificate by Serial Number ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user1" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'serial' filter, user1 certificate not returned"
grep "user3" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'serial' filter, user3 certificate not returned"

## List certificate by Serial Number and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --id user1 -H $CA_CFG_PATH/$USERNAME --store $CA_CFG_PATH/$USERNAME> output.txt
grep "user1" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'serial' filter, user1 certificate not returned"
grep "user3" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'serial' and 'id' filter, user3 certificate should not be returned"
if [ ! -f $CA_CFG_PATH/$USERNAME/user1.pem ]; then
    ErrorMsg "Failed to store certificate in the specified location"
fi

## List certificate by AKI ##

$FABRIC_CA_CLIENTEXEC certificate list --aki 2223 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user2" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'aki' filter, user2 certificate not returned"
grep "user3" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'aki' filter, user3 certificate not returned"

## List certificate by Serial Number, AKI, and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --aki 2224 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user3" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'serial', 'aki', and 'id' filters, user3 certificate not returned"
grep "2223" output.txt
test $? == 1 || ErrorMsg "Incorrectly got certificate for 'user3'"

## List certificate within expiration range ##

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-03-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user5" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user5 certificate not returned"

$FABRIC_CA_CLIENTEXEC certificate list --expiration ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user1" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user1 certificate not returned"
grep "user2" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'expiration' filter, user2 certificate should not be returned"

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user1" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'expiration' filter, user1 certificate should not be returned"
grep "user2" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user2 certificate not returned"
grep "user3" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user3 certificate not returned"
grep "user4" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user4 certificate not returned"

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user2" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'expiration' filter, user2 certificate should not be returned"
grep "user3" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'expiration' filter, user3 certificate not returned"

## List certificate within revocation range ##

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-02-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user5" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'revocation' filter, user5 certificate not returned"

$FABRIC_CA_CLIENTEXEC certificate list --revocation ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user6" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'revocation' filter, user6 certificate not returned"
grep "user5" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'revocation' filter, user5 certificate should not be returned"

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-02-01 -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user5" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'revocation' filter, user5 certificate should not be returned"
grep "user6" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'revocation' filter, user6 certificate should not be returned"
grep "user7" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'revocation' filter, user7 certificate not returned"

## List certificates within expiration range but have not been revoked ##
$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-20::2018-01-30 --notrevoked -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user4" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'revocation' and 'notexpired' filter, user4 certificate not returned"
grep "user8" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'expiration' and 'notrevoked' filter, user8 certificate should not be returned"

## List certificates within revocation range but have not expired ##
$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-01-30 --notexpired -H $CA_CFG_PATH/$USERNAME > output.txt
grep "user7" output.txt
test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with 'revocation' and 'notexpired' filter, user7 certificate not returned"
grep "user8" output.txt
test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with 'revocation' and 'notexpired' filter, user8 certificate should not be returned"

$SCRIPTDIR/fabric-ca_setup.sh -K
postgresDBCleanup

