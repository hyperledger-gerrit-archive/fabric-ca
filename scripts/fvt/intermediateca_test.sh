#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
export driver="sqlite3"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"

PATH=/usr/local/bin:$PATH
. $SCRIPTDIR/fabric-ca_utils
RC=0
rm -rf $TDIR
setTLS
TDIR=/tmp/intermediateca-tests
PROTO="http://"
: ${FABRIC_TLS:="false"}
if $($FABRIC_TLS); then
   tlsopts="--tls.enabled --tls.certfile $TESTDATA/tls_server-cert.pem --tls.keyfile $TESTDATA/tls_server-key.pem"
   PROTO="https://"
fi
FABRIC_CA_SERVER_HOME="$TDIR/root" fabric-ca-server start $tlsopts -b admin:adminpw -d 2>&1 | tee $TDIR/root/server.log &
pollServer fabric-ca-server localhost 7054 10
FABRIC_CA_SERVER_HOME="$TDIR/int1" fabric-ca-server start $tlsopts -b admin:adminpw -u ${PROTO}admin:adminpw@localhost:7054 -p 7055 -d 2>&1 | tee $TDIR/int1/server.log &
pollServer fabric-ca-server localhost 7055 10
FABRIC_CA_SERVER_HOME="$TDIR/int2" fabric-ca-server init $tlsopts -b admin:adminpw -u ${PROTO}admin:adminpw@localhost:7055 -d 2>&1
test $? -eq 0 && let RC+=1
kill $(ps -x -o pid,comm | awk '$2~/fabric-ca-serve/ {print $1}')
CleanUp "$RC"
exit $RC
