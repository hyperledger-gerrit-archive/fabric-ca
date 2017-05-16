#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

export driver="sqlite3"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
TDIR=/tmp/intermediateca-tests
PROTO="http://"
ROOT_CA_ADDR=localhost
CA_PORT=7054
TLSDIR="/tmp/hyperledger/fabric-ca/tls"

function setupTLScerts() {
   oldhome=$HOME
   rm -rf $TLSDIR
   mkdir -p $TLSDIR
   rm -rf /tmp/CAs $TLSDIR/rootTlsCa* $TLSDIR/subTlsCa*
   export HOME=$TLSDIR
   # Root TLS CA
   $SCRIPTDIR/utils/pki -f newca -a rootTlsCa -t ec -l 256 -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=localhost/" -S "IP:127.0.0.1" -d sha256 -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" -e 20370101000000Z -s 20160101000000Z -p rootTlsCa- >/dev/null 2>&1
   # Sub TLS CA
   $SCRIPTDIR/utils/pki -f newsub -b subTlsCa -a rootTlsCa -t ec -l 256 -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=subTlsCa/" -S "IP:127.0.0.1" -d sha256 -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" -e 20370101000000Z -s 20160101000000Z -p subTlsCa- >/dev/null 2>&1
   # EE TLS certs
   for i in {1..10}; do
   rm -rf $TLSDIR/intFabCaTls${i}*
   $SCRIPTDIR/utils/pki -f newcert -a subTlsCa -t ec -l 256 -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=intFabCaTls${i}/" -S "IP:127.0.${i}.1" -d sha512 -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" -e 20370101000000Z -s 20160101000000Z -p intFabCaTls${i}- >/dev/null 2>&1 <<EOF
y
y
EOF
   done
   cat $TLSDIR/rootTlsCa-cert.pem $TLSDIR/subTlsCa-cert.pem > $TLSDIR/tlsroots.pem
   HOME=$oldhome
}

setupTLScerts

setTLS
rm -rf $TDIR
: ${FABRIC_TLS:="false"}
if $($FABRIC_TLS); then
   setupTLScerts
   PROTO="https://"
fi

# Start RootCA
$($FABRIC_TLS) && tlsopts="--tls.enabled --tls.certfile $TLSDIR/rootTlsCa-cert.pem --tls.keyfile $TLSDIR/rootTlsCa-key.pem"
mkdir -p "$TDIR/root"
FABRIC_CA_SERVER_HOME="$TDIR/root" fabric-ca-server start --csr.hosts $ROOT_CA_ADDR --address $ROOT_CA_ADDR $tlsopts -b admin:adminpw -d 2>&1 | tee $TDIR/root/server.log &
pollServer fabric-ca-server $ROOT_CA_ADDR $CA_PORT 10

# Start 10 intermediate CAs
for i in {1..10}; do
   mkdir -p "$TDIR/int${1}"
  $($FABRIC_TLS) && tlsopts="--tls.enabled --tls.certfile $TLSDIR/intFabCaTls${i}-cert.pem --tls.keyfile $TLSDIR/intFabCaTls${i}-key.pem --intermediate.tls.certfiles $TLSDIR/tlsroots.pem"
  ADDR=127.0.${i}.1
  FABRIC_CA_SERVER_HOME="$TDIR/int${1}" fabric-ca-server start --csr.hosts $ADDR --address $ADDR $tlsopts -b admin:adminpw -u ${PROTO}admin:adminpw@$ROOT_CA_ADDR:$CA_PORT -d 2>&1 | tee $TDIR/int${i}/server.log &
  pollServer fabric-ca-server $ADDR $CA_PORT 10
done

last=$((i+1))
$($FABRIC_TLS) && tlsopts="--tls.enabled --tls.certfile $TLSDIR/intFabCaTls${last}-cert.pem --tls.keyfile $TLSDIR/intFabCaTls${last}-key.pem --intermediate.tls.certfiles $TLSDIR/tlsroots.pem"
FABRIC_CA_SERVER_HOME="$TDIR/int2" fabric-ca-server init --csr.hosts 127.0.${last}.1 --address 127.0.${last}.1 $tlsopts -b admin:adminpw -u ${PROTO}admin:adminpw@$ADDR:$CA_PORT -d 2>&1 | tee $TDIR/int${i}/server.log
test ${PIPESTATUS[0]} -eq 0 && let RC+=1
$SCRIPTDIR/fabric-ca_setup.sh -L
kill $(ps -x -o pid,comm | awk '$2~/fabric-ca-serve/ {print $1}')
CleanUp "$RC"
rm -rf $TDIR
exit $RC




+ local FABRIC_CA_ENROLLMENT_DIR=/tmp/admin
+ local FABRIC_CA_CERT_FILE=/tmp/admin/msp/signcerts/cert.pem
+ local FABRIC_CA_KEY_FILE=/tmp/admin/msp/keystore/key.pem
+ local FABRIC_CA_CLIENT_HOME=/tmp/admin
+ local HOST=localhost
+ local PORT=8888
+ local RC=0
+ export FABRIC_CA_CLIENT_HOME
+ export FABRIC_CA_ENROLLMENT_DIR
+ test -d /tmp/admin
+ mkdir -p /tmp/admin
+ ENROLLCONFIG=/tmp/admin/enroll.yaml
+ setTLS
+ PROTO=http://
+ TLSOPT=
+ test -n true
++ true
+ PROTO=https://
+ TLSOPT='--tls.certfiles /opt/gopath/src/github.com/hyperledger/fabric-ca/testdata/root.pem'
+ /usr/local/bin/fabric-ca-client enroll -u https://admin:adminpw@localhost:8888 --tls.certfiles /opt/gopath/src/github.com/hyperledger/fabric-ca/testdata/root.pem -c /tmp/admin/enroll.yaml --csr.hosts admin@fab-client.raleigh.ibm.com --csr.hosts admin.fabric.raleigh.ibm.com,127.0.0.2
2017/06/16 19:57:57 [INFO] User provided config file: /tmp/admin/enroll.yaml
2017/06/16 19:57:57 [INFO] Created a default configuration file at /tmp/admin/enroll.yaml
2017/06/16 19:57:57 [INFO] generating key: &{A:ecdsa S:256}
2017/06/16 19:57:57 [INFO] encoded CSR
2017/06/16 19:57:57 [INFO] TLS Enabled
Error: Error response from server was: Authorization failure

