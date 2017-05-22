#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HOST="http://localhost:8888"
RC=0
$($FABRIC_TLS) && HOST="https://localhost:8888"

while getopts "du:p:t:l:x:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
     u)   USERNAME="$OPTARG" ;;
     p)   USERPSWD="$OPTARG"
          test -z "$USERPSWD" && AUTH=false
     ;;
     t)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done
test -z "$CA_CFG_PATH" && CA_CFG_PATH="$HOME/fabric-ca"
test -z "$CLIENTCERT" && CLIENTCERT="$CA_CFG_PATH/cert.pem"
test -z "$CLIENTKEY" && CLIENTKEY="$CA_CFG_PATH/key.pem"
test -f "$CA_CFG_PATH" || mkdir -p $CA_CFG_PATH

: ${FABRIC_CA_DEBUG="false"}
: ${AUTH="true"}
: ${USERNAME="admin"}
: ${USERPSWD="adminpw"}
$($AUTH) || unset USERPSWD
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}

test "$KEYTYPE" = "ecdsa" && sslcmd="ec"

genClientConfig "$CA_CFG_PATH/client-config.json"
$FABRIC_CAEXEC client enroll "$USERNAME" "$USERPSWD" "$HOST" <(echo "{
    \"hosts\": [
        \"admin@fab-client.raleigh.ibm.com\",
        \"fab-client.raleigh.ibm.com\",
        \"127.0.0.2\"
    ],
    \"CN\": \"$USERNAME\",
    \"key\": {
        \"algo\": \"$KEYTYPE\",
        \"size\": $KEYLEN
    },
    \"names\": [
        {
            \"SerialNumber\": \"$USERNAME\",
            \"O\": \"Hyperledger\",
            \"O\": \"Fabric\",
            \"OU\": \"FABRIC_CA\",
            \"OU\": \"FVT\",
            \"STREET\": \"Miami Blvd.\",
            \"DC\": \"peer\",
            \"UID\": \"admin\",
            \"L\": \"Raleigh\",
            \"L\": \"RTP\",
            \"ST\": \"North Carolina\",
            \"C\": \"US\"
        }
    ]
}")
RC=$?
$($FABRIC_CA_DEBUG) && printAuth $CLIENTCERT $CLIENTKEY
exit $RC
