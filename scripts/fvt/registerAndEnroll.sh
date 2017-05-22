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
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

while getopts "du:t:k:l:x:" option; do
  case "$option" in
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
  esac
done

: ${REGISTRAR:="admin"}
: ${CA_CFG_PATH:="/tmp/fabric-ca"}
: ${USERNAME="newclient"}
: ${USERTYPE="client"}
: ${USERGRP="bank_a"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}

FABRIC_CA_CLIENT_HOME=$CA_CFG_PATH/$REGISTRAR
enroll
test $? -eq 0 || ErrorExit "Failed to enroll admin"

for i in $USERNAME; do
   pswd=$(register $REGISTRAR $i $USERTYPE $USERGRP "" $FABRIC_CA_CLIENT_HOME |
                                   tail -n1 | awk '{print $NF}')
   enroll $i $pswd
   RC=$((RC+$?))
   sleep 1
done

exit $RC
