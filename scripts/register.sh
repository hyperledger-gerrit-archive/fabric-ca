#!/bin/bash 
COP="$GOPATH/src/github.com/hyperledger/fabric-ca"
COPEXEC="$COP/bin/fabric-ca"
TESTDATA="$COP/testdata"
SCRIPTDIR="$COP/scripts"
HOST="http://localhost:8888"
RC=0
. $SCRIPTDIR/fabric-ca_utils

while getopts "u:t:g:a:x:" option; do
  case "$option" in
     x)   DATADIR="$OPTARG" ;;
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG";
          test -z "$USERGRP" && NULLGRP='true' ;;
     a)   USERATTR="$OPTARG" ;;
  esac
done

test -z $DATADIR && DATADIR="$HOME/fabric-ca"
CLIENTCERT=$DATADIR/cert.pem
CLIENTKEY=$DATADIR/key.pem

: ${NULLGRP:="false"}
: ${USERNAME:="testuser"}
: ${USERTYPE:="client"}
: ${USERGRP:="bank_a"}
$($NULLGRP) && unset USERGRP
: ${USERATTR:='[{"name":"test","value":"testValue"}]'}
: ${COP_DEBUG="false"}

genClientConfig "$DATADIR/fabric-ca_client.json"

$COPEXEC client register <(echo "{
  \"id\": \"$USERNAME\",
  \"type\": \"$USERTYPE\",
  \"group\": \"$USERGRP\",
  \"attrs\": $USERATTR }") $HOST
RC=$?
$($COP_DEBUG) && printAuth $CLIENTCERT $CLIENTKEY
exit $RC
