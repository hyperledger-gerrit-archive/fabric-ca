#!/bin/bash
num=$1
: ${num:=1}
COP="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$COP/scripts"
$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -X -S -n $num
