#!/bin/bash 
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function checkPasswd() {
   set -f
   # Extract password value(s) from logfile
   passwd=$(egrep -o "Pass:[^[:space:]]+" $LOGFILE| awk -F':' '{print $2}')

   # Fail if password is empty
   if [[ -z "$passwd" ]] ; then
      ErrorMsg "Unable to extract password value(s)"
   fi

   # Fail if password matches anything other than '*'
   for p in $passwd; do 
      if ! [[ "$p" =~ \*+ ]]; then
         ErrorMsg "Passwords were not masked in the log"
      fi
   done
   set +f
}

RC=0
TESTCASE="passwordsInLog"
TESTDIR="/tmp/$TESTCASE"
mkdir -p $TESTDIR

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils

export CA_CFG_PATH="$TESTDIR"
export FABRIC_CA_SERVER_HOME="$TESTDIR"
LOGFILE=$FABRIC_CA_SERVER_HOME/log.txt

USER=administrator
PSWD=administratorpw

# Test using bootstrap ID
fabric-ca-server init -b $USER:$PSWD -d 2>&1 | tee $LOGFILE
test $? -ne 0 && ErrorMsg "Init of CA failed"
checkPasswd

# Test using multiple IDs from pre-supplied config file
$SCRIPTDIR/fabric-ca_setup.sh -R
mkdir -p $TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -I -X -n1 -D 2>&1 | tee $LOGFILE 
checkPasswd

CleanUp $RC
exit $RC
