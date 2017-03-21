#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HOST="127.0.0.1:10888"
echo $HOST
RC=0
HTTP_PORT="3755"
CA_CFG_PATH="/tmp/fabric-ca/roundrobin"
export CA_CFG_PATH

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp 1; exit 1" INT

$SCRIPTDIR/fabric-ca_setup.sh -R
for driver in sqlite3 mysql postgres ; do
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -t rsa -l 2048 -d $driver
   test $? -ne 0 && ErrorExit "Failed to setup server"
   $SCRIPTDIR/registerAndEnroll.sh -u 'user1 user2 user3 user4 user5 user6 user7 user8 user9'
   test $? -ne 0 && ErrorMsg "registerAndEnroll failed"
   reenroll admin
   if test "$FABRIC_TLS" = 'false'; then
      for s in 1 2 3 4; do
         curl -s http://$HOST/ | awk -v s="server${s}" '$0~s'|html2text | egrep "HTTP|server${s}"
         verifyServerTraffic $HOST server${s} 5
         test $? -ne 0 && ErrorMsg "verifyServerTraffic failed"
      done
   fi
   $SCRIPTDIR/fabric-ca_setup.sh -L
   $SCRIPTDIR/fabric-ca_setup.sh -R
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
