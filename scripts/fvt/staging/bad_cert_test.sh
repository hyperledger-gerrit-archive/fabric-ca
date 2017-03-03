#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
PKI="$SCRIPTDIR/utils/pki"
RC=0
export CA_CFG_PATH="/tmp/fabric-ca/badcert"
CERT_HOME="/tmp/CAs/"
SERVER_CERT="$CA_CFG_PATH/fabric-ca-cert.pem"
SERVER_KEY="$CA_CFG_PATH/fabric-ca-key.pem"
CLIENT_CERT="$CA_CFG_PATH/admin/cert.pem"
CLIENT_KEY="$CA_CFG_PATH/admin/key.pem"

trap "CleanUp 1; exit 1" INT

curr_year=$(date +"%g")
next_year=$((curr_year+1))
prev_year=$((curr_year-1))

past=$(date +"$prev_year%m%d%H%M%SZ")
now=$(date +"%g%m%d%H%M%SZ")
future=$(date +"$next_year%m%d%H%M%SZ")

rm -rf $CERT_HOME/ROOT_CERT1 $HOME/ROOT_CERT1*
rm -rf $CERT_HOME/ROOT_CERT2 $HOME/ROOT_CERT2*
rm -rf $CERT_HOME/NOT_A_CA  $HOME/NOT_A_CA*
rm -rf $CERT_HOME/BAD_START_CA $HOME/BAD_START_CA*
rm -rf $CERT_HOME/BAD_END_CA $HOME/BAD_END_CA*
rm -rf $CERT_HOME/INVALID_USE $HOME/INVALID_USE*
rm -rf $CERT_HOME/UNSUPPORTED $HOME/UNSUPPORTED-
rm -rf $CERT_HOME/INSECURE_KEY $HOME/INSECURE_KEY-

$PKI -f newca -a ROOT_CERT1 -n "/CN=ROOT_CERT1/"
$PKI -f newca -a ROOT_CERT2 -n "/CN=ROOT_CERT2/"
$PKI -f newsub -a ROOT_CERT1 -b BAD_START_CA -s $future -n "/CN=BAD_START_CA/" <<EOF
y
y
EOF
$PKI -f newsub -a ROOT_CERT1 -b BAD_END_CA -e $past -n "/CN=BAD_END_CA/" <<EOF
y
y
EOF
$PKI -f newsub -a ROOT_CERT1 -b INSECURE_KEY -n "/CN=INSECURE_KEY/" -l 512 <<EOF
y
y
EOF
$PKI -f newcert -a ROOT_CERT1 -p NOT_A_CA- -n "/CN=NOT_A_CA/" <<EOF
y
y
EOF
$PKI -f newcert -K decipherOnly -p INVALID_USE- -n "/CN=INVALID_USE/"
$PKI -f newcert -t dsa -p UNSUPPORTED- -n "/CN=UNSUPPORTED/"

client_key_type="ec"
#for driver in sqlite3 postgres mysql; do
for CA in NOT_A_CA BAD_END_CA BAD_START_CA INVALID_USE UNSUPPORTED; do
   for driver in sqlite3 ; do
      case "$CA" in
         UNSUPPORTED) server_key_type=dsa ;;
         *) server_key_type=rsa ;;
      esac

      echo ""
      echo ""
      echo ""
      echo " ************************************"
      echo " -----> Testing Error case $CA "
      echo " ************************************"
      echo ""
      TESTCERT=$HOME/${CA}-cert.pem
      TESTKEY=$HOME/${CA}-key.pem
      $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
      $SCRIPTDIR/fabric-ca_setup.sh -m 0 -I -S -X -c $TESTCERT -k $TESTKEY
      $($FABRIC_CA_DEBUG) && printAuth $SERVER_CERT $SERVER_KEY
      keyCheck "$SERVER_CERT" "$SERVER_KEY" "$server_key_type"
      if test $? -ne 0; then
         ErrorMsg "Problem creating key pair: $server_key_type Public key of $SERVER_CERT does not match $SERVER_KEY"
         continue
      fi
      enroll
      test $? -eq 0 && ErrorMsg "Enroll of admin unexpectedly succeeded using CAcert $TESTCERT"
      currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
      test "$currId" == "$prevId" && RC=$((RC+1))
      prevId="$currId"
      if $($FABRIC_CA_DEBUG); then
         echo "server certdata ==========>"; printAuth $TESTCERT $TESTKEY
         echo "client certdata ==========>"; printAuth $CLIENT_CERT $CLIENT_KEY
      fi
      keyCheck "$CLIENT_CERT" "$CLIENT_KEY" "$client_key_type"
      test $? -eq 0 && ErrorMsg "Enroll of admin unexpectedly succeeded: $client_key_type Public key of $CLIENT_CERT matches $CLIENT_KEY"
   done
done
#
# wrong public key
server_key_type=rsa
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
$SCRIPTDIR/fabric-ca_setup.sh -m 0 -I -S -X -c $HOME/ROOT_CERT1-cert.pem -k $HOME/ROOT_CERT2-key.pem
test $? -eq 0 && ErrorMsg "Invalid key pair accepted"
$($FABRIC_CA_DEBUG) && printAuth $SERVER_CERT $SERVER_KEY
enroll
test $? -eq 0 && ErrorMsg "Enroll of admin unexpectedly succeeded using CAcert $SERVER_CERT"
currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
test "$currId" == "$prevId" && RC=$((RC+1))
prevId="$currId"
$($FABRIC_CA_DEBUG) && printAuth $CLIENT_CERT $CLIENT_KEY
keyCheck "$CLIENT_CERT" "$CLIENT_KEY" "$client_key_type"
test $? -eq 0 && ErrorMsg "Enroll of admin unexpectedly succeeded: $client_key_type Public key of $CLIENT_CERT matches $CLIENT_KEY"

$SCRIPTDIR/fabric-ca_setup.sh -L
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
CleanUp $RC
exit $RC
