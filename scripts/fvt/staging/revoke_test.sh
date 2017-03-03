#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
HOST="localhost"
PROTO="http://"
PORT="8888"
TLSOPT=""
setTLS
URI="$PROTO$HOST:$PORT"
USERS=("admin" "admin2" "notadmin")
PSWDS=("adminpw" "adminpw2" "pass")
HTTP_PORT="3755"
KEYSTORE="/tmp/keyStore"
REVOKECONFIG="revoke.json"


# Expected codes
            # user  cert
test1Result="1 good"
test2Result="1 revoked"
test3Result="1 revoked"

function testStatus() {
  local user="$1"
  user_status=$(sqlite3 $DB "SELECT * FROM users WHERE (id=\"$user\");")
  cert_status=$(sqlite3 $DB "SELECT * FROM certificates WHERE (id=\"$user\");")
  user_status_code=$(echo $user_status | awk -F'|' '{print $6}')
  cert_status_code=$(echo $cert_status | awk -F'|' '{print $5}')
  echo "$user_status_code $cert_status_code"
}

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID;CleanUp 1; exit 1" INT

rm -rf $KEYSTORE
mkdir -p $KEYSTORE
FABRIC_CA_SERVER_HOME="$HOME/fabric-ca"
DB="$FABRIC_CA_SERVER_HOME/fabric-ca-server.db"
# Kill any running servers
$SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_SERVER_HOME

# Setup CA server
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -x $FABRIC_CA_SERVER_HOME

# Enroll
i=-1
while test $((i++)) -lt 2; do
   FABRIC_CA_CLIENT_HOME="$KEYSTORE/${USERS[i]}"
   FABRIC_CA_ENROLLMENT_DIR="$KEYSTORE/${USERS[i]}"
   enroll "${USERS[i]}" "${PSWDS[i]}" "$FABRIC_CA_ENROLLMENT_DIR/cert.pem" "$FABRIC_CA_ENROLLMENT_DIR/key.pem"
done

# notadmin cannot revoke
FABRIC_CA_CLIENT_HOME="$KEYSTORE/${USERS[2]}"
echo "CN: ${USERS[2]}" > $FABRIC_CA_CLIENT_HOME/$REVOKECONFIG
$FABRIC_CA_CLIENTEXEC revoke -u $URI -e ${USERS[2]} --eid ${USERS[2]} -c $FABRIC_CA_CLIENT_HOME/$REVOKECONFIG $TLSOPT
test "$?" -eq 0 && ErrorMsg "Non-revoker successfully revoked cert"

# Check the DB contents
test "$(testStatus ${USERS[0]})" = "$test1Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test1Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

# Grab the serial number of admin cert (convert to decimal)
SN=$(echo "ibase=16;$(openssl x509 -noout -serial -in $KEYSTORE/${USERS[0]}/cert.pem | awk -F'=' '{print $2}')" | bc)
# and the auth keyid of admin cert - translate upper to lower case
AKI=$(openssl x509 -noout -text -in $KEYSTORE/${USERS[0]}/cert.pem |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print tolower($0)}')

# Revoke the certs
FABRIC_CA_CLIENT_HOME="$KEYSTORE/${USERS[0]}"
#### Blanket revoke all of admin2 certs
echo "CN: ${USERS[0]}" > $KEYSTORE/${USERS[0]}/$REVOKECONFIG
$FABRIC_CA_CLIENTEXEC revoke -u $URI -e ${USERS[1]} --eid ${USERS[0]} -c $FABRIC_CA_CLIENT_HOME/$REVOKECONFIG $TLSOPT
#### Revoke admin's cert by serial number and authority keyid
$FABRIC_CA_CLIENTEXEC revoke --serial $SN --aki $AKI -u $URI -e ${USERS[0]} --eid ${USERS[0]} -c $FABRIC_CA_CLIENT_HOME/$REVOKECONFIG $TLSOPT

# Verify the DB update
test "$(testStatus ${USERS[0]})" = "$test2Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test2Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

# Veriy that the cert is no longer usable
FABRIC_CA_CLIENT_HOME="$KEYSTORE/${USERS[0]}"
register admin 'user100' client bank_a 'x=y' $FABRIC_CA_CLIENT_HOME
test "$?" -eq 0 && ErrorMsg "${USERS[0]} authenticated with revoked certificate" RC
FABRIC_CA_CLIENT_HOME="$KEYSTORE/${USERS[1]}"
register admin 'user101' client bank_a 'x=y' $FABRIC_CA_CLIENT_HOME
test "$?" -eq 0 && ErrorMsg "${USERS[1]} authenticated with revoked certificate" RC

# Verify the DB update
test "$(testStatus ${USERS[0]})" = "$test3Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test3Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

$SCRIPTDIR/fabric-ca_setup.sh -L
$SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_SERVER_HOME
CleanUp $RC
kill $HTTP_PID
wait $HTTP_PID
exit $RC
