#!/bin/bash 
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
export CA_CFG_PATH="/tmp/revoke_test"
RC=0
# FIXME should not require user:pass
URI="http://user:pass@localhost:8888"
DB="fabric_ca"
USERS=("admin" "admin2" "notadmin" "testUser" "testUser2" "testUser3" )
PSWDS=("adminpw" "adminpw2" "pass" "user1" "user2" "user3" )
#USERS=("admin" "admin2" "notadmin")
#PSWDS=("adminpw" "adminpw2" "pass")
HTTP_PORT="3755"

. $SCRIPTDIR/fabric-ca_utils

# Expected codes
            # user  cert
enrolledGood="1 good"
enrolledRevoked="1 revoked"
revokedRevoked="-1 revoked"
TEST_RESULTS=("$revokedRevoked" "$revokedRevoked" "$enrolledRevoked" "$enrolledRevoked" "$enrolledGood" "$enrolledGood" )

function testStatus() {
   local user="$1"
   local driver="$2"
   : ${driver:="sqlite3"}
   case $driver in 
      sqlite3) 
         user_status=$(sqlite3 $CA_CFG_PATH/$DB "SELECT * FROM users WHERE (id=\"$user\");")
         cert_status=$(sqlite3 $CA_CFG_PATH/$DB "SELECT * FROM certificates WHERE (id=\"$user\");")
         user_status_code=$(echo $user_status | awk -F'|' '{print $6}')
         cert_status_code=$(echo $cert_status | awk -F'|' '{print $5}')
      ;;
      mysql)
         user_status_code=$(mysql --host=localhost --user=root --password=mysql -e "SELECT * FROM users WHERE (id=\"$user\");" $DB| awk -F'\t' -v u=$user '$1~u {print $6}')
         cert_status_code=$(mysql --host=localhost --user=root --password=mysql -e "SELECT * FROM certificates WHERE (id=\"$user\");" $DB| awk -F'\t' -v u=$user '$1~u {print $5}')
      ;;
      postgres)
         user_status_code=$(/usr/bin/psql -U postgres -h localhost -c "SELECT id,state FROM users WHERE id='$user';" --dbname=fabric_ca | awk -v u=$user -F'|' '$1~u {gsub(/ /,"");print $2}')
         cert_status_code=$(/usr/bin/psql -U postgres -h localhost -c "SELECT id,encode(status,'escape') FROM certificates WHERE id='$user';" --dbname=fabric_ca | awk -v u=$user -F'|' '$1~u {gsub(/ /,"");print $2}')
      ;;
    esac
    echo "$user_status_code $cert_status_code"
}

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp; exit 1" INT


for driver in mysql postgres sqlite3; do
   echo ""
   echo ""
   echo ""
   echo ""
   echo "=====================> TESTING $driver"
   # Kill any running servers
   $SCRIPTDIR/fabric-ca_setup.sh -R -d $driver
   
   # Setup CA server
   #$SCRIPTDIR/fabric-ca_setup.sh -D -I -S -X -d $driver 
   #$SCRIPTDIR/fabric-ca_setup.sh -D -I -S -X -d $driver -g /tmp/runFabricCaFvt.yaml -o 30 -x $CA_CFG_PATH
   $SCRIPTDIR/fabric-ca_setup.sh -D -I -S -X -d $driver -g /home/eabailey/runFabricCaFvt.yaml -x $CA_CFG_PATH
   sleep 5 
   # Enroll admin, admin2, notadmin, testUser
   i=-1
   while test $((i++)) -lt 5; do
      enroll "${USERS[i]}" "${PSWDS[i]}" "$CA_CFG_PATH/${USERS[i]}"
   done

   # notadmin cannot revoke
   export FABRIC_CA_CLIENT_HOME="/tmp/revoke_test/${USERS[2]}"
   $FABRIC_CA_CLIENTEXEC revoke -u $URI --eid ${USERS[1]}
   test "$?" -eq 0 && ErrorMsg "Non-revoker successfully revoked cert"
   
   # Check the DB contents
   while test $((i++)) -lt 3; do
      test "$(testStatus ${USERS[i]} $driver)" = "$enrolledGood" ||
      ErrorMsg "Incorrect user/certificate status for ${USERS[i]}" RC
   done

   ### Ensure case-insensitivity by using both upper/lower case
   ###  in two separate instances
   # Grab the serial number of notadmin cert 
   SN_UC="$(openssl x509 -noout -serial -in $CA_CFG_PATH/${USERS[2]}/msp/signcerts/cert.pem | awk -F'=' '{print toupper($2)}')"
   # and the auth keyid of notadmin cert - translate upper to lower case
   AKI_UC=$(openssl x509 -noout -text -in $CA_CFG_PATH/${USERS[2]}/msp/signcerts/cert.pem |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')

#   # Grab the serial number of testUser cert 
   SN_LC="$(openssl x509 -noout -serial -in $CA_CFG_PATH/${USERS[3]}/msp/signcerts/cert.pem | awk -F'=' '{print tolower($2)}')"
#   # and the auth keyid of testUser cert - translate upper to lower case
   AKI_LC=$(openssl x509 -noout -text -in $CA_CFG_PATH/${USERS[3]}/msp/signcerts/cert.pem |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print tolower($0)}')
   
   # Revoke the certs
   echo "=========================> REVOKING by --eid"
   export FABRIC_CA_CLIENT_HOME="/tmp/revoke_test/${USERS[0]}"
   #### Blanket revoke all of admin2 certs
   $FABRIC_CA_CLIENTEXEC revoke -u $URI --eid ${USERS[1]}

   #### Revoke notadmin's cert by serial number and authority keyid
   #### using upper-case hexidecimal
   echo "=========================> REVOKING by -s -a (UPPERCASE)"
   $FABRIC_CA_CLIENTEXEC revoke -s $SN_UC -a $AKI_UC -u $URI

   #### Ensure that revoking an already revoked cert doesn't blow up
   echo "=========================> Issuing duplicate revoke by -s -a"
   $FABRIC_CA_CLIENTEXEC revoke -s $SN_UC -a $AKI_UC -u $URI 

   #### Revoke using lower-case hexadeciaml
   # FIXME - should allow combination of SN + AKI + EID
   #$FABRIC_CA_CLIENTEXEC revoke -s $SN_LC -a $AKI_LC -u $URI --eid ${USERS[3]}
   echo "=========================> REVOKING by -s -a (LOWERCASE)"
   $FABRIC_CA_CLIENTEXEC revoke -s $SN_LC -a $AKI_LC -u $URI

   echo "=========================> REVOKING by --eid"
   export FABRIC_CA_CLIENT_HOME="/tmp/revoke_test/${USERS[0]}"
   #### Revoke across affiliations not allowed
   $FABRIC_CA_CLIENTEXEC revoke -u $URI --eid ${USERS[5]}

   #### Revoke my own cert
   echo "=========================> REVOKING self"
   $FABRIC_CA_CLIENTEXEC revoke --eid ${USERS[0]}

   # Verify the DB update
   for ((i=${#USERS[@]}; i<=0; i--)); do
      test "$(testStatus ${USERS[i-1]} $driver)" = "${TEST_RESULTS[i-1]}" ||
         ErrorMsg "Incorrect user/certificate status for ${USERS[i-1]}" RC
   done
 
   # Veriy that the cert is no longer usable
   export FABRIC_CA_CLIENT_HOME="/tmp/revoke_test/${USERS[0]}"
   register ${USERS[0]} 'user100'
   test "$?" -eq 0 && ErrorMsg "${USERS[0]} authenticated with revoked certificate" RC
   export FABRIC_CA_CLIENT_HOME="/tmp/revoke_test/${USERS[1]}"
   register ${USERS[1]} 'user101'
   test "$?" -eq 0 && ErrorMsg "${USERS[1]} authenticated with revoked certificate" RC
   
   # Verify the DB update
   for ((i=${#USERS[@]}; i<=0; i--)); do
      test "$(testStatus ${USERS[i-1]} $driver)" = "${TEST_RESULTS[i-1]}" ||
         ErrorMsg "Incorrect user/certificate status for ${USERS[i-1]}" RC
   done
done
CleanUp $RC
kill $HTTP_PID
wait $HTTP_PID
exit $RC
