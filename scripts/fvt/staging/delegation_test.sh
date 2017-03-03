#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HTTP_PORT="3755"
RC=0
export CA_CFG_PATH="/tmp/fabca/delegation_test"
export FABRIC_CA_DEBUG

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp; exit 1" INT

REGISTRAR="admin"
REGIRSTRARPWD="adminpw"

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -m10 -I -S -X -d $driver
   if test $? -ne 0; then ErrorMsg "server setup failed"; continue; fi
   enroll $REGISTRAR $REGIRSTRARPWD
   if test $? -ne 0; then ErrorMsg  "Failed to enroll $REGISTRAR" continue; fi

   for DEL in client peer validator auditor; do
      # admin can enroll anybody
      REGISTRAR="admin"
      enroll A_$DEL $(register $REGISTRAR A_$DEL $DEL "" \
                      "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"},\
                        {\"name\":\"hf.Registrar.DelegateRoles\", \"value\": \"${DEL}\"}]" |
                        tail -n1 |awk '{print $NF}')
      if test $? -ne 0; then ErrorMsg "enroll A_$DEL failed"; continue; fi
      enroll Aleaker_$DEL $(register $REGISTRAR Aleaker_$DEL $DEL ""\
                                   "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"}" |
                                   tail -n1 |awk '{print $NF}')
      if test $? -ne 0; then ErrorMsg "enroll Aleaker_$DEL failed"; continue; fi

      for REG in client peer validator auditor; do
         # A_$DEL can enroll and/or delegate $DEL
         REGISTRAR="Aleaker_$DEL"
         enroll Dleaker_$DEL$REG $(register $REGISTRAR Dleaker_$DEL$REG $REG ""\
                                  "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"},\
                                   {\"name\":\"hf.Registrar.DelegateRoles\", \"value\": \"${DEL}\"}]" |
                                   tail -n1 |awk '{print $NF}')
         test $? -eq 0 && ErrorMsg "Aleaker_$DEL enrolled a delegate"
         REGISTRAR="A_$DEL"
         enroll D_$DEL$REG $REG $(register $REGISTRAR D_$DEL$REG $REG "" \
                                 "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"},
                                 {\"name\":\"hf.Registrar.DelegateRoles\", \"value\": \"${DEL}\"}]" |
                                  tail -n1 |awk '{print $NF}')
         rc=$?
         if test "$REG" == "$DEL" -a $rc -ne 0; then ErrorMsg "register D_$DEL$REG failed"
         elif test "$REG" != "$DEL" -a $rc -eq 0; then ErrorMsg "register D_$DEL$REG succeeded"
         elif test "$REG" != "$DEL" -a $rc -ne 0; then continue; fi
         for ENR in client peer validator auditor; do
            # D_$DEL$REG can enroll only $REG
            REGISTRAR="D_$DEL$REG"
            enroll -u E_$DEL$REG$ENR $(register $REGISTRAR -u E_$DEL$REG$ENR $ENR "" \
                                        "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"}" |
                                      tail -n1 |awk '{print $NF}')
            rc=$?
            if test "$REG" == "$ENR" -a $rc -ne 0; then ErrorMsg "register E_$DEL$REG$ENR failed"
            elif test "$REG" != "$ENR" -a $rc -eq 0; then ErrorMsg "register E_$DEL$REG$ENR succeeded"
            elif test "$REG" != "$ENR" -a $rc -ne 0; then continue; fi
            for XXX in client peer validator auditor; do
               # E_$DEL$REG$ENR can't enroll anyone
               REGISTRAR="E_$DEL$REG$ENR"
               enroll $DEL$REG$ENR$XXX $(register $REGISTRAR $DEL$REG$ENR$XXX $XXX "" \
                                         "[{\"name\":\"type\",\"value\":\"value\"}]" |
                                         tail -n1 |awk '{print $NF}')
               if test $? -eq 0; then ErrorMsg "X_$XXX registered a user"; continue; fi
            done
         done
      done
   done
   $SCRIPTDIR/fabric-ca_setup.sh -L
   $SCRIPTDIR/fabric-ca_setup.sh -R
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp "$RC"
exit $RC
