#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
GO_VER="1.7.1"
ARCH="amd64"
RC=0

function usage() {
   echo "ARGS:"
   echo "  -d)   <DRIVER> - [sqlite3|mysql|postgres]"
   echo "  -n)   <FABRIC_CA_INSTANCES> - number of servers to start"
   echo "  -i)   <GITID> - ID for cloning git repo"
   echo "  -t)   <KEYTYPE> - rsa|ecdsa"
   echo "  -l)   <KEYLEN> - ecdsa: 256|384|521; rsa 2048|3072|4096"
   echo "  -c)   <SRC_CERT> - pre-existing server cert"
   echo "  -k)   <SRC_KEY> - pre-existing server key"
   echo "  -x)   <DATADIR> - local storage for client auth_info"
   echo "FLAGS:"
   echo "  -D)   set FABRIC_CA_DEBUG='true'"
   echo "  -R)   set RESET='true' - delete DB, server certs, client certs"
   echo "  -P)   set PREP='true'  - install mysql, postgres, pq"
   echo "  -C)   set CLONE='true' - clone fabric-ca repo"
   echo "  -B)   set BUILD='true' - build fabric-ca server"
   echo "  -I)   set INIT='true'  - run fabric-ca server init"
   echo "  -S)   set START='true' - start \$FABRIC_CA_INSTANCES number of servers"
   echo "  -X)   set PROXY='true' - start haproxy for \$FABRIC_CA_INSTANCES of fabric-ca servers"
   echo "  -K)   set KILL='true'  - kill all running fabric-ca instances and haproxy"
   echo "  -L)   list all running fabric-ca instances"
   echo " ?|h)  this help text"
   echo ""
   echo "Defaults: -d sqlite3 -n 1 -k ecdsa -l 256"
}

function runPSQL() {
   local cmd="$1"
   local opts="$2"
   local wrk_dir="$(pwd)"
   cd /tmp
   /usr/bin/psql "$opts" -U postgres -h localhost -c "$cmd"
   local rc=$?
   cd $wrk_dir
   return $rc
}

function updateBase {
   apt-get update
   apt-get -y upgrade
   apt-get -y autoremove
   return $?
}

function installGolang {
   local rc=0
   curl -G -L https://storage.googleapis.com/golang/go${GO_VER}.linux-${ARCH}.tar.gz \
           -o /tmp/go${GO_VER}.linux-${ARCH}.tar.gz
   tar -C /usr/local -xzf /tmp/go${GO_VER}.linux-${ARCH}.tar.gz
   let rc+=$?
   apt-get install -y golang-golang-x-tools
   let rc+=$?
   return $rc
}

function installDocker {
   local rc=0
   local codename=$(lsb_release -c | awk '{print $2}')
   local kernel=$(uname -r)
   apt-get install apt-transport-https ca-certificates \
                linux-image-extra-$kernel linux-image-extra-virtual
   echo "deb https://apt.dockerproject.org/repo ubuntu-${codename} main" >/tmp/docker.list
   cp /tmp/docker.list /etc/apt/sources.list.d/docker.list
   apt-key adv --keyserver hkp://ha.pool.sks-keyservers.net:80 \
                    --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
   apt-get update
   apt-get -y upgrade
   apt-get -y install docker-engine || let rc+=1
   curl -L https://github.com/$(curl -s -L https://github.com/docker/compose/releases | awk -v arch=$(uname -s)-$(uname -p) -F'"' '$0~arch {print $2;exit}') -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
   groupadd docker
   usermod -aG docker $(who are you | awk '{print $1}')
   return $rc
}

function updateSudoers() {
   local tmpfile=/tmp/sudoers
   local rc=0
   sudo cp /etc/sudoers $tmpfile
   echo 'ibmadmin ALL=(ALL) NOPASSWD:ALL' | tee -a $tmpfile
   sudo uniq $tmpfile | sudo tee $tmpfile
   sudo visudo -c -f $tmpfile
   test "$?" -eq "0" && sudo cp $tmpfile /etc/sudoers || rc=1
   sudo rm -f $tmpfile
   return $rc
}

function installPrereq() {
   updateBase || ErrorExit "updateBase failed"
   #updateSudoers || ErrorExit "updateSudoers failed"
   installGolang || ErrorExit "installGolang failed"
   installDocker || ErrorExit "installDocker failed"
   go get github.com/go-sql-driver/mysql || ErrorExit "install go-sql-driver failed"
   go get github.com/lib/pq || ErrorExit "install pq failed"
   apt-get -y install haproxy postgresql postgresql-contrib postgresql-client-common \
                   vim-haproxy haproxy-doc postgresql-doc locales-all \
                   libdbd-pg-perl isag jq git || ErrorExit "haproxy installed failed"
   export DEBIAN_FRONTEND=noninteractive
   apt-get -y purge mysql-server
   apt-get -y purge mysql-server-core
   apt-get -y purge mysql-common
   apt-get -y install debconf-utils zsh htop
   rm -rf /var/log/mysql
   rm -rf /var/log/mysql.*
   rm -rf /var/lib/mysql
   rm -rf /etc/mysql
   echo "mysql-server mysql-server/root_password password mysql" | debconf-set-selections
   echo "mysql-server mysql-server/root_password_again password mysql" | debconf-set-selections
   apt-get install -y mysql-client mysql-common \
                           mysql-server --fix-missing --fix-broken || ErrorExit "install mysql failed"
   apt -y autoremove
   runPSQL "ALTER USER postgres WITH PASSWORD 'postgres';"
}

function cloneFabricCa() {
   test -d ${GOPATH}/src/github.com/hyperledger || mkdir -p ${GOPATH}/src/github.com/hyperledger
   cd ${GOPATH}/src/github.com/hyperledger
   git clone http://gerrit.hyperledger.org/r/fabric-ca || ErrorExit "git clone of fabric-ca failed"
}

function buildFabricCa(){
   cd $FABRIC_CA
   make fabric-ca || ErrorExit "buildFabricCa failed"
}

function resetFabricCa(){
   killAllFabricCas
   rm -rf $DATADIR >/dev/null
   test -f $(pwd)/fabric-ca-server.db && rm $(pwd)/fabric-ca-server.db
   cd /tmp
   mysql --host=localhost --user=root --password=mysql -e 'show tables' $DBNAME 2>/dev/null &&
      mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE IF EXISTS $DBNAME"
   /usr/bin/dropdb "$DBNAME" -U postgres -h localhost -w --if-exists 2>/dev/null
}

function listFabricCa(){
   echo "Listening servers;"
   lsof -n -i tcp:9888


   case $DRIVER in
      mysql)
         echo ""
         mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM users;' $DBNAME
         echo "Users:"
         mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM users;' $DBNAME
         if $($FABRIC_CA_DEBUG); then
            echo "Certificates:"
            mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM certificates;' $DBNAME
            echo "Affiliations:"
            mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM affiliations;' $DBNAME
         fi
      ;;
      postgres)
         echo ""
         runPSQL "\l $DBNAME" | sed 's/^/   /;1s/^ *//;1s/$/:/'

         echo "Users:"
         runPSQL "SELECT * FROM USERS;" "--dbname=$DBNAME" | sed 's/^/   /'
         if $($FABRIC_CA_DEBUG); then
            echo "Certificates::"
            runPSQL "SELECT * FROM CERTIFICATES;" "--dbname=$DBNAME" | sed 's/^/   /'
            echo "Affiliations:"
            runPSQL "SELECT * FROM AFFILIATIONS;" "--dbname=$DBNAME" | sed 's/^/   /'
         fi
      ;;
      sqlite3) sqlite3 "$DATASRC" 'SELECT * FROM USERS ;;' | sed 's/^/   /'
               if $($FABRIC_CA_DEBUG); then
                  sqlite3 "$DATASRC" 'SELECT * FROM CERTIFICATES;' | sed 's/^/   /'
                  sqlite3 "$DATASRC" 'SELECT * FROM AFFILIATIONS;' | sed 's/^/   /'
               fi
   esac
}

function initFabricCa() {
   test -f $FABRIC_CA_SERVEREXEC || ErrorExit "fabric-ca executable not found (use -B to build)"

   $FABRIC_CA_SERVEREXEC init -c $RUNCONFIG

   echo "FABRIC_CA server initialized"
   if $($FABRIC_CA_DEBUG); then
      openssl x509 -in $DST_CERT -noout -issuer -subject -serial \
                   -dates -nameopt RFC2253| sed 's/^/   /'
      openssl x509 -in $DST_CERT -noout -text |
         awk '
            /Subject Alternative Name:/ {
               gsub(/^ */,"")
               printf $0"= "
               getline; gsub(/^ */,"")
               print
            }'| sed 's/^/   /'
      openssl x509 -in $DST_CERT -noout -pubkey |
         openssl $KEYTYPE -pubin -noout -text 2>/dev/null| sed 's/Private/Public/'
      openssl $KEYTYPE -in $DST_KEY -text 2>/dev/null
   fi
}


function startHaproxy() {
   local inst=$1
   local i=0
   local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
   test -n "$proxypids" && kill $proxypids
   #sudo sed -i 's/ *# *$UDPServerRun \+514/$UDPServerRun 514/' /etc/rsyslog.conf
   #sudo sed -i 's/ *# *$ModLoad \+imudp/$ModLoad imudp/' /etc/rsyslog.conf
   case $TLS_ON in
     "true")
   haproxy -f  <(echo "global
      log /dev/log	local0 debug
      log /dev/log	local1 debug
      daemon
defaults
      log     global
      option  dontlognull
      maxconn 1024
      timeout connect 5000
      timeout client 50000
      timeout server 50000

frontend haproxy
      bind *:8888
      mode tcp
      option tcplog
      default_backend fabric-cas

backend fabric-cas
      mode tcp
      balance roundrobin";
   while test $((i++)) -lt $inst; do
      echo "      server server$i  127.0.0.$i:9888"
   done)
   ;;
   *)
   haproxy -f  <(echo "global
      log /dev/log	local0 debug
      log /dev/log	local1 debug
      daemon
defaults
      log     global
      mode http
      option  httplog
      option  dontlognull
      maxconn 1024
      timeout connect 5000
      timeout client 50000
      timeout server 50000
      option forwardfor

listen stats
      bind *:10888
      stats enable
      stats uri /
      stats enable

frontend haproxy
      bind *:8888
      mode http
      option tcplog
      default_backend fabric-cas

backend fabric-cas
      mode http
      http-request set-header X-Forwarded-Port %[dst_port]
      balance roundrobin";
   while test $((i++)) -lt $inst; do
      echo "      server server$i  127.0.0.$i:9888"
   done)
   ;;
   esac

}

function startFabricCa() {
   local inst=$1
   local start=$SECONDS
   local timeout=8
   local now=0
   local server_addr=127.0.0.$inst
   local server_port=9888

   inst=0
   $FABRIC_CA_SERVEREXEC start --address $server_addr --port $server_port --ca.certfile $DST_CERT \
                     --ca.keyfile $DST_KEY --config $RUNCONFIG 2>&1 | sed 's/^/     /' &
                    # --db.datasource $DATASRC --ca.keyfile $DST_KEY --config $RUNCONFIG 2>&1 | sed 's/^/     /' &
   until test "$started" = "$server_addr:$server_port" -o "$now" -gt "$timeout"; do
      started=$(ss -ltnp src $server_addr:$server_port | awk 'NR!=1 {print $4}')
      sleep .5
      let now+=1
   done
   printf "FABRIC_CA server on $server_addr:$server_port "
   if test "$started" = "$server_addr:$server_port"; then
      echo "STARTED"
   else
      RC=$((RC+1))
      echo "FAILED"
   fi
}


function killAllFabricCas() {
   local fabric_capids=$(ps ax | awk '$5~/fabric-ca/ {print $1}')
   local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
   test -n "$fabric_capids" && kill $fabric_capids
   test -n "$proxypids" && kill $proxypids
}

while getopts "\?hPRCBISKXLDTAd:t:l:n:i:c:k:x:g:m:p:" option; do
  case "$option" in
     d)   DRIVER="$OPTARG" ;;
     p)   HTTP_PORT="$OPTARG" ;;
     n)   FABRIC_CA_INSTANCES="$OPTARG" ;;
     i)   GITID="$OPTARG" ;;
     t)   KEYTYPE=$(tolower $OPTARG);;
     l)   KEYLEN="$OPTARG" ;;
     c)   SRC_CERT="$OPTARG";;
     k)   SRC_KEY="$OPTARG" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
     m)   MAXENROLL="$OPTARG" ;;
     g)   SERVERCONFIG="$OPTARG" ;;
     D)   export FABRIC_CA_DEBUG='true' ;;
     A)   AUTH="false" ;;
     P)   PREP="true"  ;;
     R)   RESET="true"  ;;
     C)   CLONE="true" ;;
     B)   BUILD="true" ;;
     I)   INIT="true" ;;
     S)   START="true" ;;
     X)   PROXY="true" ;;
     K)   KILL="true" ;;
     L)   LIST="true" ;;
     T)   TLS_ON="true" ;;
   \?|h)  usage
          exit 1
          ;;
  esac
done

: ${HTTP_PORT="3755"}
: ${DBNAME:="fabric_ca"}
: ${MAXENROLL="1"}
: ${AUTH="true"}
: ${DRIVER="sqlite3"}
: ${FABRIC_CA_INSTANCES=1}
: ${FABRIC_CA_DEBUG="false"}
: ${GITID="rennman"}
: ${LIST="false"}
: ${PREP="false"}
: ${RESET="false"}
: ${CLONE="false"}
: ${BUILD="false"}
: ${INIT="false"}
: ${START="false"}
: ${PROXY="false"}
: ${HTTP="true"}
: ${KILL="false"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
test $KEYTYPE = "rsa" && SSLKEYCMD=$KEYTYPE || SSLKEYCMD="ec"

: ${CA_CFG_PATH:="/tmp/fabric-ca"}
: ${DATADIR:="$CA_CFG_PATH"}
export CA_CFG_PATH

# regarding tls:
#    honor the command-line setting to turn on TLS
#      else honor the envvar
#        else (default) turn off tls
if test -n "$TLS_ON"; then
   TLS_DISABLE='false'
else
   case "$FABRIC_TLS" in
      true) TLS_DISABLE='false';TLS_ON='true';LDAP_PORT=636 ;;
     false) TLS_DISABLE='true' ;TLS_ON='false' ;;
         *) TLS_DISABLE='true' ;TLS_ON='false' ;;
   esac
fi
test -d $DATADIR || mkdir -p $DATADIR
DST_KEY="$DATADIR/fabric-ca-key.pem"
DST_CERT="$DATADIR/fabric-ca-cert.pem"
test -n "$SRC_CERT" && cp "$SRC_CERT" $DST_CERT
test -n "$SRC_KEY" && cp "$SRC_KEY" $DST_KEY
RUNCONFIG="$DATADIR/runFabricCaFvt.yaml"

case $DRIVER in
   postgres) DATASRC="dbname=$DBNAME host=127.0.0.1 port=$POSTGRES_PORT user=postgres password=postgres sslmode=disable" ;;
   sqlite3)  DATASRC="$DATADIR/fabric-ca-server.db" ;;
   mysql)    DATASRC="root:mysql@tcp(localhost:$MYSQL_PORT)/$DBNAME?parseTime=true" ;;
esac

$($LIST)  && listFabricCa
$($PREP)  && installPrereq
$($RESET) && resetFabricCa
$($CLONE) && cloneFabricCa
$($BUILD) && buildFabricCa
$($KILL)  && killAllFabricCas
$($PROXY) && startHaproxy $FABRIC_CA_INSTANCES

$( $INIT -o $START ) && genRunconfig "$RUNCONFIG" "$DRIVER" "$DATASRC" "$DST_CERT" "$DST_KEY" "$MAXENROLL"
test -n "$SERVERCONFIG" && cp "$SERVERCONFIG" "$RUNCONFIG"

$($INIT) && initFabricCa
if $($START); then
   inst=0
   while test $((inst++)) -lt $FABRIC_CA_INSTANCES; do
      startFabricCa $inst
   done
fi
exit $RC
