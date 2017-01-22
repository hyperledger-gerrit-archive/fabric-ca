# !/bin/bash
COP="$GOPATH/src/github.com/hyperledger/fabric-ca"
COPEXEC="$COP/bin/fabric-ca"
TESTDATA="$COP/testdata"
SCRIPTDIR="$COP/scripts"
CSR="$TESTDATA/csr.json"
HOST="http://localhost:8888"
RUNCONFIG="$TESTDATA/postgres.json"
INITCONFIG="$TESTDATA/csr_ecdsa256.json"
RC=0
. $SCRIPTDIR/fabric-ca_utils

: ${COP_DEBUG="false"}

while getopts "k:l:x:" option; do
  case "$option" in
     x)   FABRIC_CA_HOME="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done

: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
: ${COP_DEBUG="false"}
test -z "$FABRIC_CA_HOME" && FABRIC_CA_HOME=$HOME/fabric-ca
CLIENTCERT="$FABRIC_CA_HOME/cert.pem"
CLIENTKEY="$FABRIC_CA_HOME/key.pem"
export FABRIC_CA_HOME

genClientConfig "$FABRIC_CA_HOME/client-config.json"
$COPEXEC client reenroll $HOST <(echo "{
    \"hosts\": [
        \"admin@fab-client.raleigh.ibm.com\",
        \"fab-client.raleigh.ibm.com\",
        \"127.0.0.2\"
    ],
    \"key\": {
        \"algo\": \"$KEYTYPE\",
        \"size\": $KEYLEN
    },
    \"names\": [
        {
            \"O\": \"Hyperledger\",
            \"O\": \"Fabric\",
            \"OU\": \"COP\",
            \"OU\": \"FVT\",
            \"STREET\": \"Miami Blvd.\",
            \"DC\": \"peer\",
            \"UID\": \"admin\",
            \"L\": \"Raleigh\",
            \"L\": \"RTP\",
            \"ST\": \"North Carolina\",
            \"C\": \"US\"
        }
    ]
}")
RC=$?
$($COP_DEBUG) && printAuth $CLIENTCERT $CLIENTKEY
exit $RC
