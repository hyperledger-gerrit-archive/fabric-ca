#!/bin/sh
#
# Copyright IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CLIENTCERT=$1
CLIENTKEY=$2

: ${CLIENTCERT:="$HOME/fabric-ca/cert.pem"}
: ${CLIENTKEY:="$HOME/fabric-ca/key.pem"}

#key=$(cat  $CLIENTAUTH |jq '.publicSigner.key'  |sed 's/"//g')
#cert=$(cat $CLIENTAUTH |jq '.publicSigner.cert' |sed 's/"//g')
#echo CERT:
#echo $cert |base64 -d| openssl x509 -text 2>&1 | sed 's/^/    /'
#type=$(echo $key  |base64 -d | head -n1 | awk '{print tolower($2)}')
#echo KEY:
#echo $key  |base64 -d| openssl $type -text 2>/dev/null| sed 's/^/    /'
#case $1 in
#   d) base64 -d ;;
#   *) awk -v FS='' '
#         BEGIN { printf "-----BEGIN CERTIFICATE-----\n"}
#         { for (i=1; i<=NF; i++) if (i%64) printf $i; else print $i }
#         END   { if ((i%64)!=0) print "" ; printf "-----END CERTIFICATE-----\n" }'
#      ;;
#esac
echo CERT:
openssl x509 -in $CLIENTCERT -text 2>&1 | sed 's/^/    /'
type=$(cat $CLIENTKEY | head -n1 | awk '{print tolower($2)}')
echo KEY:
openssl $type -in $CLIENTKEY -text 2>/dev/null| sed 's/^/    /'

