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

AUTHJSON=$1
CERTFILE="$2"
KEYFILE="$3"

test -z $AUTHJSON && AUTHJSON="$HOME/fabric-ca/client.json"
test -z $CERTFILE    && CERTFILE="/tmp/cert.${RANDOM}.pem"
test -z $KEYFILE    && KEYFILE="/tmp/key.${RANDOM}.pem"

key=$(cat  $AUTHJSON |jq '.publicSigner.key'  |sed 's/"//g')
cert=$(cat $AUTHJSON |jq '.publicSigner.cert' |sed 's/"//g')
echo $cert |base64 -d > $CERTFILE
echo $key  |base64 -d > $KEYFILE
