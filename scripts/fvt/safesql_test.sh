#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -o pipefail
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"

safesql -v ../lib/ #&> safesql_report.log
