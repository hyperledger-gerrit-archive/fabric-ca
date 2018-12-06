#!/bin/bash -e

# Copyright IBM Corp All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

DEP="$GOPATH/bin/dep"

if [ ! -f $DEP ]; then
   echo "Installing dep ..."
   go get -u github.com/golang/dep/cmd/dep
   if [ $? -ne 0 ]; then
      echo "Failed to install dep"
      exit 1
   fi
fi

echo "DEP: Checking for dependency issues.."

dep version
dep check
