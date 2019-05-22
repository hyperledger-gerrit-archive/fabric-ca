#!/bin/bash
#
# Copyright Greg Haskins All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# ALERT: if you encounter an error like:
# error: [Errno 1] Operation not permitted: 'cf_update.egg-info/requires.txt'
# The proper fix is to remove any "root" owned directories under your update-cli directory
# as source mount-points only work for directories owned by the user running vagrant

# Stop on first error
set -e
set -x

# ----------------------------------------------------------------
# Install Golang
# ----------------------------------------------------------------

mkdir -p $GOPATH
ARCH=`uname -m | sed 's|i686|386|' | sed 's|x86_64|amd64|'`
BINTARGETS="x86_64 ppc64le s390x"

# Install Golang binary if found in BINTARGETS
if echo $BINTARGETS | grep -q `uname -m`; then
   cd /tmp
   wget --quiet --no-check-certificate https://storage.googleapis.com/golang/go${GOVER}.linux-${ARCH}.tar.gz
   tar -xzf go${GOVER}.linux-${ARCH}.tar.gz
   mv go $GOROOT
   chmod 775 $GOROOT
# Otherwise, build Golang from source
else
   # Install Golang 1.6 binary as a bootstrap to compile the Golang GO_VER source
   apt-get -y install golang-1.6

   cd /tmp
   wget --quiet --no-check-certificate https://storage.googleapis.com/golang/go${GOVER}.src.tar.gz
   tar -xzf go${GOVER}.src.tar.gz -C /opt

   cd $GOROOT/src
   export GOROOT_BOOTSTRAP="/usr/lib/go-1.6"
   ./make.bash
   apt-get -y remove golang-1.6
fi
