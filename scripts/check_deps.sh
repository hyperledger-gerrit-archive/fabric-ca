#!/bin/bash -e

# Copyright IBM Corp All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

make -f gotools.mk

echo "DEP: Checking for dependency issues.."

dep version
dep check
