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


if [ "$#" -ne 3 ]; then
    echo "Prepends a changelog into the current CHANGELOG.md at the root of the project"
    echo "Note: must be run from root directory of repository clone"
    echo "Usage: ./scripts/changelog.sh <StartRefSpec> <EndRefSpec> <ReleaseVersion>"
    exit 1
fi

echo "## $3\n$(date)\n" >> CHANGELOG.new
git log $1..$2  --oneline | grep -v Merge | sed -e "s/\[\(FAB-[0-9]*\)\]/\[\1\](https:\/\/jira.hyperledger.org\/browse\/\1\)/" -e "s/ \(FAB-[0-9]*\)/ \[\1\](https:\/\/jira.hyperledger.org\/browse\/\1\)/" -e "s/\([0-9|a-z]*\)/* \[\1\](https:\/\/github.com\/hyperledger\/fabric\/commit\/\1)/" >> CHANGELOG.new
echo "" >> CHANGELOG.new
cat CHANGELOG.md >> CHANGELOG.new
mv -f CHANGELOG.new CHANGELOG.md
