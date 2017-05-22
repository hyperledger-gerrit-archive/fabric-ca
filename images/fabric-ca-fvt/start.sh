#!/bin/bash
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

POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($POSTGRES_PORT $MYSQL_PORT $LDAP_PORT)

timeout=12
su postgres -c 'postgres -D /usr/local/pgsql/data' &
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &
/etc/init.d/slapd start &

for port in ${PORTS[*]}; do
   i=0
   while ! nc -zvnt -w 5 127.0.0.1 $port; do
      sleep 1
      test $i -gt $timeout && break
      let i++;
   done
done

exec "$@"
