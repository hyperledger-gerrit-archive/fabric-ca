#!/bin/bash
POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($POSTGRES_PORT $MYSQL_PORT $LDAP_PORT)

timeout=12
su postgres -c 'postgres -D /usr/local/pgsql/data' &
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES \
                     --ssl-ca=/var/lib/mysql/ca.pem \
                     --ssl-cert=/var/lib/mysql/server-cert.pem \
                     --ssl-key=/var/lib/mysql/server-key.pem &
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
