#!/bin/bash 
/sbin/setuser postgres /usr/lib/postgresql/9.5/bin/postgres -D /usr/local/pgsql/data &
while ! nc -zvnt -w 5 127.0.0.1 5432; do sleep 1;done
/sbin/setuser mysql /usr/bin/mysqld_safe &
while ! nc -zvnt -w 5 127.0.0.1 3306; do sleep 1;done
exec "$@"
