#!/bin/bash
RC=0

arch=$(uname -m)
rm -rf $MYSQLDATA 
mkdir -p $MYSQLDATA /var/run/mysqld
chown mysql:mysql $MYSQLDATA
chmod 777 /var/run/mysqld
if test "$arch" = "x86_64"; then
   /usr/sbin/mysqld --initialize-insecure || let RC+=1
fi

# Mysql certificates
cp $FABRIC_CA_DATA/$TLS_BUNDLE $MYSQLDATA/
cp $FABRIC_CA_DATA/$TLS_SERVER_CERT $MYSQLDATA/
openssl rsa -in $FABRIC_CA_DATA/$TLS_SERVER_KEY -out $MYSQLDATA/$TLS_SERVER_KEY || let RC+=1
chown mysql.mysql $MYSQLDATA/*pem
chmod 600 $MYSQLDATA/$TLS_SERVER_KEY
test $arch = s390x && MYCNF=/etc/mysql/my.cnf || MYCNF=/etc/mysql/mysql.conf.d/mysqld.cnf
sed -i "s/^[[:blank:]]*#*[[:blank:]]*ssl-ca=.*/ssl-ca=$TLS_BUNDLE/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-cert=.*/ssl-cert=$TLS_SERVER_CERT/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-key=.*/ssl-key=$TLS_SERVER_KEY/" $MYCNF || let RC+=1

exit $RC