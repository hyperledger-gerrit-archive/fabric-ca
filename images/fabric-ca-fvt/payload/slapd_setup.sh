#!/bin/bash

# Install slapd
printf  "slapd slapd/internal/generated_adminpw password $LDAPPASWD\n\
slapd slapd/password2 password $LDAPPASWD\n\
slapd slapd/internal/adminpw password $LDAPPASWD\n\
slapd slapd/password1 password $LDAPPASWD\n\
slapd slapd/domain string example.com\n\
slapd shared/organization string example.com" | debconf-set-selections 
apt-get -y update
apt-get -y install --no-install-recommends slapd ldap-utils
adduser openldap ssl-cert
cp $FABRIC_CA_DATA/$TLS_BUNDLE /etc/ssl/certs/
cp $FABRIC_CA_DATA/$TLS_SERVER_CERT /etc/ssl/certs/
cp $FABRIC_CA_DATA/$TLS_SERVER_KEY /etc/ssl/private/$TLS_SERVER_KEY
cp $FABRIC_CA_DATA/*ldif /etc/ldap/

adduser openldap ssl-cert
chgrp ssl-cert /etc/ssl/private/$TLS_SERVER_KEY
chmod 644 /etc/ssl/certs/$TLS_BUNDLE
chmod 644 /etc/ssl/certs/$TLS_SERVER_CERT
chmod 640 /etc/ssl/private/$TLS_SERVER_KEY
sed -i \
   "s@^[[:blank:]]*SLAPD_SERVICES=.*@SLAPD_SERVICES=\"ldap://$HOSTADDR:$LDAPPORT/ ldaps:/// ldapi:///\"@"\
   /etc/default/slapd
/etc/init.d/slapd start && \
    ldapadd -h localhost -p 389 -D cn=$LDAPUSER,dc=example,dc=com -w $LDAPPASWD -f /etc/ldap/base.ldif && \
    ldapadd -h localhost -p 389 -D cn=$LDAPUSER,dc=example,dc=com -w $LDAPPASWD -f /etc/ldap/add-users.ldif && \
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ldap/certinfo.ldif && \
    /etc/init.d/slapd stop


exit
