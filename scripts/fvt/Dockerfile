from phusion/baseimage:latest

ENV GO_VER 1.7.1
ENV ARCH amd64
ENV DEBIAN_FRONTEND noninteractive
ENV PATH "/usr/local/go/bin/:${PATH}"
ENV GOPATH "/opt/gopath"
ENV PGDATA "/usr/local/pgsql/data/"
ENV PGUSER "postgres"
ENV PGPASSWORD "postgres"

WORKDIR /opt
RUN mkdir gopath

WORKDIR /tmp
# Avoid ERROR: 
#   invoke-rc.d: policy-rc.d denied execution of start.
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d
RUN locale-gen en_US.UTF-8 && \
echo 'LANG="en_US.UTF-8"' > /etc/default/locale

# Update system
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install apt-utils

# Install more test depedencies
RUN echo "mysql-server mysql-server/root_password password mysql" | debconf-set-selections
RUN echo "mysql-server mysql-server/root_password_again password mysql" | debconf-set-selections
RUN apt-get -y install build-essential lsof netcat haproxy postgresql \
                       isag jq git html2text debconf-utils zsh htop python2.7-minimal \
                       mysql-client  mysql-common mysql-server
RUN apt-get -y autoremove

# Configure and start postgres
RUN mkdir -p $PGDATA
RUN chown postgres:postgres $PGDATA
RUN setuser postgres /usr/lib/postgresql/9.5/bin/initdb -D $PGDATA && setuser postgres /usr/lib/postgresql/9.5/bin/pg_ctl start -D $PGDATA && psql -U postgres -h localhost -c "ALTER USER $PGUSER WITH PASSWORD '$PGPASSWORD';"
RUN echo "host all  all    0.0.0.0/0  trust" >> ${PGDATA}/pg_hba.conf
RUN echo "listen_addresses='*'" >> ${PGDATA}/postgresql.conf

# Install golang
RUN curl -G -L https://storage.googleapis.com/golang/go${GO_VER}.linux-${ARCH}.tar.gz \
         -o go${GO_VER}.linux-${ARCH}.tar.gz
RUN tar -C /usr/local -xzf go${GO_VER}.linux-${ARCH}.tar.gz

# Install fabric-ca dependencies
RUN go get github.com/go-sql-driver/mysql
RUN go get github.com/lib/pq

# Dummy docker exec to fool make
# we don't need docker
RUN touch /usr/local/bin/docker
RUN chmod 777 /usr/local/bin/docker

# Use python2, not 3
RUN ln -s /usr/bin/python2.7 /usr/local/bin/python
RUN chmod 777 /usr/local/bin/python

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY start.sh /start.sh

WORKDIR ${GOPATH}/src/github.com/hyperledger/fabric-ca
ENTRYPOINT [ "/start.sh" ]
