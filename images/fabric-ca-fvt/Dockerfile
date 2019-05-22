#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG BASEIMAGE_RELEASE
ARG ALPINE_VER
ARG GO_LDFLAGS
ARG GO_TAGS
ARG GO_VERSION="1.12.5"

FROM golang:${GO_VERSION} as fabric-ca-builder

RUN apt-get update && apt-get install -qq -y libtool libc-dev gcc
ADD . ${GOPATH}/src/github.com/hyperledger/fabric-ca
RUN go build -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	-o /opt/fabric-ca-server \
	github.com/hyperledger/fabric-ca/cmd/fabric-ca-server \
	&& go build -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	-o /opt/fabric-ca-client \
	github.com/hyperledger/fabric-ca/cmd/fabric-ca-client;

FROM ubuntu:xenial

ARG PG_VER

ENV PATH="/usr/local/bin/:${PATH}" \
    DEBIAN_FRONTEND="noninteractive" \
    GOROOT="/opt/go" \
    GOPATH="/opt/gopath" \
    GOVER="1.12.5" \
    PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}" \
    PGDATA="/usr/local/pgsql/data/" \
    PGUSER="postgres" \
    PGPASSWORD="postgres" \
    PGSSLCERT="/etc/hyperledger/fabric-ca/FabricTlsClientEEcert.pem" \
    PGSSLKEY="/etc/hyperledger/fabric-ca/FabricTlsClientEEkey.pem" \
    PGVER=${PG_VER} \
    HOSTADDR="127.0.0.1" \
    LDAPPORT="389" \
    LDAPUSER="admin" \
    LDAPPASWD="adminpw" \
    FABRIC_CA_DATA=/etc/hyperledger/fabric-ca \
    TLS_BUNDLE=FabricTlsPkiBundle.pem \
    TLS_SERVER_CERT=FabricTlsServerEEcert.pem \
    TLS_SERVER_KEY=FabricTlsServerEEkey.pem \
    TLS_CLIENT_CERT=FabricTlsClientEEcert.pem \
    TLS_CLIENT_KEY=FabricTlsClientEEkey.pem \
    MYSQLDATA=/var/lib/mysql

# setup scripts for slapd, postgres, mysql, and openssl
COPY ./images/fabric-ca-fvt/payload ${FABRIC_CA_DATA}
RUN chmod +x ${FABRIC_CA_DATA}/*sh
RUN cd ${FABRIC_CA_DATA}

RUN apt-get update && apt-get install -qq -y openssl netcat wget libltdl-dev gcc
RUN $FABRIC_CA_DATA/tls_pki.sh
RUN chmod 600 ${FABRIC_CA_DATA}/${TLS_SERVER_KEY}
RUN chmod 600 ${FABRIC_CA_DATA}/${TLS_CLIENT_KEY}

# Avoid ERROR:
#   invoke-rc.d: policy-rc.d denied execution of start.
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

RUN ${FABRIC_CA_DATA}/system_update.sh
RUN ${FABRIC_CA_DATA}/postgres_setup.sh
RUN ${FABRIC_CA_DATA}/slapd_setup.sh
RUN ${FABRIC_CA_DATA}/mysql_setup.sh
RUN ${FABRIC_CA_DATA}/install_go.sh

# Install fabric-ca dependencies
RUN /opt/go/bin/go get github.com/go-sql-driver/mysql
RUN /opt/go/bin/go get github.com/lib/pq

# Add docker-built execs for (potentially) alternative architecture
COPY --from=fabric-ca-builder /opt/fabric-ca-server /usr/local/bin
COPY --from=fabric-ca-builder /opt/fabric-ca-client /usr/local/bin

WORKDIR ${GOPATH}/src/github.com/hyperledger/fabric-ca
RUN cp ${FABRIC_CA_DATA}/start.sh /
ENTRYPOINT [ "/start.sh" ]
CMD ["scripts/run_fvt_tests"]
