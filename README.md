# Fabric CA

The Fabric-CA is a Certificate Authority for Hyperledger Fabric v1.0 and later.

It consists of both a serve and a client component.

It provides features including:  
* registration of identities;
* enrollment of identities and issuance of enrollment certificates (ECerts);
* issuance of transaction certificates (TCerts) given proof of ownership
  of an ECert;
* certificate renewal and revocation.

See the [Fabric-CA design doc](https://docs.google.com/document/d/1TRYHcaT8yMn8MZlDtreqzkDcXx0WI50AV2JpAcvAM5w) for design documentation.

<div id='contents'>
# Table of Contents
1. [Overview](#overview)
2. [Getting Started](#getting-started)
	1. [Prequisites](#prerequisites)
  2. [Installation](#installation)
	3. [Explore the Fabric-CA CLI](#explore)
	4. [Development vs Production](#devprod)
3. [File Formats](#formats)
  1. [Server-config.yaml](#server)
  2. [Client-config.yaml](#clientconfig)
  3. [RegistrationRequest.json](#registration)
  4. [CSR.json](#csr)
4. [Initialize the Fabric-CA Server](#initialize)
5. [TLS/SSL Configuration](#tls)
	1. [Client & Fabric-CA Server](#tls-client-server)
	2. [Database & Fabric-CA Server](#tls-db-server)
6. [Start the Fabric-CA server](#start)
7. [Enroll the admin client](#enroll)
8. [Reenroll](#reenroll)
9. [Register a new user](#register)
10. [Revoke a user](#revoke)
11. [LDAP](#ldap)
12. [Setting up a cluster](#cluster)
	1. [HAProxy](#haproxy)
	1. [PostgreSQL](#postgres)
	2. [MySQL](#mysql)
13. [Run the Fabric-CA tests](#tests)
14. [Appendix](#appendix)

<div id='overview'/>
## Overview

The diagram below describes how the Fabric-CA server fits into the overall picture.
Fabric-CA is a means of generating Enrollment and Transaction certificates. There are
two ways to interact with a Fabric-CA server. Fabric-CA comes with a CLI that
can be used to perform various actions, such as registering and enrolling participants.
Fabric-CA can also be invoked through an SDK interacting with Fabric-CA APIs.

The SDK or CLI may point to a logical Fabric-CA server. This is illustrated in the
top right section of the diagram below. A client may actually be talking directly
to a load balancer (e.g. HA proxy), which is than directing traffic to clustered
Fabric-CA servers. In a cluster setup, multiple Fabric-CA servers will share the same
database for keeping track of users, groups, and certificates.

![Fabric-CA Overview](Fabric-CA.png)

[Back to Top](#contents)

<div id='getting-started'/>
## Getting Started

<div id='prerequisites'/>
### Prerequisites

* Go 1.7+ installation or later
* **GOPATH** environment variable is set correctly
* **fabric-ca** environment variable is set to **$GOPATH/src/github.com/hyperledger/fabric-ca**

<div id='installation'/>
### Installation

Fabric-CA can be installed on your local machine or an in Vagrant environment.
To get started with using vagrant, refer to this [Documentation](http://hyperledger-fabric.readthedocs.io/en/latest/dev-setup/devenv/)

#### Go Get

```
# go get -u github.com/hyperledger/fabric-ca/cli
# mv $GOPATH/bin/cli $GOPATH/bin/fabric-ca
```

will download the Fabric-CA server, installing it in `$GOPATH/github.com/hyperledger/fabric-ca`.
Navigate to `$fabric-ca` and execute `make fabric-ca`. This will build the Fabric-CA executable
(i.e. the 'Fabric-CA' binary). The executable is located at `$fabric-ca/bin/fabric-ca`.

#### GIT Clone

```
# cd $GOPATH/src/github.com/hyperledger
# git clone ssh://YOUR-ID@gerrit.hyperledger.org:29418/fabric-ca
# cd $GOPATH/src/github.com/hyperledger/fabric-ca
# make fabric-ca
```

This will build the Fabric-CA executable (i.e. the 'Fabric-CA' binary). The executable is
located at `$fabric-ca/bin/fabric-ca`.

#### Docker

Use either Go Get or Git Clone to download Fabric-CA. Then run the following
commands to set up a docker container running a Fabric-CA server.
Navigate to `$fabric-ca` and execute `make docker`.

After previous command completes, to launch the Fabric-CA server, run the following:

```
# docker run hyperledger/fabric-ca
```

Open up a new terminal window and run:

```
# docker ps
```

Get the id of the container that was launched with the docker run command.
The container id will be needed for the next command.

```
# docker exec -it <container-id> sh
```

At this point you should be inside the container and can execute Fabric-CA commands.

<div id='explore'/>
### Explore the Fabric-CA CLI

The following shows the Fabric-CA usage message:

```
# cd $fabric-ca/bin
# ./fabric-ca
fabric-ca client       - client related commands
fabric-ca server       - server related commands
fabric-ca cfssl        - all cfssl commands

For help, type "fabric-ca client", "fabric-ca server", or "fabric-ca cfssl".
```

The Fabric-CA client and server commands are what you will use.
However, since Fabric-CA is built on top of [CFSSL](https://github.com/cloudflare/cfssl)
and CFSSL has its own CLI, you may issue any CFSSL commands with the `fabric-ca cfssl`
command prefix.

Refer to table for more information on specific commands. Refer to CFSSL
documentation on specific commands available for CFSSL.


| Component  | Command  | Description                                             | Usage                                                                       |
|------------|----------|---------------------------------------------------------|-----------------------------------------------------------------------------|
| **Client** | enroll   | Enroll a user                                           | fabric-ca client enroll -config CONFIG-FILE ID SECRET                |
|            | reenroll | Reenroll a user                                         | fabric-ca client reenroll -config CONFIG-FILE                        |
|            | register | Register an ID and get an enrollment secret             | fabric-ca client register -config CONFIG-FILE REGISTER-REQUEST-FILE  |
|            | revoke   | Revokes one or more certificates                        | fabric-ca client revoke -config CONFIG-FILE [ENROLLMENT_ID]          |
| **Server** | init     | Generates a new private key and self-signed certificate | fabric-ca server init CSRJSON                                               |
|			       | start    | Start the Fabric-CA server                              | fabric-ca server start [-config CONFIG-FILE]                                |

<div id='devprod'>
### Development vs Production

#### Development
A development environment does not require much configuration. By default,
Fabric-CA server uses SQLite database. This removes any requirement of having to set
up a database for development purposes. When starting Fabric-CA server for the first
time, the Fabric-CA server will create a SQLite database and then make use of it from
this point forward. However, SQLite has limitations such as its inability to
support remote connections. For that reason, SQLite is not recommended for use
in a production environment. See the Production section below for more information.

#### Production
In production, a database that supports remote connection is required to allow
for clustering. PostgreSQL and MySQL are two database that Fabric-CA server supports
which support remote connections. Refer to [Setting up a Cluster](#cluster) for
more details on how to setup a cluster environment.

LDAP can also be used in production. Refer to [LDAP](#ldap) for instructions on setup.

[Back to Top](#contents)

<div id='formats'>
## File Formats

<div id='server'>
### Server-config.yaml

Fabric-CA server requires a configuration file to start. Sample server configuration
files can be found in `testdata` folder. The `server-config.yaml` file provides basic
configuration, for more advance configurations refer to `testconfig.yaml`.

```
#####################################
#    CA Certificate and Key Section
#####################################
ca:

  certFile: ec.pem
  keyFile: ec-key.pem

#####################################
#    User Registry Section
#####################################
userRegistry:

  maxEnrollments: 1

####################################
#    Database section
#####################################
database:

  type: sqlite3
  datasource: fabric-ca.db

  tls:
      enabled: false
      caFiles:
        - root.pem
      certFile: tls-cert.pem
      keyFile: tls-key.pem

#####################################
#    TLS section
#####################################
tls:

  enabled: true
  caFile: root.pem
  certFile: tls_server-cert.pem
  keyFile: tls_server-key.pem

#####################################
#    Users section
#####################################
users:

  admin:
    pass: adminpw
    type: client
    affiliation: bank_a
    attrs:
      - name: "hf.Registrar.Roles"
        value: "client,user,peer,validator,auditor"
      - name: "hf.Registrar.DelegateRoles"
        value: "client,user,validator,auditor"
      - name: "hf.Revoker"
        value: true

#####################################
#    Affiliation section
#####################################
affiliations:

   banks_and_institutions:
      banks:
          - bank_a
          - bank_b
          - bank_c
      institutions:
          - institution_a

#####################################
#    Signing section
#####################################
signing:

    profiles:
      expiry:
         usage:
           - cert sign
         expiry: 1s

    default:
      usage:
        - cert sign
      expiry: 8000h
```

The table below defines the available configuration options available
on the Fabric-CA server.

|Section          |Property        |              Description                                                                                    | Default      |
|-----------------|----------------|-------------------------------------------------------------------------------------------------------------|--------------|
|**ca**           | certFile       | File path to CA certificate on file system                                                                  | n/a          |
|                 | keyFile        | File path to CA key on file system                                                                          | n/a          |
|**userRegistry** | maxEnrollments | Number of enrollments allowed for registered users                                                          | unlimited    |
|**database**     | type			  | Specify database type, 3 options available: sqlite3, postgres, mysql                                        | sqlite       |
|					 | datasource 	  | Connection information for connecting to database. See specific database sections for more info             | fabric-ca.db |
|					 | enabled		  | Enable TLS connection between Fabric-CA server and database                                                 | false        |
|					 | caFiles		  | File path to root certificates that database certificate should be signed by                                   | n/a          |
|					 | certFile		  | File path to DB client certificate on file system                                                           | n/a          |
|					 | keyFile         | File path to DB client key on file system                                                                   | n/a         |
|**tls**          | enabled        | Enable TLS connection between Fabric-CA server and client                                                   | false        |
| 					 | caFile			  | File path to certificate that client certificate should be signed by                                        | n/a          |
|                 | certFile		  | File path to the server's TLS certificate on file system                                                    | CA Cert File |
|					 | keyFile		  | File path to the server's TLS key on file system                                                            | CA Key File  |
|**users**        |      | Defines users that server will be bootstrapped with. See ./testdata/server-config.yaml for example on defining users  | n/a          |
|**affiliations** || Defines affiliations that server will be bootstrapped with. See ./testdata/server-config.yaml for example on defining groups | n/a          |    

<div id='clientconfig'>
### Client-config.yaml

Fabric-CA client supports a config flag that can be used to point to a client side
configuration file. Sample server configuration files can be found in `testdata` folder. The `client-config.yaml` file is an example of the properties that can be set. A configuration 
file is required if client wishes to establish a TLS connection with the Fabric-CA server. 

If a configuration file is not specified using the config flag, the client will look
in the home directory for the configuration file. If no file is found, it will use
default values. 

Note: Default settings will not allow you to establish a TLS connection. 

```
#####################################
# Client Configuration
#####################################

serverURL: https://localhost:7054

#####################################
#    TLS section
#####################################
tls:
  caFile: root.pem
  certFile: tls-cert.pem
  keyFile: tls-key.pem
```  

The table below defines the available properties for client side configuration.

|Section          |Property        |              Description                                                                   | Default                  |
|-----------------|----------------|--------------------------------------------------------------------------------------------|--------------------------|
|			        | serverURL      | URL of the Fabric-CA server                                                                | https://localhost:7054   |
|**tls**          | caFile         | File path to root certificate that Fabric-CA server certificate should be signed by        | n/a                      |
|                 | certFile       | File path to client certificate on file system                                             | n/a                      |
|                 | keyFile        | File path to client key on file system                                                     | n/a                      |
  
<div id='registration'>
### RegistrationRequest.json

Registering a new user requires the creation of a JSON file describing properties
of the user being registered. A sample registration request JSON can be found
at `testdata/registrationrequest.json` or see example below.

```
{
  "id": "test_user",
  "type": "client",
  "group": "bank_a",
  "attrs": [{"name":"test","value":"testValue"}]
  "max_enrollments": 2
}
```

The table below defines the available properties of a new user being registered

|Property        |              Description                       |
|----------------|------------------------------------------------|
|id              | Name of the user                               |
|type            | Type of participant (e.g. client, peer, etc.)  |
|group           | Name of the group the participant belongs to   |
|attrs           | Attributes belonging to this participant       |
|max_enrollments | Number of enrollments allowed                  |

<div id='csr'/>
### CSR.json

In order to generate a Certificate and Key, you must provide a JSON file
containing the relevant details of your request. This JSON file looks something
like:

```
{
    "hosts": [
        "example.com",
        "www.example.com"
    ],
    "CN": "www.example.com",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [{
        "C": "US",
        "L": "San Francisco",
        "O": "Example Company, LLC",
        "OU": "Operations",
        "ST": "California"
    }]
}
```

The `../testdata/csr_dsa.json` file can be customized to generate x509
certificates and keys that support both RSA and Elliptic Curve (ECDSA).

The following setting is an example of the implementation of Elliptic Curve
Digital Signature Algorithm (ECDSA) with curve:
secp384r1 and Signature Algorithm: ecdsa-with-SHA384:

"algo": "ecdsa"  
"size": 384

The choice of algorithm and key size are based on security needs.

Elliptic Curve (ECDSA) offers the following curves and security levels:

| size        | ASN1 OID           | Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 256      | prime256v1 | ecdsa-with-SHA256 |
| 384      | secp384r1      |   ecdsa-with-SHA384 |
| 521 | secp521r1     | ecdsa-with-SHA512 |

Likewise, these are the secure choices for RSA modulus:

| size        | Modulus (bits)| Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 2048      | 2048 | sha256WithRSAEncryption |
| 4096      | 4096 | sha512WithRSAEncryption |

See table below for more information on fiels in the CSR.json

| Field    |                 Description                                                       |
|----------|-----------------------------------------------------------------------------------|
| hosts    | List of the domain names which the certificate should be valid for                                                                          |
| CN       | Used by some CAs to determine which domain the certificate is to be generated for instead; these CAs will most often provide a certificate for both the "www" (e.g. www.example.net) and "bare" (e.g. example.net) domain names if the "www" domain name is provided                                        |
| key      | Key generation protocol				                                                                                |
| names    | "C": country<br>"L": locality or municipality (such as city or town name)<br>"O": organisation<br>"OU": organisational unit, such as the department responsible for owning the key; it can also be used for a "Doing Business As" (DBS) name<br>"ST": the state or province|
<div id='initialize'/>

[Back to Top](#contents)

## Initialize the Fabric-CA server  

Executing the following "Fabric-CA init" command will generate a private key and self-signed
x509 certificate to start the Fabric-CA server in the [Start the Fabric-CA server](#start) section.
These two PEM files will be generated and stored in the directory
`$FABRIC_CA_HOME/fabric-ca/`: server-cert.pem and server-key.pem.
They can be used as input parameters to `-ca` and `-ca-key` in the command to
start the Fabric-CA server.

```
# cd $fabric-ca/bin
# ./fabric-ca server init ../testdata/csr_dsa.json
```

[Back to Top](#contents)

<div id='tls'/>
## TLS/SSL Configuration
<div id='tls-client-server'/>

### Generating TLS Certificate and Key
Fabric-CA server supports the use of TLS when communicating with client. If TLS is enabled
and  no specific TLS Certificate and Key is specified it will default to using the CA 
Certificate and Key which is required to start up a Fabric-CA server
([Starting the Fabric-CA server](#start))

However, if a different TLS Certificate and Key would like to be used, they can
be generated using the instructions in [Initialize the Fabric-CA server](#initialize)
to generate a pair that can be used for TLS purposes.

### Client & Fabric-CA Server

The steps below should be followed to enable a secure connection between client
and server.

1. The Fabric-CA server should be started with the following properties set in the Fabric-CA
configuration file (server-config.yaml). In the **TLS** section, **enabled** needs to be set 
to true and **certFile** and **keyFile** should point to the certificate and key that would 
like to be used for setting up the TLS protocol. <br><br> The **caFile** property requires 
that client certificates be signed by this specific CA and client is required to send its 
certificate. The configuration file for the server should contain the following:

```
#####################################
#    TLS section
#####################################
tls:

  enabled: true
  caFile: root.pem
  certFile: tls_server-cert.pem
  keyFile: tls_server-key.pem
```

2. On client side, a configuration file (client-config.yaml) should be created as
seen below and placed in the client home directory (see [Fabric-CA Directory](#directory)).
The **caFiles** option is the set of root certificates that client uses when
verifying server certificates. The **certFile** and **keyFile** option contains file 
paths to certificate and key to present to the other side of the connection.

```
#####################################
#    TLS section
#####################################
tls:
  caFiles: 
    -root.pem
  certFile: tls-cert.pem
  keyFile: tls-key.pem
```

Once all the certificates and key have been properly configured on both client
and server, a secure connection should be established.

<div id='tls-db-server'/>
### Database & Fabric-CA Server
#### PostgreSQL

When specifying the connection string for the PostgreSQL database in the server
configuration file (server-config.yaml), we must indicate that we wish to use a secure connection.
The connection string and tls section should be set as indicated below, replacing root.pem 
with location of root certificate.

```
####################################
#    Database section
#####################################
database:

  type: postgres
  datasource: host=localhost port=5432 user=Username password=Password dbname=fabric-ca sslmode=verify-full
  
  tls:
    enabled: false
    caFiles:
      - root.pem
```
**sslmode** - Enable SSL.

  - **verify-full** - Always SSL (verify that the certification presented by the
    PostgreSQL server was signed by a trusted CA and the PostgreSQL server host name
     matches the one in the certificate).

We also need to set the TLS configuration in the Fabric-CA server config file. If the
database server requires client authentication than a client cert and key file
needs to be provided. The following should be present in the Fabric-CA server config:

```
####################################
#    Database section
#####################################
database:

  type: postgres
  datasource: host=localhost port=5432 user=Username password=Password dbname=fabric-ca sslmode=verify-full

  tls:
      enabled: false
      caFiles:
        - root.pem
      certFile: tls-cert.pem
      keyFile: tls-key.pem
```

**caFiles** - The location of the root certificate file(s).

**certFile** - Client certificate file.

**keyFile** - Client key file.

### MySQL

When specifying the connection string for the MySQL database in the server
configuration file, we must indicate that we wish to use a secure connection.
The connection string should be set with the **tls=custom** parameter. The tls 
section should be set as indicated below, replacing root.pem with 
location of root certificate.

```
####################################
#    Database section
#####################################
database:

  type: mysql
  datasource: root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom
  
  tls:
  enabled: false
  caFiles:
    - root.pem
```

In the configuration file for the Fabric-CA server, we need to define the properties
below to establish a secure connection between Fabric-CA server and MySQL server. If
the database server requires client authentication than a client cert and key
file needs to be provided as well.

```
####################################
#    Database section
#####################################
database:

  type: mysql
  datasource: root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom
  
    tls:
      enabled: false
      caFiles:
        - root.pem
      certFile: tls-cert.pem
      keyFile: tls-key.pem
```

**caFiles** - The location of the root certificate file(s).

**certFile** - Client certificate file.

**keyFile** - Client key file.

[Back to Top](#contents)

<div id='start'/>
## Start the Fabric-CA server

Execute the following commands to start the Fabric-CA server.  If you would like to
specify debug-level logging, set the `FABRIC_CA_DEBUG` environment variable to `true`.
And if you would like to run this in the background, append the "&" character to
the command.

In server-config.yaml, specify the following properties. They specify the file path to where
the CA certificate and CA key are located. If no CA certificate or CA key is provided
the server will fail to start.

```
#####################################
#    CA Certificate and Key Section
#####################################
ca:

  certFile: cert.pem
  keyFile: key.pem
```

Run the following command to start Fabric-CA server:

```
# cd $fabric-ca/bin
# ./fabric-ca server start -config ../testdata/server-config.yaml
```

It is now listening on localhost port 7054.

You can customize your Fabric-CA config file at `../testdata/server-config.yaml`.  For example,
if you want to disable authentication, you can do so by setting `authentication` to
`false`.  This prevents the Fabric-CA server from looking at the authorization header.
Auhentication is added by Fabric-CA since CFSSL does not perform authentication.  A standard HTTP
basic authentication header is required for the enroll request.  All other requests
to the Fabric-CA server will require a JWT-like token, but this work is not yet complete.

[Back to Top](#contents)

<div id='enroll'/>
## Enroll the admin client

See the `$fabric-ca/testdata/server-config.yaml` file and note the "admin" user with a password of "adminpw".
The following command gets an ecert for the admin user.

```
# cd $fabric-ca/bin
# ./fabric-ca client enroll -config <client-config.yaml> admin adminpw
```

The enrollment certificate is stored at `$FABRIC_CA_ENROLLMENT_DIR/cert.pem` by default,
but a different path can be specified by setting the `FABRIC_CA_CERT_FILE` environment
variable to an absolute path name or a path relative to the current working directory.

The enrollment key is stored at `$FABRIC_CA_ENROLLMENT_DIR/key.pem` by default, but a
different path can be specified by setting the `FABRIC_CA_KEY_FILE` environment
variable to an absolute path name or a path relative to the current working directory.

The default value of the `FABRIC_CA_ENROLLMENT_DIR` environment variable is `$FABRIC_CA_HOME`.

The default value of the `FABRIC_CA_HOME` environment variable is `$HOME/fabric-ca`.

[Back to Top](#contents)

<div id='reenroll'/>
## Reenroll

Suppose your enrollment certificate is about to expire.  You can issue the
reenroll command to renew your enrollment certificate as follows.  Note that
this is identical to the enroll command except no username or password is
required.  Instead, your previously stored private key is used to authenticate
to the Fabric-CA server.

```
# cd $fabric-ca/bin
# ./fabric-ca client reenroll -config <client-config.yaml>
```

The enrollment certificate and enrollment key are stored in the same location as
described in the previous section for the `enroll` command.

[Back to Top](#contents)

<div id='register'/>
## Register a new user

The user performing the registration request must be currently enrolled, and also
this registrar must have the proper authority to register the type of user being
registered. The registrar must have been enrolled with attribute
"hf.Registrar.DelegateRoles". The DelegateRoles attribute specifies the types
this registrar is allowed to register.

For example, the attributes for a registrar might look like this:

```
    attrs:
      - name: "hf.Registrar.DelegateRoles"
        value: "client,user,validator,auditor"
```

The registrar should then create a JSON file as defined in  the [Registration Request JSON](#registration) section.
The following command will register the user and return a password. The password can
then be used to enroll.

```
# cd $fabric-ca/bin
# ./fabric-ca client register -config <client-config.yaml> ../testdata/registerrequest.json
```

[Back to Top](#contents)

<div id='revoke'>
## Revoke certificates

To revoke a specific certificate, AKI and Serial number for the certificate needs
to be provided.

```
# cd $fabric-ca/bin
# ./fabric-ca client revoke -config <client-config.yaml> -aki 1234 -serial 1234
```

To revoke a user (including the user's enrollment and all transaction certificates), an Enrollment ID must be provided.

```
# cd $fabric-ca/bin
# ./fabric-ca client revoke -config <client-config.yaml> user1
```

[Back to Top](#contents)

<div id='ldap'/>
## LDAP

The Fabric-CA server can be configured to read from an LDAP server.

In particular, the Fabric-CA server may connect to an LDAP server to do the following:

   * authenticate a user prior to enrollment, and   
   * retrieve a user's attribute values which is used for authorization.

In order to configure the Fabric-CA server to connect to an LDAP server, add a section
of the following form to your Fabric-CA server's configuration file:

```
{
   "ldap": {
       "url": "scheme://adminDN:pass@host[:port][/base]"
       "userfilter": "filter"
   }
```

where:  
   * `scheme` is one of *ldap* or *ldaps*;  
   * `adminDN` is the distinquished name of the admin user;  
   * `pass` is the password of the admin user;   
   * `host` is the hostname or IP address of the LDAP server;  
   * `port` is the optional port number, where default 389 for *ldap* and 636 for *ldaps*;  
   * `base` is the optional root of the LDAP tree to use for searches;  
   * `filter` is a filter to use when searching to convert a login user name to
   a distinquished name.  For example, a value of `(uid=%s)` searches for LDAP
   entries with the value of a `uid` attribute whose value is the login user name.
   Similarly, `(email=%s)` may be used to login with an email address.

The following is a sample configuration section for the default settings for the
 OpenLDAP server whose docker image is at `https://github.com/osixia/docker-openldap`.

```
 "ldap": {
    "url": "ldap://cn=admin,dc=example,dc=org:admin@localhost:10389/dc=example,dc=org",
    "userfilter": "(uid=%s)"
 },
```

See `fabric-ca/testdata/testconfig-ldap.json` for the complete configuration file with
this section.  Also see `fabric-ca/scripts/run-ldap-tests` for a script which starts
an OpenLDAP docker image, configures it, runs the LDAP tests in
fabric-ca/cli/server/ldap/ldap_test.go, and stops the OpenLDAP server.

#### When LDAP is configured, enrollment works as follows:

  * A Fabric-CA client or client SDK sends an enrollment request with a basic
  authorization header.
  * The Fabric-CA server receives the enrollment request, decodes the user/pass in the
  authorization header, looks up the DN (Distinquished Name) associated with the
  user using the "userfilter" from the configuration file, and then attempts an
  LDAP bind with the user's password. If successful, the enrollment processing
  is authorized and can proceed.

#### When LDAP is configured, attribute retrieval works as follows:

   * A client SDK sends a request for a batch of tcerts **with one or more attributes**
   to the Fabric-CA server.  
   * The Fabric-CA server receives the tcert request and does as follows:
       * extracts the enrollment ID from the token in the authorization header
       (after validating the token);
       * does an LDAP search/query to the LDAP server, requesting all of the
       attribute names received in the tcert request;
       * the attribute values are placed in the tcert as normal

[Back to Top](#contents)

<div id='cluster'/>
## Setting up a cluster

<div id='haproxy'>
### HAProxy
First step to support clustering is setting up a proxy server. HAProxy is used
in this example. Below is a basic configuration file that can be used to get
HAProxy up and running. Change hostname and port to reflect the settings of your
Fabric-CA servers.

haproxy.conf

```
global
      maxconn 4096
      daemon

defaults
      mode http
      maxconn 2000
      timeout connect 5000
      timeout client 50000
      timeout server 50000

listen http-in
      bind *:7054
      balance roundrobin
      server server1 <hostname:port>
      server server2 <hostname:port>
      server server3 <hostname:port>
```

<div id='postgres'/>
### PostgreSQL

When starting up the Fabric-CA servers specify the database that you would like to
connect to. In your Fabric-CA configuration file, the following should be present for
a PostgreSQL database:

server-config.yaml

```
####################################
#    Database section
#####################################
database:

  type: mysql
  datasource: root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom
```

Change "host" and "dbname" to reflect where your database is located and the
database you would like to connect to. Default port is used if none is specified.
Enter username and password for a user that has permission to connect to the
database.

Once your proxy, Fabric-CA servers, and PostgreSQL server are all running you can have
your client direct traffic to the proxy server which will load balance and direct
traffic to the appropriate Fabric-CA server which will read/write from the PostgreSQL
database.  

<div id='mysql'/>
### MySQL

When starting up the Fabric-CA servers specify the database that you would like to
connect to. In your Fabric-CA configuration file, the following should be present for
a PostgreSQL database:

server-config.yaml

```
####################################
#    Database section
#####################################
database:

  type: mysql
  datasource: root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom
```

Change the host to reflect where your database is located. Change "root" and
"rootpw" to the username and password you would like to use to connec to the
database. The database is specified after the '/', specify the database you
would like to connect to. Default port is used if none is specified.

Once your proxy, Fabric-CA servers, and database servers are all running you can have
your clients direct traffic to the proxy server which will load balance and
direct traffic to the appropriate Fabric-CA server which will read/write from the
database.  

[Back to Top](#contents)

<div id='tests'/>
## Run the Fabric-CA tests

To run the Fabric-CA test, do the following.

WARNING: You must first stop the Fabric-CA server which you started above; otherwise,
it will fail with a port binding error.

```
# cd $fabric-ca
# make unit-tests
```

[Back to Top](#contents)

<div id='appendix'/>
## Appendix

### PostgreSQL SSL Configuration

**Basic instructions for configuring SSL on PostgreSQL server:**
1. In postgresql.conf, uncomment SSL and set to "on" (SSL=on)
2. Place Certificate and Key files in Postgres data directory.

Instructions for generating self-signed certificates for:
https://www.postgresql.org/docs/9.1/static/ssl-tcp.html

Note: Self-signed certificates are for testing purposes and should not be used
in a production environment

**PostgreSQL Server - Require Certificates from Fabric-CA server**
1. Place certificates of the certificate authorities (CAs) you trust in the file
 root.crt in the PostgreSQL data directory
2. In postgresql.conf, set "ssl_ca_file" to point to the root cert of client (CA cert)
3. Set the clientcert parameter to 1 on the appropriate hostssl line(s) in pg_hba.conf.

For more details on configuring SSL on the PostgreSQL server, please refer to the
following PostgreSQL documentation: https://www.postgresql.org/docs/9.4/static/libpq-ssl.html


### MySQL SSL Configuration
**Basic instructions for configuring SSL on MySQL server:**
1. Open or create my.cnf file for the server. Add or un-comment the lines below
in [mysqld] section. These should point to the key and certificates for the
server, and the root CA cert.

Instruction on creating server and client side certs:
http://dev.mysql.com/doc/refman/5.7/en/creating-ssl-files-using-openssl.html

[mysqld]
ssl-ca=ca-cert.pem
ssl-cert=server-cert.pem
ssl-key=server-key.pem

Can run the following query to confirm SSL has been enabled.

mysql> SHOW GLOBAL VARIABLES LIKE 'have_%ssl';

Should see:
```
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| have_openssl  | YES   |
| have_ssl      | YES   |
+---------------+-------+
```

2. After the server-side SSL configuration is finished, the next step is to
create a user who has a privilege to access the MySQL server over SSL. For that,
log in to the MySQL server, and type:

mysql> GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY 'password' REQUIRE SSL;
mysql> FLUSH PRIVILEGES;

If you want to give a specific ip address from which the user will access the
server change the '%' to the specific ip address.

**MySQL Server - Require Certificates from Fabric-CA server**
Options for secure connections are similar to those used on the server side.

- ssl-ca identifies the Certificate Authority (CA) certificate. This option,
if used, must specify the same certificate used by the server.
- ssl-cert identifies the client public key certificate.
- ssl-key identifies the client private key.

Suppose that you want to connect using an account that has no special encryption
requirements or was created using a GRANT statement that includes the REQUIRE SSL
option. As a recommended set of secure-connection options, start the MySQL
server with at least --ssl-cert and --ssl-key, and invoke the Fabric-CA server with
**ca_certfiles** option set in the Fabric-CA server file.

To require that a client certificate also be specified, create the account using
the REQUIRE X509 option. Then the client must also specify the proper client key
and certificate files or the MySQL server will reject the connection. CA cert,
client cert, and client key are all required for the Fabric-CA server.

<div id='directory'>
### Fabric-CA Directory
The Fabric-CA directory will contain various files depending on if server or client side.

Location of Fabric-CA directory will depend on the environment variables set. If
FABRIC\_CA\_HOME is set, the Fabric-CA directory can be found at $FABRIC\_CA\_HOME/fabric-ca.
If FABRIC\_CA\_HOME is not set and HOME is set than the Fabric-CA directory can be found at
$HOME/fabric-ca. If neither one of those environment variables is set, the default
location of directory is: `/var/hyperledger/fabric/dev/fabric-ca`

[Back to Top](#contents)
