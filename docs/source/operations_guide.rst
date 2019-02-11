Fabric CA Operation's Guide
============================

This guide will illustrate how to use Fabric CA to setup
a Fabric network. All identities participation on a Hyperledger
Fabric blockchain network require that they be authorized. This
authorization comes in the form of cryptographic material that is
verified against trusted authorities. 

In this guide, you will see what the process is for setting up a
blockchain network between two organization with two peers each,
and an orderer. You'll see how to generate crypto material for orderers,
peers, administrators, and end users so that private keys never leave
the host or container in which they are generated.

This guide will use Mutual Auth TLS to establish a secure and encrypted
network.

<<<<<< insert diagram >>>>>>

Setup for TLS CA
-----------------

This guide will use TLS for client to server communication. First, you will setup
a CA that will be responsible for issuing TLS certificates. To simplfyy this
example all organization will use the same TLS CA to get their TLS certificates.

The TLS issue certificate issued from this CA will be used for communication
between end user, peers, and orderers.

A docker service, such as the one below can be used to a launch a Fabric CA
container.

.. code:: yaml

  ca-tls:
    container_name: ca-tls
    image: hyperledger/fabric-ca
    command: sh -c 'fabric-ca-server start -d -b tls-ca-admin:tls-ca-adminpw --port 7052'
    environment:
      - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
      - FABRIC_CA_SERVER_TLS_ENABLED=true
      - FABRIC_CA_SERVER_CSR_CN=tls-ca
      - FABRIC_CA_SERVER_CSR_HOSTS=tls-ca,0.0.0.0
      - FABRIC_CA_SERVER_DEBUG=true
    volumes:
      - ./tls/ca:/tmp/hyperledger/fabric-ca
    networks:
      - fabric-ca
    ports:
      - 7052:7052

Enrolling CA Admin
^^^^^^^^^^^^^^^^^^^

The CA server was bootstrapped with an identity that has full admin privileges on the CA. One of the
key abilities of the admin is the ability to register new identities. The administrator for this CA will use 
the Fabric CA client to register four new identities with the CA. These identities will be used to get TLS certificates for peers, org admin, and end users.

You will issue the commands below to get the CA admin enrolled and register identities.
In the commands below, we will assume the issuing certificate for CA's TLS certificate has been
copied to /tmp/hyperledger/tls-ca/crypto/tls-ca-cert.pem

.. code:: bash


   export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/tls-ca/crypto/tls-ca-cert.pem
   export FABRIC_CA_CLIENT_HOME=/tmp/tls-ca/admin
   fabric-ca-client enroll -d -u http://tls-ca-admin:tls-ca-adminpw@0.0.0.0:7052
   fabric-ca-client register -d --id.name peer1-org1 --id.secret peer1PW --id.type peer -u https://0.0.0.0:7052 
   fabric-ca-client register -d --id.name peer2-org1 --id.secret peer2PW --id.type peer -u https://0.0.0.0:7052
   fabric-ca-client register -d --id.name peer1-org2 --id.secret peer1PW --id.type peer -u https://0.0.0.0:7052 
   fabric-ca-client register -d --id.name peer2-org2 --id.secret peer2PW --id.type peer -u https://0.0.0.0:7052
   fabric-ca-client register -d --id.name orderer1-org0 --id.secret ordererPW --id.type orderer -u https://0.0.0.0:7052 

With the identities registered on the TLS CA, we can move forward to bootstrapping each organization. Anytime we need to get TLS certificates for a node in an organization, we will refer to this CA.

Setup for Org 1
-----------------

Each organziation will consist of it's own Certificate Authority (CA) for issuing enrollment certificates.
The peers in the each organization will use the CA to acquire certificates. In the steps below we will go through the flow of getting an organziation up and running on a blockchain network.

Setting up CA
~~~~~~~~~~~~~~~

An administrator for Org 1 will launch a Fabric CA docker container, which
will be used by Org 1 to issue crypto material for identities in Org 1.

A docker service, such as the one below can be used to a launch a Fabric CA
container.

.. code:: yaml

   rca-org1:
      container_name: rca-org1
      image: hyperledger/fabric-ca
      command: /bin/bash -c 'fabric-ca-server start -d -b rca-org1-admin:rca-org1-adminpw'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca
         - FABRIC_CA_SERVER_TLS_ENABLED=true
         - FABRIC_CA_SERVER_CSR_CN=rca-org1
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - ./ca-server:/tmp/hyperledger/fabric-ca
      networks:
         - org1
      ports:
         - 7054:7054

On a successfull launch of the container, you will see the following line in
the CA container's log.

.. code:: bash

   [INFO] Listening on https://0.0.0.0:7054

At this point the CA server is on a listening on a secure socket, and can start
issuing crypto material.

Download fabric-ca-client binary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For each host that needs to acquire crypto material, you will need to have the
fabric-ca-client binary available on the host machine that will be used to connect
to the Fabric CA server container.

To download the fabric-ca-client binary. Go to the following link: https://nexus.hyperledger.org/content/repositories/releases/org/hyperledger/fabric-ca/hyperledger-fabric-ca/

Download the latest binary suitable for your machine. Before you can start using
the CA client, you must acquire the signing certificate for CA's TLS certificate.
This is a required step before you can connect using TLS. In our example, you
would go to `/ca-server/ca-cert.pem` on the machine running the CA server and
copy this file over to the host where we are running the CA client binary.
This certificate is going to be used to validate the TLS certificate of the CA.
Once the certificate has been copied over to the CA client's host machine,
you can start issuing commands.

The CA's signing certificate will need to available on each host that will run
commands against the CA.

Enrolling CA Admin
^^^^^^^^^^^^^^^^^^^

The CA server was bootstrapped with an identity that has full admin privileges
on the CA. One of the key abilities of the admin is the ability to register new
identities. The admin for Org 1 will use the Fabric CA client to register four
new identities with the CA. These identities will be used to enroll the peers,
org admin, and end users.

You will issue the commands below to get the CA admin enrolled and all org 1
/tmp/hyperledger/org1/ca/crypto/tls-ca-cert.pem on CA client's host machine.

.. code:: bash

    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/org1/ca/crypto/tls-ca-cert.pem
    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org1/ca/admin
    fabric-ca-client enroll -d -u https://rca-org1-admin:rca-org1-adminpw@0.0.0.0:7054
    fabric-ca-client register -d --id.name peer1-org1 --id.secret peer1PW --id.type peer -u https://0.0.0.0:7054 
    fabric-ca-client register -d --id.name peer2-org1 --id.secret peer2PW --id.type peer -u https://0.0.0.0:7054
    fabric-ca-client register -d --id.name admin-org1 --id.secret org1AdminPW --id.type user -u https://0.0.0.0:7054 
    fabric-ca-client register -d --id.name user-org1 --id.secret org1UserPW --id.type user -u https://0.0.0.0:7054

Setting up Peers
~~~~~~~~~~~~~~~~~

An administrator for Org 1 will enroll the peers with the CA and then launch the
peer docker containers. 

Peer1
^^^^^^^

Before starting the peer, you will need to enroll the peer identity with the CA
to get the MSP that the peer will use. This is known as the local peer MSP.

If the host machine running peer1 does not have the fabric-ca-client binary, please
refer to the instructions above on to download the binary.

On the Peer1's host machine, you will get out of band org1's CA's signing
certificate. You will issue the commands below to get the first peer enrolled.
In the commands below, we will assume the issuing certificate for CA's TLS
certificate has been has been copied to
/tmp/hyperledger/crypto/org1/peer1/org1-ca-cert.pem on peer1's host machine. 

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org1/peer1
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org1/peer1/org1-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer1-org1:peer1PW@0.0.0.0:7054

Next step is to get the TLS crypto for the peer. This requires another enrollment,
but this time you will enroll against the ``tls`` profile on the TLS CA. You will
also need to provide the address of the host machine in the enrollment request as
the input to the ``csr.hosts`` flag.

.. code:: bash

    export FABRIC_CA_CLIENT_MSPDIR=tls-msp
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org1/peer1/tls-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer1-org1:peer1PW@0.0.0.0:7052 --enrollment.profile tls --csr.hosts peer1-org1

Go to path ``/tmp/hyperledger/org1/peer1/tls-msp/keystore`` and change the name of
the key to ``key.pem``. This will make it easy to be able to refer to the key in
later steps.

At this point, you will have two MSP directories. One MSP contains peer's enrollment
certificate and the other has the peer's TLS certificate. However, there needs be
on additional folder added in the enrollment MSP directory, and this is the ``admincerts``
folder. This folder will contain certificates for the administrator of org 1.
We will talk more about this when we enroll org1's admin a little further down.

A docker service, such as the one below can be used to a launch a container for peer1.

.. code:: yaml

  peer1-org1:
    container_name: peer1-org1
    image: hyperledger/fabric-peer
    environment:
      - CORE_PEER_ID=peer1-org1
      - CORE_PEER_ADDRESS=peer1-org1:7051
      - CORE_PEER_LOCALMSPID=org1MSP
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org1/peer1/msp
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
      - FABRIC_LOGGING_SPEC=grpc=debug:info
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org1/peer1/tls-msp/signcerts/cert.pem
      - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org1/peer1/tls-msp/keystore/key.pem
      - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org1/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
      - CORE_PEER_GOSSIP_USELEADERELECTION=true
      - CORE_PEER_GOSSIP_ORGLEADER=false
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer1-org1:7051
      - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org1/peer1
    volumes:
      - /var/run:/host/var/run
      - /tmp/hyperledger/org1/peer1:/tmp/hyperledger/org1/peer1
    networks:
      - fabric-ca

Launching the peer service will bring up a peer container, and in the logs you will
see the following line:

.. code:: bash

   serve -> INFO 020 Started peer with ID=[name:"peer1-org1" ], network ID=[dev], address=[peer1-org1:7051]

Peer 2
^^^^^^^

You will similiar commands for Peer2. In the commands below, we will
assume the issuing certificate for CA's TLS certificate has been has been copied to
/tmp/hyperledger/crypto/org1/peer2/org1-ca-cert.pem on peer 1's host machine. 

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org1/peer2
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org1/peer2/org1-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer2-org1:peer2PW@0.0.0.0:7054

Next step is to get the TLS crypto for the peer. This requires another enrollment,
but this time you will enroll against the ``tls`` profile on the CA. You will also
need to provide the address of the host machine in the enrollment request as the
input to the ``csr.hosts`` flag.

.. code:: bash

    export FABRIC_CA_CLIENT_MSPDIR=tls-msp
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org1/peer2/tls-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer2-org1:peer2PW@0.0.0.0:7052 --enrollment.profile tls --csr.hosts peer2-org1

Go to path ``./peer1/tls-msp/keystore`` and change the name of the key to ``key.pem``.
This will make it easy to be able to refer to the key in later steps.

At this point, you will have two MSP directories. One MSP contains peer's enrollment
certificate and the other has the peer's TLS certificate. However, there needs be
on additional folder added in the enrollment MSP directory, and this is the ``admincerts``
folder. This folder will contain certificates for the administrator of org 1.
We will talk more about this when we enroll org1's admin a little further down.

A docker service, such as the one below can be used to a launch a container for the first peer.

.. code:: yaml

  peer2-org1:
    container_name: peer2-org1
    image: hyperledger/fabric-peer
    environment:
      - CORE_PEER_ID=peer2-org1
      - CORE_PEER_ADDRESS=peer2-org1:7051
      - CORE_PEER_LOCALMSPID=org1MSP
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org1/peer2/msp
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
      - FABRIC_LOGGING_SPEC=grpc=debug:info
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org1/peer2/tls-msp/signcerts/cert.pem
      - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org1/peer2/tls-msp/keystore/key.pem
      - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org1/peer2/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
      - CORE_PEER_GOSSIP_USELEADERELECTION=true
      - CORE_PEER_GOSSIP_ORGLEADER=false
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer2-org1:7051
      - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer1-org1:7051
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org1/peer2
    volumes:
      - /var/run:/host/var/run
      - /tmp/hyperledger/org1/peer2:/tmp/hyperledger/org1/peer2
    networks:
      - fabric-ca

Launching the peer service will bring up a peer container, and in the logs you
will see the following line:

.. code:: bash

    serve -> INFO 020 Started peer with ID=[name:"peer2-org1" ], network ID=[dev], address=[peer2-org1:7051]

Enrolling Org Admin
~~~~~~~~~~~~~~~~~~~~

At this point, both peer identities have been enrolled. Now, you will enroll the
org's admin identity. The admin identity is responsible for activities such as
installing and instantiating chaincode. The steps below go through enrolling the
admin.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org1/admin
    export FABRIC_CA_CLIENT_MSPDIR=msp
    fabric-ca-client enroll -d -u https://admin-org1:org1@0.0.0.0:7055

After enrollment, you should have an admin MPS. You will copy the
certifcate from this MSP and move it to the peer MSPs under the ``admincerts``
folder.

.. code:: bash

    mkdir /tmp/hyperledger/org1/peer1/msp/admincerts
    mkdir /tmp/hyperledger/org1/peer2/msp/admincerts
    cp /tmp/hyperledger/org1/admin/msp/signcerts/cert.pem /tmp/hyperledger/org1/peer1/msp/admincerts/org1-admin-cert.pem
    cp /tmp/hyperledger/org1/admin/msp/signcerts/cert.pem /tmp/hyperledger/org1/peer2/msp/admincerts/org1-admin-cert.pem

Setup for Org 2
-----------------

The same set of steps that you followed for org 1 apply to org 2. So we will quickly
go through the set of steps that administrator on org 2 will perform.

Setting up CA
~~~~~~~~~~~~~~~

A docker service, such as the one below can be used to a launch a Fabric CA for Org 2.

.. code:: yaml

  rca-org2:
    container_name: rca-org2
    image: hyperledger/fabric-ca
    command: /bin/bash -c 'fabric-ca-server start -d -b rca-org2-admin:rca-org2-adminpw --port 7055'
    environment:
      - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
      - FABRIC_CA_SERVER_TLS_ENABLED=true
      - FABRIC_CA_SERVER_CSR_CN=rca-org2
      - FABRIC_CA_SERVER_CSR_HOSTS=rca-org2,0.0.0.0
      - FABRIC_CA_SERVER_DEBUG=true
    volumes:
      - ./org2/ca:/tmp/hyperledger/fabric-ca
    networks:
      - fabric-ca
    ports:
      - 7055:7055

On a successfull launch of the container, you will see the following line in
the CA container's log.

.. code:: bash

   [INFO] Listening on https://0.0.0.0:7055

At this point the CA server is on a listening on a secure socket, and can start issuing
crypto material.

Download fabric-ca-client binary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each host that needs to acquire crypto material, you will need to have the
fabric-ca-client binary avialable on the host machince that will be used to
connect to the Fabric CA server container.

To download the fabric-ca-client binary. Go to the following link: https://nexus.hyperledger.org/content/repositories/releases/org/hyperledger/fabric-ca/hyperledger-fabric-ca/

Enrolling CA Admin
^^^^^^^^^^^^^^^^^^^

You will issue the commands below to get the CA admin enrolled and all peer
related identities registered. In the commands below, we will assume the CA's
certificate has been copied to /tmp/hyperledger/org2/ca/crypto/tls-ca-cert.pem

.. code:: bash

    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/org2/ca/crypto/tls-ca-cert.pem
    fabric-ca-client enroll -d -u https://rca-org2-admin:rca-org2-adminpw@0.0.0.0:7055
    fabric-ca-client register -d --id.name peer1-org2 --id.secret peer1PW --id.type peer -u https://0.0.0.0:7055 
    fabric-ca-client register -d --id.name peer2-org2 --id.secret peer2PW --id.type peer -u https://0.0.0.0:7055
    fabric-ca-client register -d --id.name admin-org2 --id.secret org2AdminPW --id.type user -u https://0.0.0.0:7055 
    fabric-ca-client register -d --id.name user-org2 --id.secret org2UserPW --id.type user -u https://0.0.0.0:7055

Setting up Peers
~~~~~~~~~~~~~~~~~

An administrator for Org 2 will use the CA bootstap identity to enroll the peers
with the CA and then launch the peer docker containers. 

Peer1
^^^^^^^

You will issue the commands below to get the peer1 enrolled. In the commands below,
we will assume the CA's certificate is available at
/tmp/hyperledger/crypto/org2/peer1/tls-ca-cert.pem on peer1's host machine. 

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org2/peer1
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org2/peer1/org2-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer1-org2:peer1PW@0.0.0.0:7055

Get TLS certificates:

.. code:: bash

    export FABRIC_CA_CLIENT_MSPDIR=tls-msp
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org2/peer1/tls-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer1-org2:peer1PW@0.0.0.0:7052 --enrollment.profile tls --csr.hosts peer1-org2

Go to path ``/tmp/hyperledger/peer1/tls-msp/keystore`` and change the name of the
key to ``key.pem``.

A docker service, such as the one below can be used to a launch a container for
the peer1.

.. code:: yaml

  peer1-org2:
    container_name: peer1-org2
    image: hyperledger/fabric-peer
    environment:
      - CORE_PEER_ID=peer1-org2
      - CORE_PEER_ADDRESS=peer1-org2:7051
      - CORE_PEER_LOCALMSPID=org2MSP
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org2/peer1/msp
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
      - FABRIC_LOGGING_SPEC=debug
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org2/peer1/tls-msp/signcerts/cert.pem
      - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org2/peer1/tls-msp/keystore/key.pem
      - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org2/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
      - CORE_PEER_GOSSIP_USELEADERELECTION=true
      - CORE_PEER_GOSSIP_ORGLEADER=false
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer1-org2:7051
      - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org2/peer1
    volumes:
      - /var/run:/host/var/run
      - /tmp/hyperledger/org2/peer1:/tmp/hyperledger/org2/peer1
    networks:
      - fabric-ca

Launching the peer service will bring up a peer container, and in the logs you
will see the following line:

.. code:: bash

   serve -> INFO 020 Started peer with ID=[name:"peer1-org2" ], network ID=[dev], address=[peer1-org2:7051]

Peer2
^^^^^^^

You will issue the commands below to get the peer2 enrolled. In the commands below,
we will assume the CA's certificate is available at
/tmp/hyperledger/crypto/org2/peer2/org2-ca-cert.pem on peer2's host machine. 

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org2/peer2
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org2/peer2/org2-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer2-org2:peer2PW@0.0.0.0:7055

Get TLS certificates:

.. code:: bash

    export FABRIC_CA_CLIENT_MSPDIR=tls-msp
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/tmp/hyperledger/crypto/org2/peer2/tls-ca-cert.pem
    fabric-ca-client enroll -d -u https://peer2-org2:peer2PW@0.0.0.0:7052 --enrollment.profile tls --csr.hosts peer2-org2

Go to path ``/tmp/hyperledger/org2/peer2/tls-msp/keystore`` and change the name
of the key to ``key.pem``.

A docker service, such as the one below can be used to a launch a container for the peer1.

.. code:: yaml

  peer2-org2:
    container_name: peer2-org2
    image: hyperledger/fabric-peer
    environment:
      - CORE_PEER_ID=peer2-org2
      - CORE_PEER_ADDRESS=peer2-org2:7051
      - CORE_PEER_LOCALMSPID=org2MSP
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org2/peer2/msp
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
      - FABRIC_LOGGING_SPEC=debug
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org2/peer2/tls-msp/signcerts/cert.pem
      - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org2/peer2/tls-msp/keystore/key.pem
      - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org2/peer2/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
      - CORE_PEER_GOSSIP_USELEADERELECTION=true
      - CORE_PEER_GOSSIP_ORGLEADER=false
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer2-org2:7051
      - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer1-org2:7051
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org2/peer2
    volumes:
      - /var/run:/host/var/run
      - ./org2/peer2:/tmp/hyperledger/org2/peer2
    networks:
      - fabric-ca
   version: '2'

Launching the peer service will bring up a peer container, and in the logs you will see the following line:

.. code:: bash

    serve -> INFO 020 Started peer with ID=[name:"peer2-org2" ], network ID=[dev], address=[peer2-org2:7052]

Enrolling Org Admin
~~~~~~~~~~~~~~~~~~~~

At this point, you will have two MSP directory. One MSP contains your enrollment certificate and the other
has your TLS certificate. However, there needs be on additional folder added in the enrollment MSP directory, this is the ``admincerts`` folder. This folder will contain certificates for the administrator of org2. You will enroll the org2 admin's identity by issuing the commands below.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=/tmp/hyperledger/org2/admin
    export FABRIC_CA_CLIENT_MSPDIR=msp
    fabric-ca-client enroll -d -u https://admin-org2:org2AdminPW@0.0.0.0:7055

After enrollment, you should have an admin msp folder at. You will copy the certifcate from this MSP
and move it to the peer MSP under the ``admincerts`` folder.

.. code:: bash

    mkdir /tmp/hyperledger/org2/peer1/msp/admincerts
    mkdir /tmp/hyperledger/org2/peer2/msp/admincerts
    cp /tmp/hyperledger/org2/admin/msp/signcerts/cert.pem /tmp/hyperledger/org2/peer1/msp/admincerts/org2-admin-cert.pem
    cp /tmp/hyperledger/org2/admin/msp/signcerts/cert.pem /tmp/hyperledger/org2/peer2/msp/admincerts/org2-admin-cert.pem

Setup for Orderer
-----------------

Setting up CA
~~~~~~~~~~~~~~~

An administrator for Org 1 will launch a Fabric CA docker container, which
will be used by Org 1 to issue crypto material for identities in Org 1 that
wish to participate on the blockchain network.

A docker-compose.yaml file, such as the one below can be used to a launch a
Fabric CA container.

.. code:: yaml

   rca-org0:
      container_name: rca-org1
      image: hyperledger/fabric-ca
      command: /bin/bash -c 'fabric-ca-server start -d -b rca-org0-admin:rca-org0-adminpw --port 7055'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca
         - FABRIC_CA_SERVER_TLS_ENABLED=true
         - FABRIC_CA_SERVER_CSR_CN=rca-org0
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - ./ca-server:/tmp/hyperledger/fabric-ca
      networks:
         - org0
      ports:
         - 7056:7056

From the directory where the docker-compose.yaml file is located, run the command below:

.. code:: bash

   docker-compose up

This will launch the container, and if the lauch is successfull you will see the following line
the CA container's log.

.. code:: bash

   [INFO] Listening on https://0.0.0.0:7056

At this point the CA server is on a listening on a secure socket, and can start issuing
crypto material.

Download fabric-ca-client binary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On a host that will connect to the Fabric CA server container, you need to download the
fabric-ca-client binary. Go to the following link: https://nexus.hyperledger.org/content/repositories/releases/org/hyperledger/fabric-ca/hyperledger-fabric-ca/

Download the latest binary suitable for your machine. Before you can start using the CA client,
you must be able to refer to the CA's certificate. This is a required step before you can connect
using TLS. In our example, we would go to `/ca-server/ca-cert.pem` and copy this file over to
the host where we are running the CA client binary. Once the certificate has been copied over to
the CA client's host machine, you can start issuing commands.

Enrolling CA Admin
^^^^^^^^^^^^^^^^^^^

The CA server was bootstrapped with an identity that has full admin privileges on the CA. One of the
key abilities of the admin is the ability to register new identities. The admin for Org1 will use the
Fabric CA client to register four new identities with the CA. These identities will be used to enroll
the peers and peer admin's.

You will issue the commands below to get the CA admin enrolled and all peer related identities registered.
In the commands below, we will assume the CA's certificate has been copied to /crypto/org1/ca-cert.pem

.. code:: bash

    export FABRIC_CA_CLIENT_TLS_CERTFILES=/crypto/org0/ca-cert.pem
    fabric-ca-client enroll -d -u https://rca-org0-admin:rca-org0-adminpw@0.0.0.0:7056
    fabric-ca-client register -d --id.name orderer-org0 --id.secret ordererPW --id.type orderer -u https://0.0.0.0:7056 
    fabric-ca-client register -d --id.name orderer-org0-admin --id.secret ordererAdminPW --id.type user -u https://0.0.0.0:7056 

---------------

Before starting the peer, you will need to enroll the peer identity with the CA to get the MSP
that the peer will use. This is known as the local peer MSP.

If the host machine does not have the fabric-ca-client binary, please refer to the instructions above
on to download the binary.

You will issue the commands below to get the first peer enrolled. In the commands below,
we will assume the CA's certificate is available at /crypto/org1/peer1/ca-cert.pem on peer 1's
host machine. 

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=./orderer
    export FABRIC_CA_CLIENT_TLS_CERTFILES=/crypto/org0/orderer/ca-cert.pem
    fabric-ca-client enroll -d -u https://orderer-org0:ordererPW@0.0.0.0:7056

Next step is to get the TLS crypto for the peer. This requires another enrollment, but this time you will
enroll against the ``tls`` profile on the CA. You will also need to provide the host's in your enrollment
request.

.. code:: bash

    export FABRIC_CA_CLIENT_MSPDIR=tls-msp
    fabric-ca-client enroll -d -u https://orderer-org0:ordererPW@0.0.0.0:7056 --enrollment.profile tls --csr.hosts orderer1-org0

Go to path ``./orderer/tls-msp/keystore`` and change the name of the key to ``key.pem``.

At this point, you will have two MSP directory. One MSP contains your enrollment certificate and the other
has your TLS certificate. However, there needs be on additional folder added in the enrollment MSP directory, this is the ``admincerts`` folder. This folder will contain certificates for the administrator of peer 1. Now, you will enroll the peer admin's identity by issuing the commands below.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=./orderer-admin
    export FABRIC_CA_CLIENT_MSPDIR=msp
    fabric-ca-client enroll -d -u https://orderer-org0-admin:ordererAdminPW@0.0.0.0:7056

After enrollment, you should have an msp folder at ``orderer-admin``. You will copy the certifcate from this MSP
and move it to the peer MSP under the ``admincerts`` folder.

.. code:: bash

    mkdir ./orderer/msp/admincerts
    cp ./orderer-admin/msp/signcerts/cert.pem ./orderer/msp/admincerts/orderer-admin-cert.pem

create genesis block

genesis block: configtxgen -profile OrgsOrdererGenesis -outputBlock orderer/genesis.block
channel block: configtxgen -profile OrgsChannel -outputCreateChannelTx orderer/channel.tx -channelID mychannel

compose file:

UTC [orderer/common/server] Start -> INFO 0b8 Beginning to serve requests


Create Channel on Peers
--------------------------

export FABRIC_LOGGING_SPEC=debug

switch to msp of admin identity
export CORE_PEER_MSPCONFIGPATH=peer-admin/msp (need admin cert in both signcert and admincert folders)

peer channel create -c mychannel -f /tmp/hyperledger/cli/org2/peer1/assets/channel.tx -o orderer1-org1:7050 --tls --cafile /tmp/crypto/orderer-rootca.pem
returns back mychannel.block. needs to be transfered to all peers that will join network.

---- join channel

      peer channel join -b $CHANNEL_NAME.block

      - CORE_PEER_ADDRESS=peer1-org1:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org1/peer1/msp

      - CORE_PEER_ADDRESS=peer2-org1:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org1/peer2/msp

      - CORE_PEER_ADDRESS=peer1-org2:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org2/peer1/msp

      - CORE_PEER_ADDRESS=peer2-org2:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org2/peer2/msp

      how to get chaincode on to container to run chaincode install????

      - CORE_PEER_ADDRESS=peer1-org1:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org1/peer1/msp

mkdir /opt/gopath/src/github.com/hyperledger/fabric-samples
      cp -r /tmp/hyperledger/cli/org1/peer1/chaincode/ /opt/gopath/src/github.com/hyperledger/fabric-samples/
      peer chaincode install -n mycc -v 1.0 -p github.com/hyperledger/fabric-samples/chaincode/abac/go


      - CORE_PEER_ADDRESS=peer1-org2:7051
      - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/cli/org2/peer1/msp

---- install chaincode

mkdir /opt/gopath/src/github.com/hyperledger/fabric-samples
      cp -r /tmp/hyperledger/cli/org2/peer1/chaincode/ /opt/gopath/src/github.com/hyperledger/fabric-samples/
     peer chaincode install -n mycc -v 1.0 -p github.com/hyperledger/fabric-samples/chaincode/abac/go


---- chaincode instantiate

peer chaincode instantiate -C mychannel -n mycc -v 1.0 -c '{"Args":["init","a","100","b","200"]}' -o orderer1-org1:7050

---- query chaincode 

peer chaincode query -C mychannel -n mycc -c '{"Args":["query","a"]}'

--- invoke chaincode

peer chaincode invoke -C mychannel -n mycc -c '{"Args":["invoke","a","b","10"]}'



err:  error validating DeltaSet: policy for [Group]  /Channel/Application not satisfied: Failed to reach implicit threshold of 1 sub-policies, required 1 remaining

