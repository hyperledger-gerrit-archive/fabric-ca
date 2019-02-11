.. code:: yaml

   version: '2'

   networks:
   fabric-ca:

   services:
   ca-tls:
      container_name: ca-tls
      image: hyperledger/fabric-ca
      command: sh -c 'fabric-ca-server start -d -b tls-ca-admin:tls-ca-adminpw --port 7052'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
         - FABRIC_CA_SERVER_CSR_CN=tls-ca
         - FABRIC_CA_SERVER_CSR_HOSTS=tls-ca,0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - /tmp/hyperledger/tls/ca:/tmp/hyperledger/fabric-ca
      networks:
         - fabric-ca
      ports:
         - 7052:7052
