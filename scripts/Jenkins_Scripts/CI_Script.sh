#!/bin/bash -e
#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#

# error check
err_Check() {

echo -e "\033[31m $1" "\033[0m"
exit 1

}

Parse_Arguments() {
        while [ $# -gt 0 ]; do
                case $1 in
                        --env_Info)
                                env_Info
                                ;;
                        --clean_Environment)
                                clean_Environment
                                ;;
                        --node_E2e_Tests)
                                node_E2e_Tests
                                ;;
                        --pullJavaEnv)
                                pullJavaEnv
                                ;;
                esac
                shift
        done
}

clean_Environment() {

echo "-----------> Clean Docker Containers & Images, unused/lefover build artifacts"
function clearContainers () {
        CONTAINER_IDS=$(docker ps -aq)
        if [ -z "$CONTAINER_IDS" ] || [ "$CONTAINER_IDS" = " " ]; then
                echo "---- No containers available for deletion ----"
        else
                docker rm -f $CONTAINER_IDS || true
        fi
}

function removeUnwantedImages() {

        for i in $(docker images | grep none | awk '{print $3}'); do
                docker rmi ${i};
        done

        for i in $(docker images | grep -vE ".*baseimage.*(0.4.13|0.4.14)" | grep -vE ".*baseos.*(0.4.13|0.4.14)" | grep -vE ".*couchdb.*(0.4.13|0.4.14)" | grep -vE ".*zoo.*(0.4.13|0.4.14)" | grep -vE ".*kafka.*(0.4.13|0.4.14)" | grep -v "REPOSITORY" | awk '{print $1":" $2}'); do
                docker rmi ${i};
        done
}

# Delete nvm prefix & then delete nvm
rm -rf $HOME/.nvm/ $HOME/.node-gyp/ $HOME/.npm/ $HOME/.npmrc || true
# Delete node_modules
rm -rf $WORKSPACE/gopath/src/github.com/hyperledger/fabric-sdk-node/node_modules || true
rm -rf $WORKSPACE/gopath/src/github.com/hyperledger/fabric-chaincode-node/node_modules || true

mkdir $HOME/.nvm || true

# remove tmp/hfc and hfc-key-store data
rm -rf /home/jenkins/.nvm /home/jenkins/npm /tmp/fabric-shim /tmp/hfc* /tmp/npm* /home/jenkins/kvsTemp /home/jenkins/.hfc-key-store

rm -rf /var/hyperledger/*
rm -rf gopath/src/github.com/hyperledger/fabric-ca

clearContainers
removeUnwantedImages
}

env_Info() {
        # This function prints system info
        #### Build Env INFO
        echo -e "\033[32m -----------> Build Env INFO" "\033[0m"
        # Output all information about the Jenkins environment
        uname -a
        cat /etc/*-release
        env
        gcc --version
        docker version
        docker info
        docker-compose version
        pgrep -a docker
        docker images
        docker ps -a
}

pullJavaEnv() {

        NEXUS_URL=nexus3.hyperledger.org:10001
        ORG_NAME="hyperledger/fabric-javaenv"
        # Update Java_Env_Tag to the latest version
        # This version is depending on what fabric-chaincode-java merge job publish
        JAVA_ENV_TAG=1.4.0
        JAVA_ENV_VERSION=amd64-$JAVA_ENV_TAG-stable
        docker pull $NEXUS_URL/$ORG_NAME:$JAVA_ENV_VERSION
        docker tag $NEXUS_URL/$ORG_NAME:$JAVA_ENV_VERSION $ORG_NAME
        docker tag $NEXUS_URL/$ORG_NAME:$JAVA_ENV_VERSION $ORG_NAME:amd64-$JAVA_ENV_TAG
        docker rmi -f $NEXUS_URL/$ORG_NAME:$JAVA_ENV_VERSION
}

# Install node
install_Node() {

echo "-------> ARCH:" $ARCH
if [[ $ARCH == "s390x" || $ARCH == "ppc64le" ]]; then

        # Install nvm to install multi node versions
        wget -qO- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
        # shellcheck source=/dev/null
        export NVM_DIR="$HOME/.nvm"
        # shellcheck source=/dev/null
        [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"  # This loads nvm
        echo "------> Install NodeJS"
        # Install NODE_VER
        echo "------> Use $NODE_VER"
        nvm install $NODE_VER || true
        nvm use --delete-prefix v$NODE_VER --silent
        npm install || err_Check "ERROR!!! npm install failed"
        npm config set prefix ~/npm && npm install -g gulp && npm install -g istanbul

        echo -e "\033[32m npm version ------> $(npm -v)" "\033[0m"
        echo -e "\033[32m node version ------> $(node -v)" "\033[0m"

else

        echo -e "\033[32m npm version ------> $(npm -v)" "\033[0m"
        echo -e "\033[32m node version ------> $(node -v)" "\033[0m"

        npm install || err_Check "ERROR!!! npm install failed"
        npm install -g gulp && npm install -g istanbul
fi
}

# run fabric-sdk-Node SDK e2e Tests
node_E2e_Tests() {

        cd ${WORKSPACE}/gopath/src/github.com/hyperledger
        # Clone fabric-sdk-node repository
        git clone --single-branch -b $GERRIT_BRANCH git://cloud.hyperledger.org/mirror/fabric-sdk-node
        echo -e "\033[32m cloned fabric-sdk-node repository" "\033[0m"
        # Install NPM before start the tests
        cd fabric-sdk-node
        # Print last two commits
        echo
        git log -n2 --pretty=oneline --abbrev-commit
        echo
        # Install NodeJS
        install_Node

        gulp || err_Check "ERROR!!! gulp failed"
        gulp ca || err_Check "ERROR!!! gulp ca failed"

        echo -e "\033[32m Execute Headless and Integration Tests" "\033[0m"
        # Spinup the docker containers with docker-ready gulp task
        gulp docker-ready || err_Check "ERROR!!! gulp docker-ready failed"
        # Run e2e.js
        istanbul cover --report cobertura test/integration/e2e.js
}

Parse_Arguments $@