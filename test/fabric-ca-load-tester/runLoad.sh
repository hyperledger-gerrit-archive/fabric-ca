#!/bin/bash
pushd $GOPATH/src/github.com/hyperledger/fabric-ca/test/fabric-ca-load-tester
if [ "$1" == "-B" ]; then
  echo "Building fabric-ca-load-tester..."
  if [ "$(uname)" == "Darwin" ]; then
    # On MacOS Sierra use -ldflags -s flags to work around "Killed: 9" error
    go build -o fabric-ca-load-tester -ldflags -s main.go testClient.go
  else
    go build -o fabric-ca-load-tester main.go testClient.go
  fi
fi
echo "Running load"
./fabric-ca-load-tester -config testConfig.json
popd
