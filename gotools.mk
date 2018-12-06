# Copyright IBM Corp All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

GOTOOLS = dep
GOTOOLS_BINDIR ?= $(GOPATH)/bin

# Lock to a versioned dep
gotool.dep: DEP_VERSION ?= "v0.5.0"
gotool.dep:
	@GOPATH=$(abspath $(GOPATH)) go get -d -u github.com/golang/dep
	@git -C $(abspath $(GOPATH))/src/github.com/golang/dep checkout -q $(DEP_VERSION)
	@echo "Building github.com/golang/dep $(DEP_VERSION) -> dep"
	@GOPATH=$(abspath $(GOPATH)) GOBIN=$(abspath $(GOTOOLS_BINDIR)) go install -ldflags="-X main.version=$(DEP_VERSION) -X main.buildDate=$$(date '+%Y-%m-%d')" github.com/golang/dep/cmd/dep
	@git -C $(abspath $(GOPATH))/src/github.com/golang/dep checkout -q master
