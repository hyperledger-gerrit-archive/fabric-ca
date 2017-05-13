/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	cerr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	enrollmentIDHdrName = "__eid__"
	caHdrName           = "__caname__"
)

// AuthType is the enum for authentication types: basic and token
type authType int

const (
	noAuth authType = iota
	basic           // basic = 1
	token           // token = 2
)

// Fabric CA authentication handler
type fcaAuthHandler struct {
	server   *Server
	authType authType
	next     http.Handler
}

type caname struct {
	CAName string
}

var authError = cerr.NewBadRequest(errors.New("Authorization failure"))

func (ah *fcaAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := ah.serveHTTP(w, r)
	if err != nil {
		api.HandleError(w, err)
	} else {
		ah.next.ServeHTTP(w, r)
	}
}

// Handle performs authentication
func (ah *fcaAuthHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	log.Debugf("Received request\n%s", util.HTTPRequestToString(r))

	// read body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("Failed to read body: %s", err)
		return authError
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	var req caname

	if len(body) != 0 {
		err = json.Unmarshal(body, &req)
		if err != nil {
			return err
		}
	}

	if req.CAName == "" {
		log.Debugf("Directing traffic to default CA")
	} else {
		log.Debugf("Directing traffic to CA %s", req.CAName)
	}

	// Look up CA to see if CA exist by that name
	if _, ok := ah.server.caMap[req.CAName]; !ok {
		return fmt.Errorf("CA '%s' does not exist", req.CAName)
	}

	r.Header.Set(caHdrName, req.CAName)

	ctx := newServerRequestContext(r, w, ah.server)
	var id string
	switch ah.authType {
	case noAuth:
		// No authentication required
		return nil
	case basic:
		id, err = ctx.BasicAuthentication()
		if err != nil {
			return err
		}
		log.Debugf("Successful basic authentication of '%s'", id)
		r.Header.Set(enrollmentIDHdrName, id)
		return nil
	case token:
		id, err = ctx.TokenAuthentication()
		if err != nil {
			return err
		}
		log.Debugf("Successful token authentication of '%s'", id)
		r.Header.Set(enrollmentIDHdrName, id)
		return nil
	default: // control should never reach here
		log.Errorf("No handler for the authentication type: %d", ah.authType)
		return authError
	}

}
