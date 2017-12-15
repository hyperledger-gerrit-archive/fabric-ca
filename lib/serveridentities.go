/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

func newIdentitiesEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "DELETE", "POST", "PUT"},
		Handler:   identitiesHandler,
		Server:    s,
		successRC: 200,
	}
}

func identitiesHandler(ctx *serverRequestContext) (interface{}, error) {
	var err error
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	log.Debugf("Received identity update request from %s", callerID)
	if err != nil {
		return nil, err
	}
	caname, err := ctx.getCAName()
	if err != nil {
		return nil, err
	}
	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, err
	}
	// Process Request
	resp, err := processRequest(ctx, caname, caller)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// processRequest will process the configuration request
func processRequest(ctx *serverRequestContext, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing identity configuration update request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return processGetRequest(ctx, caller, caname)
	case "DELETE":
		return processDeleteRequest(ctx, caname)
	case "POST":
		return processPostRequest(ctx, caname)
	case "PUT":
		return processPutRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

func processGetRequest(ctx *serverRequestContext, caller spi.User, caname string) (interface{}, error) {
	log.Debug("Processing GET request")

	id, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	if id == "" {
		err := getIDs(ctx, caller, caname)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	resp, err := getID(ctx, caller, id, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getIDs(ctx *serverRequestContext, caller spi.User, caname string) error {
	log.Debug("Requesting all identities that the caller is authorized view")
	var err error

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	callerTypes, err := caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		return newHTTPErr(500, ErrGettingUser, "Failed to get registrar roles for caller", err)
	}
	// Getting all identities of appropriate affiliation and type
	rows, err := registry.GetFilteredUsers(callerAff, callerTypes.Value)
	if err != nil {
		return newHTTPErr(500, ErrGettingUser, "Failed to get users by affiliation and type: %s", err)
	}

	// Get the number of identities to return back to client in a chunk based on the environment variable
	// If environment variable not set, default to 100 identities
	numberOfIdentities := os.Getenv("FABRIC_CA_CLIENT_GETIDS")
	var numIdentities int
	if numberOfIdentities == "" {
		numIdentities = 100
	} else {
		numIdentities, err = strconv.Atoi(numberOfIdentities)
		if err != nil {
			return newHTTPErr(500, ErrGettingUser, "Incorrect format specified for number of identities, an integer value is required: %s", err)
		}
	}

	log.Debugf("Number of identities to be delivered in each chunk: %d", numIdentities)

	// Set proper encoding and create flusher that will be used to deliver chunks
	w := ctx.resp
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	// Write the beginning of the JSON object
	w.Write([]byte("{\"identities\":["))

	rowNumber := 0
	for rows.Next() {
		rowNumber++
		var id UserRecord
		err := rows.StructScan(&id)
		if err != nil {
			return newHTTPErr(500, ErrGettingUser, "Failed to get read row: %s", err)
		}

		if rowNumber > 1 {
			w.Write([]byte(","))
		}

		var attrs []api.Attribute
		json.Unmarshal([]byte(id.Attributes), &attrs)

		idInfo := api.IdentityInfo{
			ID:             id.Name,
			Type:           id.Type,
			Affiliation:    id.Affiliation,
			MaxEnrollments: id.MaxEnrollments,
			Attributes:     attrs,
		}

		resp, err := util.Marshal(idInfo, "identities info")
		if err != nil {
			return newHTTPErr(500, ErrGettingUser, "Failed to marshal identity info: %s", err)
		}
		w.Write(resp)

		// If hit the number of identities requested then flush
		if rowNumber%numIdentities == 0 {
			flusher.Flush() // Trigger "chunked" encoding and send a chunk...
		}
	}

	// Close the JSON object
	w.Write([]byte(fmt.Sprintf("], \"caname\":\"%s\"}", caname)))
	flusher.Flush()

	return nil
}

func getID(ctx *serverRequestContext, caller spi.User, id, caname string) (*api.GetIDResponse, error) {
	log.Debugf("Requesting identity '%s'", id)

	registry := ctx.ca.registry
	user, err := registry.GetUser(id, nil)
	if err != nil {
		return nil, getUserError(err)
	}

	err = ctx.CanManageUser(user)
	if err != nil {
		return nil, err
	}

	userInfo := user.(*DBUser).UserInfo
	resp := &api.GetIDResponse{
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(userInfo)

	return resp, nil
}

func processDeleteRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing DELETE request")
	return nil, errors.Errorf("Not Implemented")
}

func processPostRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing POST request")
	return nil, errors.Errorf("Not Implemented")
}

func processPutRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing PUT request")
	return nil, errors.Errorf("Not Implemented")
}

func getIDInfo(user spi.UserInfo) *api.IdentityInfo {
	return &api.IdentityInfo{
		ID:             user.Name,
		Type:           user.Type,
		Affiliation:    user.Affiliation,
		Attributes:     user.Attributes,
		MaxEnrollments: user.MaxEnrollments,
	}
}
