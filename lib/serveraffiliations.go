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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

func newAffiliationsEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "DELETE", "POST", "PUT"},
		Handler:   affiliationsHandler,
		Server:    s,
		successRC: 200,
	}
}

func affiliationsHandler(ctx *serverRequestContext) (interface{}, error) {
	var err error
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	log.Debugf("Received affiliation update request from %s", callerID)
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
	resp, err := processAffiliationRequest(ctx, caname, caller)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// processRequest will process the configuration request
func processAffiliationRequest(ctx *serverRequestContext, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing affiliation configuration update request")

	ctx.endpoint.Streaming = false
	method := ctx.req.Method
	switch method {
	case "GET":
		return processAffiliationGetRequest(ctx, caller, caname)
	case "DELETE":
		return processAffiliationDeleteRequest(ctx, caname)
	case "POST":
		return processAffiliationPostRequest(ctx, caname)
	case "PUT":
		return processAffiliationPutRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

func processAffiliationGetRequest(ctx *serverRequestContext, caller spi.User, caname string) (interface{}, error) {
	log.Debug("Processing GET request")

	affiliation, err := ctx.GetVar("affiliation")
	if err != nil {
		return nil, err
	}

	if affiliation == "" {
		err := getAffiliations(ctx, caller, caname)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	resp, err := getAffiliation(ctx, caller, affiliation, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getAffiliations(ctx *serverRequestContext, caller spi.User, caname string) error {
	log.Debug("Requesting all affiliations that the caller is authorized view")
	var err error

	w := ctx.resp
	flusher, _ := w.(http.Flusher)
	ctx.endpoint.Streaming = true
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("Transfer-Encoding", "chunked")

	// Write the beginning of the JSON object
	w.Write([]byte("{\"result\":{\"affiliations\":["))
	flusher.Flush() // Trigger "chunked" encoding and send a chunk...

	err = ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return err
	}

	// Get the number of identities to return back to client in a chunk based on the environment variable
	// If environment variable not set, default to 100 identities
	numberOfAffiliations := os.Getenv("FABRIC_CA_SERVER_MAX_AFFILIATIONS_PER_CHUNK")
	var numAffiliations int
	if numberOfAffiliations == "" {
		numAffiliations = 100
	} else {
		numAffiliations, err = strconv.Atoi(numberOfAffiliations)
		if err != nil {
			return newHTTPErr(500, ErrGettingAffiliation, "Incorrect format specified for environment variable 'FABRIC_CA_SERVER_MAX_AFFILIATIONS_PER_CHUNK', an integer value is required: %s", err)
		}
	}

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	rows, err := registry.GetAllAffiliations(callerAff)
	if err != nil {
		return newHTTPErr(500, ErrGettingUser, "Failed to get affiliation: %s", err)
	}

	rowNumber := 0
	for rows.Next() {
		rowNumber++
		var aff AffiliationRecord
		err := rows.StructScan(&aff)
		if err != nil {
			return newHTTPErr(500, ErrGettingAffiliation, "Failed to get read row: %s", err)
		}

		if rowNumber > 1 {
			w.Write([]byte(","))
		}

		affInfo := api.AffiliationInfo{
			Name: aff.Name,
		}

		resp, err := util.Marshal(affInfo, "identities info")
		if err != nil {
			return newHTTPErr(500, ErrGettingUser, "Failed to marshal identity info: %s", err)
		}
		w.Write(resp)

		// If hit the number of identities requested then flush
		if rowNumber%numAffiliations == 0 {
			flusher.Flush() // Trigger "chunked" encoding and send a chunk...
		}
	}

	// Close the JSON object
	w.Write([]byte(fmt.Sprintf("], \"caname\":\"%s\"}", caname)))
	flusher.Flush()

	return nil
}

func getAffiliation(ctx *serverRequestContext, caller spi.User, requestedAffiliation, caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Requesting affiliation '%s'", requestedAffiliation)

	err := ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return nil, err
	}

	registry := ctx.ca.registry
	err = ctx.ContainsAffiliation(requestedAffiliation)
	if err != nil {
		return nil, err
	}
	affiliation, err := registry.GetAffiliation(requestedAffiliation)
	if err != nil {
		return nil, err
	}

	resp := &api.AffiliationResponse{
		CAName: caname,
	}
	resp.Name = affiliation.GetName()

	return resp, nil
}

func processAffiliationDeleteRequest(ctx *serverRequestContext, caname string) (*api.RemoveAffiliationResponse, error) {
	log.Debug("Processing DELETE request")

	err := ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return nil, err
	}

	if !ctx.ca.Config.Cfg.Affiliations.AllowRemove {
		return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Affiliation removal is disabled")
	}

	removeAffiliation, err := ctx.GetVar("affiliation")
	if err != nil {
		return nil, err
	}
	log.Debugf("Request to remove affiliation '%s'", removeAffiliation)

	callerAff := GetUserAffiliation(ctx.caller)
	if callerAff == removeAffiliation {
		return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Can't remove affiliation '%s' because the caller is associated with this affiliation", removeAffiliation)
	}

	err = ctx.ContainsAffiliation(removeAffiliation)
	if err != nil {
		return nil, err
	}

	force, err := ctx.GetBoolQueryParm("force")
	if err != nil {
		return nil, err
	}

	identityRemoval := ctx.ca.Config.Cfg.Identities.AllowRemove
	result, err := ctx.ca.registry.DeleteAffiliation(removeAffiliation, force, identityRemoval)
	if err != nil {
		return nil, err
	}

	affInfo := []api.AffiliationInfo{}
	for _, affRemoved := range result.Affiliations {
		affInfo = append(affInfo, api.AffiliationInfo{
			Name: affRemoved.GetName(),
		})
	}
	idInfo := []api.IdentityInfo{}
	for _, idRemoved := range result.Identities {
		id := getIDInfo(idRemoved)
		idInfo = append(idInfo, *id)
	}

	resp := &api.RemoveAffiliationResponse{
		Affiliations: affInfo,
		Identities:   idInfo,
		CAName:       caname,
	}

	return resp, nil
}

func processAffiliationPostRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing POST request")

	ctx.endpoint.successRC = 201

	err := ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return nil, err
	}

	var req api.AddAffiliationRequestNet
	err = ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	addAffiliation := req.Info.Name
	log.Debugf("Request to add affiliation '%s'", addAffiliation)

	registry := ctx.ca.registry
	_, err = registry.GetAffiliation(addAffiliation)
	if err == nil {
		return nil, newHTTPErr(400, ErrUpdateConfigAddAff, "Affiliation already exists")
	}

	err = ctx.ContainsAffiliation(addAffiliation)
	if err != nil {
		return nil, err
	}

	force, err := ctx.GetBoolQueryParm("force")
	if err != nil {
		return nil, err
	}

	addAffiliationSlice := strings.Split(addAffiliation, ".")
	var parentAffiliationPath string

	affLevel := ctx.ca.server.levels.Affiliation
	if force {
		// With force option, add any parent affiliations that don't exist
		var affiliationPath string
		for _, addAff := range addAffiliationSlice {
			affiliationPath = affiliationPath + addAff
			err := registry.InsertAffiliation(affiliationPath, parentAffiliationPath, affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliations '%s': %s", addAffiliation, err)
			}
			parentAffiliationPath = affiliationPath
			affiliationPath = affiliationPath + "."
		}
	} else {
		// If the affiliation being added has a parent affiliation, check to make sure that parent affiliation exists
		if len(addAffiliationSlice) > 1 {
			parentAffiliationPath = strings.Join(addAffiliationSlice[:len(addAffiliationSlice)-1], ".") // Get the path up until the last affiliation
			_, err = registry.GetAffiliation(parentAffiliationPath)
			if err != nil {
				httpErr := getHTTPErr(err)
				if httpErr.rcode == 400 {
					return nil, newHTTPErr(400, ErrUpdateConfigAddAff, "Parent affiliation does not exist, 'force' option required on request to add affiliation")
				}
				return nil, err
			}
			err := registry.InsertAffiliation(addAffiliation, parentAffiliationPath, affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliation '%s': %s", addAffiliation, err)
			}
		} else {
			err := registry.InsertAffiliation(addAffiliation, "", affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliation '%s': %s", addAffiliation, err)
			}
		}

	}

	resp := &api.AffiliationResponse{
		CAName: caname,
	}
	resp.Name = addAffiliation

	return resp, nil
}

func processAffiliationPutRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing PUT request")

	// TODO

	return nil, errors.New("Not Implemented")
}
