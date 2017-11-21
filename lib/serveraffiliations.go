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
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
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
	err = ctx.HasRole(attrAffiliationMgr)
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
		resp, err := getAffiliations(ctx, caller, caname)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	resp, err := getAffiliation(ctx, caller, affiliation, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getAffiliations(ctx *serverRequestContext, caller spi.User, caname string) (*api.GetAllAffiliationsResponse, error) {
	log.Debug("Requesting all affiliations that the caller is authorized view")
	var err error

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	affiliations, err := registry.GetAllAffiliations(callerAff)
	if err != nil {
		return nil, newHTTPErr(500, ErrGettingAffiliation, "Failed to get affiliation: %s", err)
	}
	affiliationsInfo := []api.AffiliationInfo{}

	// Get affiliation information
	for _, affiliation := range affiliations {
		affiliationsInfo = append(affiliationsInfo, api.AffiliationInfo{
			Name: affiliation.GetName(),
		})
	}

	resp := &api.GetAllAffiliationsResponse{
		Affiliations: affiliationsInfo,
		CAName:       caname,
	}

	return resp, nil
}

func getAffiliation(ctx *serverRequestContext, caller spi.User, requestedAffiliation, caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Requesting affiliation '%s'", requestedAffiliation)

	registry := ctx.ca.registry
	err := ctx.ContainsAffiliation(requestedAffiliation)
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
	var req api.AddAffiliationRequestNet
	err := ctx.ReadBody(&req)
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

	if force {
		// With force option, add any parent affiliations that don't exist
		var affiliationPath string
		for _, addAff := range addAffiliationSlice {
			affiliationPath = affiliationPath + addAff
			err := registry.InsertAffiliation(affiliationPath, parentAffiliationPath)
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
			err := registry.InsertAffiliation(addAffiliation, parentAffiliationPath)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliation '%s': %s", addAffiliation, err)
			}
		} else {
			err := registry.InsertAffiliation(addAffiliation, "")
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
