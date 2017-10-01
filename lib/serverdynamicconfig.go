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
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

func newConfigEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: configHandler,
		Server:  s,
	}
}

type action int

const (
	identity = "registry.identities"
	aff      = "affiliations"

	registrarRole      = "hf.Registrar.Roles"
	affiliationMgrRole = "hf.AffiliationMgr"

	add    = "add"
	remove = "remove"
	modify = "modify"
)

// Handle a config request
func configHandler(ctx *serverRequestContext) (interface{}, error) {
	// Read request body
	req := new(api.ConfigRequest)
	err := ctx.ReadBody(req)
	if err != nil {
		return nil, err
	}
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	log.Debugf("Received configuration update request from '%s': %+v", callerID, req)

	response, err := processConfigUpdate(ctx, req)
	if err != nil {
		if response != nil {
			return response, err
		}
		return nil, err
	}

	return response, nil
}

func processConfigUpdate(ctx *serverRequestContext, req *api.ConfigRequest) (interface{}, error) {
	log.Debugf("Processing request for dynamic configuration update: %+v", req)

	cfgResp := &api.ConfigResponse{}
	var configErrs []error

	if len(req.Commands) == 0 {
		return nil, newHTTPErr(400, ErrUpdateConfigArgs, "No arguments specified for server configuration update")
	}

	for _, cmd := range req.Commands {
		updateAction := strings.ToLower(cmd.Args[0])
		updateReq := cmd.Args[1]
		updateStr := fmt.Sprintf("%s", cmd)
		log.Debugf("Requesting to '%s' to server's configuration", updateStr)
		switch updateAction {
		case add:
			result, err := processRequest(add, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				aggregateResponses(updateStr, result, cfgResp)
			}
		case remove:
			return nil, errors.Errorf("Not Implemented")
		case modify:
			return nil, errors.Errorf("Not Implemented")
		default:
			err := newHTTPErr(400, ErrUpdateConfigArgs, "'%s' is not a supported action", updateStr)
			configErrs = append(configErrs, addActionToError(updateStr, err))
		}
	}

	if len(configErrs) == 1 {
		if len(cfgResp.Responses) != 0 {
			return cfgResp, configErrs[0]
		}
		return nil, configErrs[0]
	}

	if len(configErrs) > 1 {
		allErrors := newAllErrs(configErrs)
		if len(cfgResp.Responses) != 0 {
			return cfgResp, allErrors
		}
		return nil, allErrors
	}

	return cfgResp, nil
}

func processRequest(action, actionStr string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Processing '%s' request", action)

	if strings.HasPrefix(actionStr, identity) { // Checks to see if request contains 'registry.identities' prefix
		result, err := processIdentity(action, actionStr, ctx)
		if err != nil {
			return "", err
		}
		return result, nil
	} else if strings.HasPrefix(actionStr, aff) { // Checks to see if request contains 'affiliations' prefix
		result, err := processAffiliation(action, actionStr, ctx)
		if err != nil {
			return "", err
		}
		return result, nil
	} else {
		return "", newHTTPErr(400, ErrUpdateConfig, "Invalid configuration request '%s'", actionStr)
	}
}

func processIdentity(action, actionStr string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Process identity configuration update")
	_, isRegistrar, err := ctx.IsRegistrar()
	if err != nil {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller is unable to edit identities: %s", err)
	}
	if !isRegistrar {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have the attribute '%s', unable to edit identities", registrarRole)
	}

	switch action {
	case add:
		return addIdentity(actionStr, ctx)
	case remove:
		// TODO
		return "", errors.Errorf("Not Implemented")
	case modify:
		// TODO
		return "", errors.Errorf("Not Implemented")
	}

	return "", nil
}

func addIdentity(addStr string, ctx *serverRequestContext) (string, error) {
	if !strings.Contains(addStr, "=") {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "Incorrect format for adding identity request, missing '=' in request")
	}
	req := strings.SplitN(addStr, "=", 2)
	value := req[1]

	identity := new(api.RegistrationRequest)
	err := util.Unmarshal([]byte(value), identity, "identity")
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse JSON string for adding an identity")
	}
	log.Debugf("Adding identity %+v", identity)
	if identity.Name == "" {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "Missing 'ID' in request to add a new intentity")
	}

	caller, err := ctx.GetCaller()
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "Failed to get caller identity: %s", err)
	}
	callerID := caller.GetName()

	secret, err := registerUser(identity, callerID, ctx.ca, ctx)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "Failed to add identity: %s", err)

	}

	id := identity.Name
	log.Debugf("Identity '%s' successfully added", id)
	return fmt.Sprintf("ID: %s, Password: %s", id, secret), nil
}

func processAffiliation(action, affiliation string, ctx *serverRequestContext) (string, error) {
	log.Debug("Processing affiliation configuration request")
	hasRole, err := ctx.HasRole(affiliationMgrRole)
	if err != nil {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller is unable to edit affiliations: %s", err)
	}
	if !hasRole {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have attribute '%s', unable to edit affiliations", affiliationMgrRole)
	}

	affiliation = strings.TrimPrefix(affiliation, fmt.Sprintf("%s.", aff))

	log.Debug("Checking if the caller is authorized to edit affiliation configuration")
	validAffiliation, err := ctx.ContainsAffiliation(affiliation)
	if err != nil {
		return "", newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to edit affiliation: %s", err)
	}
	if !validAffiliation {
		return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", affiliation)
	}

	switch action {
	case add:
		return addAffiliation(affiliation, ctx)
	case remove:
		// TODO
		return "", errors.Errorf("Not Implemented")
	case modify:
		// TODO
		return "", errors.Errorf("Not Implemented")
	}

	return "", nil
}

func addAffiliation(affiliation string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Adding affiliations '%s'", affiliation)
	registry := ctx.ca.registry

	_, err := registry.GetAffiliation(affiliation)
	if err == nil {
		return "", newHTTPErr(400, ErrUpdateConfigAddAff, "Affiliation already exists")
	}

	addAffiliations := strings.Split(affiliation, ".")

	var affiliationPath string
	var parentAffiliationPath string

	for _, addAff := range addAffiliations {
		affiliationPath = affiliationPath + addAff
		err := registry.InsertAffiliation(affiliationPath, parentAffiliationPath)
		if err != nil {
			return "", newHTTPErr(400, ErrUpdateConfigAddAff, "Failed to add affiliations '%s': %s", affiliation, err)
		}
		parentAffiliationPath = affiliationPath
		affiliationPath = affiliationPath + "."
	}

	log.Debugf("Affiliation '%s' successfully added", affiliation)
	return fmt.Sprintf("Affiliation '%s' successfully added", affiliation), nil
}

func aggregateResponses(request, result string, cfgResp *api.ConfigResponse) {
	cfgResp.Responses = append(cfgResp.Responses, api.CommandResponse{Request: request, Result: result})
}

func addActionToError(action string, err error) error {
	httpError := getHTTPErr(err)
	if httpError == nil {
		return errors.Errorf("'%s' = %s", action, err.Error())
	}

	httpError.rmsg = fmt.Sprintf("'%s' = %s", action, httpError.rmsg)
	httpError.lmsg = fmt.Sprintf("'%s' = %s", action, httpError.lmsg)
	return httpError
}
