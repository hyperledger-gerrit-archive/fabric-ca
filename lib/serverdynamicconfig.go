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
	"fmt"
	"strconv"
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

	add action = 1 + iota
	remove
	modify
)

type permissions struct {
	updateAffiliations bool
	updateIdentities   bool
}

// Handle a config request
func configHandler(ctx *serverRequestContext) (interface{}, error) {
	// Read request body
	req := new(api.UpdateConfigRequest)
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

	perm := &permissions{}
	err = callerPermissions(ctx, perm) // Check to see what permission caller has in regards to updating server's configuration
	if err != nil {
		return nil, err
	}

	response, err := processConfigUpdate(ctx, req, perm)
	if err != nil {
		if response != nil {
			resp := &api.UpdateConfigResponse{
				Success: response.(string),
			}
			return resp, err
		}
		return nil, err
	}

	if response != nil {
		resp := &api.UpdateConfigResponse{
			Success: response.(string),
		}
		return resp, nil
	}

	return nil, nil
}

// Check to see what permission caller has in regards to updating server's configuration
func callerPermissions(ctx *serverRequestContext, perm *permissions) error {
	caller, err := ctx.GetCaller()
	if err != nil {
		return err
	}

	log.Debugf("Checking if caller '%s' has permission to update config", caller.GetName())

	hasRegistrar := caller.GetAttribute("hf.Registrar.Roles")
	hasAffiliationMgr := caller.GetAttribute("hf.AffiliationMgr")
	var affiliationMgrVal bool
	if hasAffiliationMgr != "" {
		affiliationMgrVal, err = strconv.ParseBool(hasAffiliationMgr)
		if err != nil {
			return errors.Wrap(err, "Failed to get boolean value of 'hf.AffiliationMgr'")
		}
	}

	if hasRegistrar == "" && !affiliationMgrVal {
		return newAuthErr(ErrUpdateConfigAuth, "Caller does not have authority to dynamically update server's configuration")
	}

	if hasRegistrar != "" {
		log.Debug("Caller has permission to update identities")
		perm.updateIdentities = true
	}

	if affiliationMgrVal {
		log.Debug("Caller has permission to update affiliations")
		perm.updateAffiliations = true
	}

	return nil
}

func processConfigUpdate(ctx *serverRequestContext, req *api.UpdateConfigRequest, perm *permissions) (interface{}, error) {
	log.Debugf("Processing request for dynamic configuration update: %+v", req)

	var allSuccess string

	updateRequest := req.Update

	if len(updateRequest) == 0 {
		return nil, newHTTPErr(400, ErrUpdateConfigArgs, "No arguments specified for server configuration update")
	}

	if len(updateRequest) == 1 && updateRequest[0] == "list" {
		// TODO
		return nil, newHTTPErr(400, ErrUpdateConfig, "Not Implemented")
	}

	if (len(updateRequest) % 2) != 0 {
		return nil, newHTTPErr(400, ErrUpdateConfigArgs, "Invalid number of arguments specified. Note: List can't be used in conjunction with add/remove/modify")
	}

	var configErrs []errorResponse

	// Process the array of configuration updates request
	for i := 0; i < len(updateRequest); i = i + 2 {
		updateAction := updateRequest[i]
		updateReq := updateRequest[i+1]
		updateStr := fmt.Sprintf("%s %s", updateAction, updateReq)
		switch strings.ToLower(updateAction) {
		case "add":
			log.Debugf("Requesting to add '%s' to server's configuration", updateStr)
			result, err := processAdd(updateReq, ctx, perm)
			if err != nil {
				configErrs = append(configErrs, *newUpdateConfigErr(updateStr, err))
			}
			if result != "" {
				allSuccess = aggregateMessages(updateStr, allSuccess, result)
			}
		case "remove":
			log.Debugf("Requesting to remove '%s' from server's configuration", updateStr)
			return nil, errors.Errorf("Not Implemented")
		case "modify":
			log.Debugf("Requesting to modify '%s' from server's configuration", updateStr)
			return nil, errors.Errorf("Not Implemented")

		default:
			err := newHTTPErr(400, ErrUpdateConfigArgs, "'%s' is not a supported action", updateStr)
			configErrs = append(configErrs, *newUpdateConfigErr(updateStr, err))
		}
	}

	allErrors := newAllErrs(configErrs)
	if len(allErrors.errs) != 0 {
		if allSuccess != "" {
			return allSuccess, allErrors
		}
		return nil, allErrors
	}

	if allSuccess != "" {
		return allSuccess, nil
	}

	return nil, nil
}

func processAdd(addStr string, ctx *serverRequestContext, perm *permissions) (string, error) {
	log.Debugf("Processing add request: '%s'", addStr)

	if strings.HasPrefix(addStr, identity) { // Checks to see if request contains 'registry.identities' prefix
		result, err := processIdentity(add, addStr, ctx, perm)
		if err != nil {
			return "", err
		}
		return result, nil
	} else if strings.HasPrefix(addStr, aff) { // Checks to see if request contains 'affiliations' prefix
		result, err := processAffiliation(add, addStr, ctx, perm)
		if err != nil {
			return "", err
		}
		return result, nil
	} else {
		return "", newHTTPErr(400, ErrUpdateConfig, "Unsupported configuration request '%s'", addStr)
	}
}

func processIdentity(configAction action, actionStr string, ctx *serverRequestContext, perm *permissions) (string, error) {
	log.Debugf("Process identity configuration update: '%s'", actionStr)
	if !perm.updateIdentities {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have permission to update identities")
	}

	switch configAction {
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
	req := strings.SplitN(addStr, "=", 2)
	value := req[1]

	identity := new(api.RegistrationRequest)
	err := util.Unmarshal([]byte(value), identity, "identity")
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse JSON string for adding an identity")
	}
	log.Debugf("Adding identity %+v", identity)

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

func processAffiliation(configAction action, affiliation string, ctx *serverRequestContext, perm *permissions) (string, error) {
	log.Debug("Processing affiliation configuration request")
	if !perm.updateAffiliations {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have permission to update affiliations")
	}

	log.Debug("Checking if the caller is authorizated to edit affiliation configuration")
	registrar, err := ctx.GetCaller()
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigAddAff, "Failed to get caller identity: %s", err)
	}
	registrarAff := strings.Join(registrar.GetAffiliationPath(), ".")
	if !strings.Contains(affiliation, registrarAff+".") {
		return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", affiliation)
	}

	switch configAction {
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
	affiliation = strings.TrimPrefix(affiliation, fmt.Sprintf("%s.", aff))

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
			return "", err
		}
		parentAffiliationPath = affiliationPath
		affiliationPath = affiliationPath + "."
	}

	log.Debugf("Affiliation '%s' successfully added", affiliation)
	return fmt.Sprintf("Affiliation '%s' successfully added", affiliation), nil
}

func aggregateMessages(action string, allMsgs string, msg string) string {
	msgtr := fmt.Sprintf("'%s' = %s", action, msg)
	if allMsgs == "" {
		allMsgs = msgtr
	} else {
		allMsgs = allMsgs + fmt.Sprintf("\n%s", msgtr)
	}
	return msgtr
}
