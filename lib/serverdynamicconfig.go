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

	add    = "add"
	remove = "remove"
	modify = "modify"

	registrarRole      = "hf.Registrar.Roles"
	affiliationMgrRole = "hf.AffiliationMgr"
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

	allResponses := &api.ConfigResponse{}
	allResponses.Responses = make(map[string]string)
	var configErrs []error

	if len(req.Commands) == 0 {
		return nil, newHTTPErr(400, ErrUpdateConfigArgs, "No arguments specified for server configuration update")
	}

	for _, cmd := range req.Commands {
		updateAction := strings.ToLower(cmd.Args[0])
		updateReq := cmd.Args[1]
		updateStr := fmt.Sprintf("%s", cmd)
		log.Debugf("Requesting to add '%s' to server's configuration", updateStr)
		switch updateAction {
		case add:
			result, err := processRequest(updateAction, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				allResponses.Responses[updateStr] = result
			}
		case remove:
			result, err := processRequest(updateAction, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				allResponses.Responses[updateStr] = result
			}
		case modify:
			result, err := processRequest(updateAction, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				allResponses.Responses[updateStr] = result
			}
		default:
			err := newHTTPErr(400, ErrUpdateConfigArgs, "'%s' is not a supported action", updateStr)
			configErrs = append(configErrs, addActionToError(updateStr, err))
		}
	}

	if len(configErrs) == 1 {
		if len(allResponses.Responses) != 0 {
			return allResponses, configErrs[0]
		}
		return nil, configErrs[0]
	}

	if len(configErrs) > 1 {
		allErrors := newAllErrs(configErrs)
		if len(allResponses.Responses) != 0 {
			return allResponses, allErrors
		}
		return nil, allErrors
	}

	return allResponses, nil
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

func processIdentity(action, configReq string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Process identity configuration update")
	registrarRoles, isRegistrar, err := ctx.IsRegistrar()
	if err != nil {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller is unable to edit identities: %s", err)
	}
	if !isRegistrar {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have the attribute '%s', unable to edit identities", registrarRole)
	}

	switch action {
	case add:
		return addIdentity(configReq, ctx)
	case remove:
		return removeIdentity(configReq, registrarRoles, ctx)
	case modify:
		return modifyIdentity(configReq, ctx)
	}

	return "", nil
}

func addIdentity(addStr string, ctx *serverRequestContext) (string, error) {
	if !strings.Contains(addStr, "=") {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "Incorrect format for adding identity, missing equals sign")
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

	if identity.Name == "" {
		return "", newHTTPErr(400, ErrUpdateConfigAddIdentity, "ID is required to add a new identity")
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

func removeIdentity(removeStr string, registrarRoles string, ctx *serverRequestContext) (string, error) {
	removeID := strings.TrimPrefix(removeStr, identity+".")
	log.Debugf("Removing identity '%s'", removeID)

	if !ctx.ca.Config.Options.Identities.AllowRemove {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveIdentity, "Server does not allow for removing of identities")
	}

	registry := ctx.ca.registry

	userToRemove, err := registry.GetUserInfo(removeID)
	if err != nil {
		return "", err
	}

	if !strings.Contains(registrarRoles, userToRemove.Type) {
		return "", newAuthErr(ErrUpdateConfigRemoveIdentity, "Caller is not authorized to remove identity")
	}
	log.Debugf("Caller is authorized to remove identities of type '%s'", registrarRoles)

	registry.DeleteUser(removeID)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveIdentity, "Failed to remove identity: ", err)
	}

	log.Debugf("Identity '%s' successfully removed", removeID)
	return fmt.Sprintf("Identity '%s' successfully removed", removeID), nil
}

func modifyIdentity(modifyStr string, ctx *serverRequestContext) (string, error) {
	modify := strings.TrimPrefix(modifyStr, identity+".") // Remove the 'identities.registry.' prefix
	modifyRequest := strings.SplitN(modify, ".", 2)       // Split the remaining string to get the identity name and property to update
	id := modifyRequest[0]                                // ID to be modified
	action := modifyRequest[1]

	modifyRequest = strings.Split(action, "=") // Split to get the property to updated and the new configuration
	update := strings.ToLower(modifyRequest[0])
	newConfig := modifyRequest[1]
	log.Debugf("Modifying identity '%s' to update the value of '%s' to '%s'", id, update, newConfig)

	registry := ctx.ca.registry
	if update == "affiliation" {
		log.Debug("Checking if caller is authorized to change affiliation to '%s'", newConfig)
		validAffiliation, err := ctx.ContainsAffiliation(newConfig)
		if err != nil {
			return "", err
		}
		if !validAffiliation {
			return "", newHTTPErr(400, ErrUpdateConfigModifyingIdentity, "Registrar does not have authority to modify identity to use '%s' affiliation", newConfig)
		}
		aff, _ := registry.GetAffiliation(newConfig)
		if aff == nil {
			return "", newHTTPErr(400, ErrUpdateConfigModifyingIdentity, "Affiliation '%s' is not supported", newConfig)
		}
	}

	if update == "type" {
		log.Debug("Checking if caller is authorized to change type to '%s'", newConfig)
		canRegister, err := ctx.CanRegisterRole(newConfig)
		if err != nil {
			return "", err
		}
		if !canRegister {
			return "", errors.Errorf("Identity '%s' may not register type '%s'", ctx.caller.GetName(), newConfig)
		}
	}

	err := registry.ModifyIdentity(id, update, newConfig)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigModifyingIdentity, "Failed to update identity: %s", err)
	}

	log.Debugf("User '%s' successfully modified", id)
	return fmt.Sprintf("User '%s' successfully modified", id), nil
}

func processAffiliation(action string, affiliation string, ctx *serverRequestContext) (string, error) {
	log.Debug("Processing affiliation configuration request")
	hasRole, err := ctx.HasRole(affiliationMgrRole)
	if err != nil {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller is unable to edit affiliations: %s", err)
	}
	if !hasRole {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have attribute '%s', unable to edit affiliations", affiliationMgrRole)
	}

	affiliation = strings.TrimPrefix(affiliation, fmt.Sprintf("%s.", aff))

	if action == add || action == remove {
		log.Debugf("Checking if the caller is authorized to edit affiliation '%s'", affiliation)
		validAffiliation, err := ctx.ContainsAffiliation(affiliation)
		if err != nil {
			return "", newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to edit affiliation: %s", err)
		}
		if !validAffiliation {
			return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", affiliation)
		}
	}

	switch action {
	case add:
		return addAffiliation(affiliation, ctx)
	case remove:
		return removeAffiliation(affiliation, ctx)
	case modify:
		return modifyAffiliation(affiliation, ctx)
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

func removeAffiliation(affiliation string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Removing affiliation '%s' and any affiliations below", affiliation)

	if !ctx.ca.Config.Options.Affiliations.AllowRemove {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Modification/Removing of affiliations is not allowed")
	}

	forceRemoveIdentities := ctx.ca.Config.Options.Affiliations.ForceRemoveIdentities

	_, isRegistar, err := ctx.IsRegistrar()
	if err != nil {
		return "", err
	}
	if !isRegistar {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Affiliation can't be modified/removed, caller does not have permission to update identities")
	}

	callerAff := strings.Join(ctx.caller.GetAffiliationPath(), ".")
	if callerAff == affiliation {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Can't remove affiliation '%s' that the caller is also a part of", affiliation)
	}

	if forceRemoveIdentities {
		if !ctx.ca.Config.Options.Identities.AllowRemove {
			return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Affiliation can't be modified/removed, because removing of identities is not allowed by server")
		}
	}

	// Affiliation can still be removed, even if removing of identities is not allwed by server, as long as the affiliation being removed
	// does not have any identities associated with it
	err = ctx.ca.registry.DeleteAffiliation(affiliation, forceRemoveIdentities)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveAff, "Failed to remove affiliation: ", err)
	}

	log.Debugf("Affiliation '%s' successfully removed", affiliation)
	return fmt.Sprintf("Affiliation '%s' successfully removed", affiliation), nil
}

func modifyAffiliation(affiliation string, ctx *serverRequestContext) (string, error) {
	affs := strings.Split(affiliation, "=")
	oldAff := affs[0]
	newAff := affs[1]

	log.Debugf("Modify affiliation '%s' to '%s'", oldAff, newAff)

	validAffiliation, err := ctx.ContainsAffiliation(oldAff)
	if err != nil {
		return "", newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to edit affiliation: %s", err)
	}
	if !validAffiliation {
		return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", oldAff)
	}

	validAffiliation, err = ctx.ContainsAffiliation(newAff)
	if err != nil {
		return "", newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to edit affiliation: %s", err)
	}
	if !validAffiliation {
		return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", newAff)
	}

	registry := ctx.ca.registry
	err = registry.ModifyAffiliation(oldAff, newAff)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigAddAff, "Failed to modify affiliation from '%s' to '%s: %s'", oldAff, newAff, err)
	}

	log.Debugf("Affiliation '%s' successfully modified to '%s'", oldAff, newAff)
	return fmt.Sprintf("Affiliation '%s' successfully modified to '%s'", oldAff, newAff), nil
}

func aggregateMessages(action string, allMsgs string, msg string) string {
	msgStr := fmt.Sprintf("'%s' = %s", action, msg)
	if allMsgs == "" {
		allMsgs = msgStr
	} else {
		allMsgs = allMsgs + fmt.Sprintf("\n%s", msgStr)
	}
	return msgStr
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
