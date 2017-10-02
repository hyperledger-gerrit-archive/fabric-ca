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

	_, err = ctx.GetCallerPermissions() // Check to see what permission caller has in regards to updating server's configuration
	if err != nil {
		return nil, err
	}

	response, err := processConfigUpdate(ctx, req)
	if err != nil {
		if response != nil {
			resp := &api.ConfigResponse{
				Success: response.(string),
			}
			return resp, err
		}
		return nil, err
	}

	resp := &api.ConfigResponse{
		Success: response.(string),
	}
	return resp, nil
}

func processConfigUpdate(ctx *serverRequestContext, req *api.ConfigRequest) (interface{}, error) {
	log.Debugf("Processing request for dynamic configuration update: %+v", req)

	var allSuccess string
	var configErrs []error

	if len(req.Commands) == 0 {
		return nil, newHTTPErr(400, ErrUpdateConfigArgs, "No arguments specified for server configuration update")
	}

	for _, cmd := range req.Commands {
		updateAction := strings.ToLower(cmd.Args[0])
		updateReq := cmd.Args[1]
		updateStr := fmt.Sprintf("%s %s", updateAction, updateReq)
		switch updateAction {
		case "add":
			log.Debugf("Requesting to add '%s' to server's configuration", updateReq)
			result, err := processRequest(updateAction, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				allSuccess = aggregateMessages(updateStr, allSuccess, result)
			}
		case "remove":
			log.Debugf("Requesting to remove '%s' from server's configuration", updateReq)
			result, err := processRequest(updateAction, updateReq, ctx)
			if err != nil {
				configErrs = append(configErrs, addActionToError(updateStr, err))
			}
			if result != "" {
				allSuccess = aggregateMessages(updateStr, allSuccess, result)
			}
		case "modify":
			log.Debugf("Requesting to modify '%s' from server's configuration", updateStr)
			return nil, errors.Errorf("Not Implemented")
		default:
			err := newHTTPErr(400, ErrUpdateConfigArgs, "'%s' is not a supported action", updateStr)
			configErrs = append(configErrs, addActionToError(updateStr, err))
		}
	}

	allErrors := newAllErrs(configErrs)
	if len(allErrors.errs) != 0 {
		if allSuccess != "" {
			return allSuccess, allErrors
		}
		return nil, allErrors
	}

	return allSuccess, nil
}

func processRequest(action, addStr string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Processing '%s' request to '%s'", action, addStr)

	if strings.HasPrefix(addStr, identity) { // Checks to see if request contains 'registry.identities' prefix
		result, err := processIdentity(action, addStr, ctx)
		if err != nil {
			return "", err
		}
		return result, nil
	} else if strings.HasPrefix(addStr, aff) { // Checks to see if request contains 'affiliations' prefix
		result, err := processAffiliation(action, addStr, ctx)
		if err != nil {
			return "", err
		}
		return result, nil
	} else {
		return "", newHTTPErr(400, ErrUpdateConfig, "Invalid configuration request '%s'", addStr)
	}
}

func processIdentity(action, configReq string, ctx *serverRequestContext) (string, error) {
	log.Debugf("Process identity configuration update: '%s'", configReq)
	if !ctx.callerPerm.isRegistrar {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have permission to update identities")
	}

	switch action {
	case "add":
		return addIdentity(configReq, ctx)
	case "remove":
		return removeIdentity(configReq, ctx)
	case "modify":
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

func removeIdentity(removeStr string, ctx *serverRequestContext) (string, error) {
	removeID := strings.TrimPrefix(removeStr, identity+".")
	log.Debugf("Removing identity '%s'", removeID)

	if !ctx.ca.Config.AllowRemove.Identities {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveIdentity, "Server does not allow for user deletions")
	}

	registry := ctx.ca.registry

	userToRemove, err := registry.GetUserInfo(removeID)
	if err != nil {
		return "", err
	}

	if !strings.Contains(ctx.callerPerm.registrarRoles, userToRemove.Type) {
		return "", newAuthErr(ErrUpdateConfigRemoveIdentity, "Caller is not authorized to remove identity")
	}
	log.Debugf("Caller is authorized to remove identities of type '%s'", ctx.callerPerm.registrarRoles)

	err = registry.DeleteUser(removeID)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveIdentity, "Failed to remove identity: ", err)

	}
	_, err = ctx.ca.certDBAccessor.RevokeCertificatesByID(removeID, 0)
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigRemoveIdentity, "Failed to revoke certificates associated with removed identity: ", err)
	}
	log.Debugf("User '%s' successfully removed", removeID)
	return fmt.Sprintf("User '%s' successfully removed", removeID), nil
}

func processAffiliation(action, affiliation string, ctx *serverRequestContext) (string, error) {
	log.Debug("Processing affiliation configuration request")
	if !ctx.callerPerm.isAffiliationMgr {
		return "", newAuthErr(ErrUpdateConfigAuth, "Caller does not have permission to update affiliations")
	}

	affiliation = strings.TrimPrefix(affiliation, fmt.Sprintf("%s.", aff))

	log.Debug("Checking if the caller is authorized to edit affiliation configuration")
	registrar, err := ctx.GetCaller()
	if err != nil {
		return "", newHTTPErr(400, ErrUpdateConfigAff, "Failed to get caller identity: %s", err)
	}
	registrarAff := strings.Join(registrar.GetAffiliationPath(), ".")
	if !strings.HasPrefix(affiliation, registrarAff+".") {
		return "", newAuthErr(ErrUpdateConfigAuth, "Not authorized to edit '%s' affiliation", affiliation)
	}

	switch action {
	case "add":
		return addAffiliation(affiliation, ctx)
	case "remove":
		return removeAffiliation(affiliation, ctx)
	case "modify":
		// TODO
		return "", errors.Errorf("Not Implemented")
	}

	return "", nil
}

func addAffiliation(affiliation string, ctx *serverRequestContext) (string, error) {
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
	if !ctx.ca.Config.AllowRemove.Affiliations {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Modification/Removing of affiliations is not allowed")
	}

	if !ctx.ca.Config.AllowRemove.Identities {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Affiliation can't be modified/removed, because removing of users is not allowed")
	}

	if !ctx.callerPerm.isRegistrar {
		return "", newHTTPErr(401, ErrUpdateConfigRemoveAff, "Affiliation can't be modified/removed, caller does not have permission to update identities")
	}

	log.Debugf("Removing affiliation '%s' and any affiliations below", affiliation)

	removeAff := affiliation + "%"
	query := "DELETE FROM affiliations WHERE name LIKE ?"
	_, err := ctx.ca.db.Exec(ctx.ca.db.Rebind(query), removeAff)
	if err != nil {
		return "", err
	}
	query = "SELECT id FROM users WHERE (affiliation LIKE ?)"
	ids := []string{}
	err = ctx.ca.db.Select(&ids, ctx.ca.db.Rebind(query), removeAff)
	if err != nil {
		return "", err
	}
	log.Debugf("IDs '%s' to removed based on affiliation '%s' removal", ids, removeAff)
	for _, id := range ids {
		err = ctx.ca.registry.DeleteUser(id)
		if err != nil {
			return "", err
		}
		_, err = ctx.ca.certDBAccessor.RevokeCertificatesByID(id, 3)
		if err != nil {
			return "", err
		}
	}

	log.Debugf("Affiliation '%s' successfully removed", removeAff)
	return fmt.Sprintf("Affiliation '%s' successfully removed", removeAff), nil
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
