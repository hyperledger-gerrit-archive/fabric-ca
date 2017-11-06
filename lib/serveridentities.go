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
	gmux "github.com/gorilla/mux"
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

	vars := gmux.Vars(ctx.req)
	id := vars["id"]

	if id == "" {
		resp, err := getAllIDs(ctx, caller, caname)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	resp, err := getID(ctx, caller, id, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getAllIDs(ctx *serverRequestContext, caller spi.User, caname string) (*GetAllIDsResponse, error) {
	log.Debug("Requesting all identities that the caller is authorized view")
	var err error

	registry := ctx.ca.registry
	callerAff := strings.Join(caller.GetAffiliationPath(), ".")

	// Getting all identities that have the appropriate affiliation
	ids, err := registry.GetAllIDsPerAffiliation(callerAff)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingUser, "Failed to get user: %s", err)
	}
	idsInfo := []IdentityInfo{}

	// Checking if all the identities with the appropriate affiliation have the appropriate type as well
	for _, user := range ids {
		userType := user.GetType()
		canAct, err := ctx.CanActOnType(userType)
		if err != nil {
			return nil, newHTTPErr(400, ErrCallerNotAffiliated, "Failed to verify if user can act on type '%s': %s", userType, err)
		}
		if canAct {
			log.Debugf("Caller is authorized to get user '%s'", user.GetName())
			userInfo := user.(*DBUser).UserInfo
			idsInfo = append(idsInfo, *getIDInfo(userInfo))
		}
	}

	resp := &GetAllIDsResponse{
		Identities: idsInfo,
		CAName:     caname,
	}

	return resp, nil
}

func getID(ctx *serverRequestContext, caller spi.User, id, caname string) (*GetIDResponse, error) {
	log.Debugf("Requesting identity '%s'", id)

	registry := ctx.ca.registry
	user, err := registry.GetUser(id, nil)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingUser, "Failed to get user: %s", err)
	}

	userAff := strings.Join(user.GetAffiliationPath(), ".")
	validAffiliation, err := ctx.ContainsAffiliation(userAff)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to get ID: %s", err)
	}
	if !validAffiliation {
		return nil, newAuthErr(ErrCallerNotAffiliated, "Caller does not have authority to act on affiliation '%s'", userAff)
	}

	userType := user.GetType()
	canAct, err := ctx.CanActOnType(userType)
	if err != nil {
		return nil, newHTTPErr(400, ErrCallerNotAffiliated, "Failed to verify if user can act on type '%s': %s", userType, err)
	}
	if !canAct {
		return nil, newAuthErr(ErrCallerNotAffiliated, "Registrar does not have authority to act on type '%s'", userType)
	}

	userInfo := user.(*DBUser).UserInfo
	resp := &GetIDResponse{
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(userInfo)

	return resp, nil
}

func processDeleteRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing DELETE request")
	if !ctx.ca.Config.Cfg.Identities.AllowRemove {
		return "", newHTTPErr(400, ErrRemoveIdentity, "Identity removal is disabled")
	}

	vars := gmux.Vars(ctx.req)
	removeID := vars["id"]

	if removeID == "" {
		return nil, errors.Errorf("No ID name specified to remove")
	}

	log.Debugf("Removing identity '%s'", removeID)

	registry := ctx.ca.registry

	userToRemove, err := registry.GetUser(removeID, nil)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingUser, "Failed to get user: %s", err)
	}

	err = performIdentityAuthCheck(userToRemove, ctx)
	if err != nil {
		return nil, errors.WithMessage(err, "Caller is not authorized to remove identity")
	}

	registry.DeleteUser(removeID)
	if err != nil {
		return nil, newHTTPErr(400, ErrRemoveIdentity, "Failed to remove identity: ", err)
	}

	userInfo := userToRemove.(*DBUser).UserInfo
	resp := &IdentityResponse{
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(userInfo)

	log.Debugf("Identity '%s' successfully removed", removeID)
	return resp, nil
}

func processPostRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing POST request")

	ctx.endpoint.successRC = 201
	var req api.AddIdentityRequest
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	addReq := req.RegistrationRequest
	log.Debugf("Adding identity: %+v", util.StructToString(&addReq))
	if req.Name == "" {
		return nil, newHTTPErr(400, ErrAddIdentity, "Missing 'ID' in request to add a new intentity")
	}

	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, newHTTPErr(400, ErrAddIdentity, "Failed to get caller identity: %s", err)
	}
	callerID := caller.GetName()

	pass, err := registerUser(&addReq, callerID, ctx.ca, ctx)
	if err != nil {
		return nil, newHTTPErr(400, ErrAddIdentity, "Failed to add identity: %s", err)

	}

	user, err := ctx.ca.registry.GetUser(req.Name, nil)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingUser, "Failed to get user: %s", err)
	}
	userInfo := user.(*DBUser).UserInfo

	resp := IdentityResponse{
		Secret: pass,
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(userInfo)

	log.Debugf("Identity successfully added")
	return resp, nil
}

func processPutRequest(ctx *serverRequestContext, caname string) (interface{}, error) {
	log.Debug("Processing PUT request")

	vars := gmux.Vars(ctx.req)
	modifyID := vars["id"]

	if modifyID == "" {
		return nil, errors.Errorf("No ID name specified to remove")
	}

	log.Debugf("Modifying identity '%s'", modifyID)

	registry := ctx.ca.registry

	userToModify, err := registry.GetUser(modifyID, nil)
	if err != nil {
		return nil, newHTTPErr(400, ErrGettingUser, "Failed to get user: %s", err)
	}

	err = performIdentityAuthCheck(userToModify, ctx)
	if err != nil {
		return nil, errors.WithMessage(err, "Caller is not authorized to remove identity")
	}

	var req api.ModifyIdentityRequest
	err = ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	if req.Affiliation != "" {
		newAff := req.Affiliation
		log.Debugf("Checking if caller is authorized to change affiliation to '%s'")
		validAffiliation, err := ctx.ContainsAffiliation(newAff)
		if err != nil {
			return "", err
		}
		if !validAffiliation {
			return "", newAuthErr(ErrModifyingIdentity, "Registrar does not have authority to modify identity to use '%s' affiliation", newAff)
		}
		if newAff != "." { // Only need to check if not requesting root affiliation
			aff, _ := registry.GetAffiliation(newAff)
			if aff == nil {
				return "", newHTTPErr(400, ErrModifyingIdentity, "Affiliation '%s' is not supported", newAff)
			}
		}
	}

	if req.Type != "" {
		newType := req.Type
		log.Debugf("Checking if caller is authorized to change type to '%s'", newType)
		canRegister, err := ctx.CanActOnType(newType)
		if err != nil {
			return "", err
		}
		if !canRegister {
			return "", newAuthErr(ErrModifyingIdentity, "Caller '%s' may not register type '%s'", ctx.caller.GetName(), newType)
		}
	}

	if len(req.Attributes) != 0 {
		newAttrs := req.Attributes
		log.Debugf("Checking if caller is authorized to change attributes to '%s'", newAttrs)
		err := ctx.canRegisterRequestedAttributes(newAttrs)
		if err != nil {
			return "", err
		}
	}
	modReq, setPass := getModifyReq(userToModify, req)
	log.Debugf("Modify Request: %+v", util.StructToString(modReq))

	err = registry.UpdateUser(*modReq, setPass)
	if err != nil {
		return nil, err
	}

	resp := IdentityResponse{
		Secret: modReq.Pass,
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(*modReq)

	log.Debugf("Identity successfully modified")
	return resp, nil
}

func performIdentityAuthCheck(user spi.User, ctx *serverRequestContext) error {
	userRole := user.GetType()
	userAff := strings.Join(user.GetAffiliationPath(), ".")

	_, isRegistrar, err := ctx.IsRegistrar()
	if err != nil {
		return newAuthErr(ErrUpdateConfigAuth, "Caller is unable to edit identities: %s", err)
	}
	if !isRegistrar {
		return newAuthErr(ErrUpdateConfigAuth, "Caller does not have the attribute '%s', unable to edit identities", registrarRole)
	}

	canActOnRole, err := ctx.CanActOnType(userRole)
	if err != nil {
		return errors.WithMessage(err, "Failed to validate if registrar has proper authority to act on role")
	}
	if !canActOnRole {
		return newAuthErr(ErrRegistrarInvalidType, "Registrar does not have authority to action on role '%s'", userRole)
	}

	validAffiliation, err := ctx.ContainsAffiliation(userAff)
	if err != nil {
		return newHTTPErr(400, ErrGettingAffiliation, "Failed to validate if caller has authority to remove identity affiliation: %s", err)
	}
	if !validAffiliation {
		return newAuthErr(ErrRegistrarNotAffiliated, "Registrar does not have authority to action on affiliation '%s'", userAff)
	}

	return nil
}

// Function takes the modification request and fills in missing information with the current user information
// and parses the modification request to generate the correct input to be stored in the database
func getModifyReq(user spi.User, req api.ModifyIdentityRequest) (*spi.UserInfo, bool) {
	modifyReq := req.RegistrationRequest
	modifyUserInfo := user.(*DBUser).UserInfo
	userPass := user.(*DBUser).pass
	setPass := false

	if modifyReq.Secret != "" {
		setPass = true
		modifyUserInfo.Pass = modifyReq.Secret
	} else {
		modifyUserInfo.Pass = string(userPass)
	}

	if len(modifyReq.Attributes) != 0 {
		allAttributes := modifyUserInfo.Attributes
		newAttributes := modifyReq.Attributes
		var newAttr api.Attribute
		for _, newAttr = range newAttributes {
			foundAttr := false
			for i := range allAttributes {
				if allAttributes[i].Name == newAttr.Name {
					allAttributes[i].Value = newAttr.Value
					foundAttr = true
					break
				}
			}
			if !foundAttr {
				allAttributes = append(allAttributes, newAttr)
			}
		}
		modifyUserInfo.Attributes = allAttributes
	}

	if modifyReq.MaxEnrollments == -2 {
		modifyUserInfo.MaxEnrollments = 0
	} else if modifyReq.MaxEnrollments != 0 {
		modifyUserInfo.MaxEnrollments = modifyReq.MaxEnrollments
	}

	if modifyReq.Affiliation == "." {
		modifyUserInfo.Affiliation = ""
	} else if modifyReq.Affiliation != "" {
		modifyUserInfo.Affiliation = modifyReq.Affiliation
	}

	if modifyReq.Type != "" {
		modifyUserInfo.Type = modifyReq.Type
	}

	return &modifyUserInfo, setPass
}

func getIDInfo(user spi.UserInfo) *IdentityInfo {
	return &IdentityInfo{
		Name:           user.Name,
		Type:           user.Type,
		Affiliation:    user.Affiliation,
		Attributes:     user.Attributes,
		MaxEnrollments: user.MaxEnrollments,
	}
}
