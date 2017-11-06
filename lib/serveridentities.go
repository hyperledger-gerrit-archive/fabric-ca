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
		resp, err := getIDs(ctx, caller, caname)
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

func getIDs(ctx *serverRequestContext, caller spi.User, caname string) (*api.GetAllIDsResponse, error) {
	log.Debug("Requesting all identities that the caller is authorized view")
	var err error

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	callerTypes, err := caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		return nil, newHTTPErr(500, ErrGettingUser, "Failed to get registrar roles for caller", err)
	}
	// Getting all identities of appropriate affiliation and type
	ids, err := registry.GetFilteredUsers(callerAff, callerTypes.Value)
	if err != nil {
		return nil, newHTTPErr(500, ErrGettingUser, "Failed to get users by affiliation and type: %s", err)
	}
	idsInfo := []api.IdentityInfo{}

	// Get identity information
	for _, user := range ids {
		userInfo := user.(*DBUser).UserInfo
		idsInfo = append(idsInfo, *getIDInfo(&userInfo))
	}

	resp := &api.GetAllIDsResponse{
		Identities: idsInfo,
		CAName:     caname,
	}

	return resp, nil
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
	resp.IdentityInfo = *getIDInfo(&userInfo)

	return resp, nil
}

func processDeleteRequest(ctx *serverRequestContext, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing DELETE request")
	if !ctx.ca.Config.Cfg.Identities.AllowRemove {
		return nil, newHTTPErr(501, ErrRemoveIdentity, "Identity removal is disabled")
	}

	removeID, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	if removeID == "" {
		return nil, newHTTPErr(400, ErrRemoveIdentity, "No ID name specified in remove request")
	}

	log.Debugf("Removing identity '%s'", removeID)
	userToRemove, err := ctx.GetUser(removeID)
	if err != nil {
		return nil, err
	}

	registry := ctx.ca.registry
	registry.DeleteUser(removeID)
	if err != nil {
		return nil, newHTTPErr(500, ErrRemoveIdentity, "Failed to remove identity: ", err)
	}

	userInfo := userToRemove.(*DBUser).UserInfo
	resp := &api.IdentityResponse{
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(&userInfo)

	log.Debugf("Identity '%s' successfully removed", removeID)
	return resp, nil
}

func processPostRequest(ctx *serverRequestContext, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing POST request")

	ctx.endpoint.successRC = 201
	var req api.AddIdentityRequest
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	if req.ID == "" {
		return nil, newHTTPErr(400, ErrAddIdentity, "Missing 'ID' in request to add a new identity")
	}
	addReq := &api.RegistrationRequest{
		Name:           req.ID,
		Secret:         req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
	}
	log.Debugf("Adding identity: %+v", util.StructToString(addReq))

	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get caller identity")
	}
	callerID := caller.GetName()

	pass, err := registerUser(addReq, callerID, ctx.ca, ctx)
	if err != nil {
		return nil, newHTTPErr(400, ErrAddIdentity, "Failed to add identity: %s", err)

	}

	user, err := ctx.ca.registry.GetUser(req.ID, nil)
	if err != nil {
		return nil, getUserError(err)
	}
	userInfo := user.(*DBUser).UserInfo

	resp := &api.IdentityResponse{
		Secret: pass,
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(&userInfo)

	log.Debugf("Identity successfully added")
	return resp, nil
}

func processPutRequest(ctx *serverRequestContext, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing PUT request")

	modifyID, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	if modifyID == "" {
		return nil, newHTTPErr(400, ErrModifyingIdentity, "No ID name specified in modify request")
	}

	log.Debugf("Modifying identity '%s'", modifyID)
	userToModify, err := ctx.GetUser(modifyID)
	if err != nil {
		return nil, err
	}

	registry := ctx.ca.registry

	var req api.ModifyIdentityRequest
	err = ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	var checkAff, checkType, checkAttrs bool
	modReq, setPass := getModifyReq(userToModify, req)
	log.Debugf("Modify Request: %+v", util.StructToString(modReq))

	if req.Affiliation != "" {
		newAff := req.Affiliation
		if newAff != "." { // Only need to check if not requesting root affiliation
			aff, _ := registry.GetAffiliation(newAff)
			if aff == nil {
				return nil, newHTTPErr(400, ErrModifyingIdentity, "Affiliation '%s' is not supported", newAff)
			}
		}
		checkAff = true
	}

	if req.Type != "" {
		checkType = true
	}

	if len(req.Attributes) != 0 {
		checkAttrs = true
	}

	err = ctx.CanModifyUser(req.Affiliation, checkAff, req.Type, checkType, req.Attributes, checkAttrs)
	if err != nil {
		return nil, err
	}

	err = registry.UpdateUser(modReq, setPass)
	if err != nil {
		return nil, err
	}

	resp := &api.IdentityResponse{
		Secret: modReq.Pass,
		CAName: caname,
	}
	resp.IdentityInfo = *getIDInfo(modReq)

	log.Debugf("Identity successfully modified")
	return resp, nil
}

// Function takes the modification request and fills in missing information with the current user information
// and parses the modification request to generate the correct input to be stored in the database
func getModifyReq(user spi.User, req api.ModifyIdentityRequest) (*spi.UserInfo, bool) {
	modifyUserInfo := user.(*DBUser).UserInfo
	userPass := user.(*DBUser).pass
	setPass := false

	if req.Secret != "" {
		setPass = true
		modifyUserInfo.Pass = req.Secret
	} else {
		modifyUserInfo.Pass = string(userPass)
	}

	// Update existing attribute, or add attribute if it does not already exist
	if len(req.Attributes) != 0 {
		allAttributes := modifyUserInfo.Attributes
		newAttributes := req.Attributes
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

	if req.MaxEnrollments == -2 {
		modifyUserInfo.MaxEnrollments = 0
	} else if req.MaxEnrollments != 0 {
		modifyUserInfo.MaxEnrollments = req.MaxEnrollments
	}

	if req.Affiliation == "." {
		modifyUserInfo.Affiliation = ""
	} else if req.Affiliation != "" {
		modifyUserInfo.Affiliation = req.Affiliation
	}

	if req.Type != "" {
		modifyUserInfo.Type = req.Type
	}

	return &modifyUserInfo, setPass
}

func getIDInfo(user *spi.UserInfo) *api.IdentityInfo {
	return &api.IdentityInfo{
		ID:             user.Name,
		Type:           user.Type,
		Affiliation:    user.Affiliation,
		Attributes:     user.Attributes,
		MaxEnrollments: user.MaxEnrollments,
	}
}
