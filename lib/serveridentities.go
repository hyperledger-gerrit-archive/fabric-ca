/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
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
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

func newIdentitiesEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "DELETE", "PUT"},
		Handler:   identitiesHandler,
		Server:    s,
		successRC: 200,
	}
}

func newIdentitiesStreamingEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "POST"},
		Handler:   identitiesStreamingHandler,
		Server:    s,
		successRC: 200,
	}
}

func identitiesStreamingHandler(ctx *serverRequestContextImpl) (interface{}, error) {
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
	resp, err := processStreamingRequest(ctx, caname, caller)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func identitiesHandler(ctx *serverRequestContextImpl) (interface{}, error) {
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

// processStreamingRequest will process the configuration request
func processStreamingRequest(ctx *serverRequestContextImpl, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing identity configuration update request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return nil, processGetAllIDsRequest(ctx, caller, caname)
	case "POST":
		return processPostRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

// processRequest will process the configuration request
func processRequest(ctx *serverRequestContextImpl, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing identity configuration update request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return processGetIDRequest(ctx, caller, caname)
	case "DELETE":
		return processDeleteRequest(ctx, caname)
	case "PUT":
		return processPutRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

func processGetAllIDsRequest(ctx *serverRequestContextImpl, caller spi.User, caname string) error {
	log.Debug("Processing GET all IDs request")

	err := getIDs(ctx, caller, caname)
	if err != nil {
		return err
	}
	return nil
}

func processGetIDRequest(ctx *serverRequestContextImpl, caller spi.User, caname string) (interface{}, error) {
	log.Debug("Processing GET ID request")

	id, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	resp, err := getID(ctx, caller, id, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getIDs(ctx *serverRequestContextImpl, caller spi.User, caname string) error {
	log.Debug("Requesting all identities that the caller is authorized view")
	var err error

	w := ctx.resp
	flusher, _ := w.(http.Flusher)

	callerTypes, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return err
	}
	if !isRegistrar {
		return caerrors.NewAuthorizationErr(caerrors.ErrGettingUser, "Caller is not a registrar")
	}

	// Getting all identities of appropriate affiliation and type
	callerAff := GetUserAffiliation(caller)
	registry := ctx.ca.registry
	rows, err := registry.GetFilteredUsers(callerAff, callerTypes)
	if err != nil {
		return caerrors.NewHTTPErr(500, caerrors.ErrGettingUser, "Failed to get users by affiliation and type: %s", err)
	}

	// Get the number of identities to return back to client in a chunk based on the environment variable
	// If environment variable not set, default to 100 identities
	numberOfIdentities := os.Getenv("FABRIC_CA_SERVER_MAX_IDS_PER_CHUNK")
	var numIdentities int
	if numberOfIdentities == "" {
		numIdentities = 100
	} else {
		numIdentities, err = strconv.Atoi(numberOfIdentities)
		if err != nil {
			return caerrors.NewHTTPErr(500, caerrors.ErrGettingUser, "Incorrect format specified for environment variable 'FABRIC_CA_SERVER_MAX_IDS_PER_CHUNK', an integer value is required: %s", err)
		}
	}

	log.Debugf("Number of identities to be delivered in each chunk: %d", numIdentities)

	w.Write([]byte(`{"identities":[`))

	rowNumber := 0
	for rows.Next() {
		rowNumber++
		var id UserRecord
		err := rows.StructScan(&id)
		if err != nil {
			return caerrors.NewHTTPErr(500, caerrors.ErrGettingUser, "Failed to get read row: %s", err)
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
			return caerrors.NewHTTPErr(500, caerrors.ErrGettingUser, "Failed to marshal identity info: %s", err)
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

func getID(ctx *serverRequestContextImpl, caller spi.User, id, caname string) (*api.GetIDResponse, error) {
	log.Debugf("Requesting identity '%s'", id)

	registry := ctx.ca.registry
	user, err := registry.GetUser(id, nil)
	if err != nil {
		return nil, err
	}

	err = ctx.CanManageUser(user)
	if err != nil {
		return nil, err
	}

	allAttributes, err := user.GetAttributes(nil)
	if err != nil {
		return nil, err
	}

	resp := &api.GetIDResponse{
		ID:             user.GetName(),
		Type:           user.GetType(),
		Affiliation:    GetUserAffiliation(user),
		Attributes:     allAttributes,
		MaxEnrollments: user.GetMaxEnrollments(),
		CAName:         caname,
	}

	return resp, nil
}

func processDeleteRequest(ctx *serverRequestContextImpl, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing DELETE request")

	if !ctx.ca.Config.Cfg.Identities.AllowRemove {
		return nil, caerrors.NewHTTPErr(403, caerrors.ErrRemoveIdentity, "Identity removal is disabled")
	}

	removeID, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	if removeID == "" {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrRemoveIdentity, "No ID name specified in remove request")
	}

	log.Debugf("Removing identity '%s'", removeID)

	force, err := ctx.GetBoolQueryParm("force")
	if err != nil {
		return nil, err
	}

	if removeID == ctx.caller.GetName() && !force {
		return nil, caerrors.NewHTTPErr(403, caerrors.ErrRemoveIdentity, "Need to use 'force' option to delete your own identity")
	}

	registry := ctx.ca.registry
	userToRemove, err := ctx.GetUser(removeID)
	if err != nil {
		return nil, err
	}

	err = ctx.CanManageUser(userToRemove)
	if err != nil {
		return nil, err
	}

	_, err = registry.DeleteUser(removeID)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveIdentity, "Failed to remove identity: %s", err)
	}

	resp, err := getIDResp(userToRemove, "", caname)
	if err != nil {
		return nil, err
	}

	log.Debugf("Identity '%s' successfully removed", removeID)
	return resp, nil
}

func processPostRequest(ctx *serverRequestContextImpl, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing POST request")

	ctx.endpoint.successRC = 201
	var req api.AddIdentityRequest
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	if req.ID == "" {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrAddIdentity, "Missing 'ID' in request to add a new identity")
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
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrAddIdentity, "Failed to add identity: %s", err)

	}

	user, err := ctx.ca.registry.GetUser(req.ID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := getIDResp(user, pass, caname)
	if err != nil {
		return nil, err
	}

	log.Debugf("Identity successfully added")
	return resp, nil
}

func processPutRequest(ctx *serverRequestContextImpl, caname string) (*api.IdentityResponse, error) {
	log.Debug("Processing PUT request")

	modifyID, err := ctx.GetVar("id")
	if err != nil {
		return nil, err
	}

	if modifyID == "" {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrModifyingIdentity, "No ID name specified in modify request")
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
	modReq, setPass := getModifyReq(userToModify, &req)
	log.Debugf("Modify Request: %+v", util.StructToString(modReq))

	if req.Affiliation != "" {
		newAff := req.Affiliation
		if newAff != "." { // Only need to check if not requesting root affiliation
			aff, _ := registry.GetAffiliation(newAff)
			if aff == nil {
				return nil, caerrors.NewHTTPErr(404, caerrors.ErrModifyingIdentity, "Affiliation '%s' is not supported", newAff)
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

	err = ctx.CanModifyUser(&req, checkAff, checkType, checkAttrs, userToModify)
	if err != nil {
		return nil, err
	}

	err = registry.UpdateUser(modReq, setPass)
	if err != nil {
		return nil, err
	}

	userToModify, err = registry.GetUser(modifyID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := getIDResp(userToModify, req.Secret, caname)
	if err != nil {
		return nil, err
	}

	log.Debugf("Identity successfully modified")
	return resp, nil
}

// Function takes the modification request and fills in missing information with the current user information
// and parses the modification request to generate the correct input to be stored in the database
func getModifyReq(user spi.User, req *api.ModifyIdentityRequest) (*spi.UserInfo, bool) {
	modifyUserInfo := user.(*DBUser).UserInfo
	userPass := user.(*DBUser).pass
	setPass := false

	if req.Secret != "" {
		setPass = true
		modifyUserInfo.Pass = req.Secret
	} else {
		modifyUserInfo.Pass = string(userPass)
	}

	if req.MaxEnrollments == -2 {
		modifyUserInfo.MaxEnrollments = 0
	} else if req.MaxEnrollments != 0 {
		modifyUserInfo.MaxEnrollments = req.MaxEnrollments
	}

	reqAttrs := req.Attributes
	if req.Affiliation == "." {
		modifyUserInfo.Affiliation = ""
		addAttributeToRequest(attr.Affiliation, "", &reqAttrs)
	} else if req.Affiliation != "" {
		modifyUserInfo.Affiliation = req.Affiliation
		addAttributeToRequest(attr.Affiliation, req.Affiliation, &reqAttrs)
	}

	if req.Type != "" {
		modifyUserInfo.Type = req.Type
		addAttributeToRequest(attr.Type, req.Type, &reqAttrs)
	}

	// Update existing attribute, or add attribute if it does not already exist
	if len(reqAttrs) != 0 {
		modifyUserInfo.Attributes = getNewAttributes(modifyUserInfo.Attributes, reqAttrs)
	}

	return &modifyUserInfo, setPass
}

// Get the identity response
// Note that the secret will be the empty string unless the
// caller is permitted to see the secret.  For example,
// when adding a new identity and a secret is automatically
// generated, it must be returned to the registrar.
func getIDResp(user spi.User, secret, caname string) (*api.IdentityResponse, error) {
	allAttributes, err := user.GetAttributes(nil)
	if err != nil {
		return nil, err
	}
	return &api.IdentityResponse{
		ID:             user.GetName(),
		Type:           user.GetType(),
		Affiliation:    GetUserAffiliation(user),
		Attributes:     allAttributes,
		MaxEnrollments: user.GetMaxEnrollments(),
		Secret:         secret,
		CAName:         caname,
	}, nil
}

// Update existing attribute, or add attribute if it does not already exist
func getNewAttributes(modifyAttrs, newAttrs []api.Attribute) []api.Attribute {
	var attr api.Attribute
	for _, attr = range newAttrs {
		log.Debugf("Attribute request: %+v", attr)
		found := false
		for i := range modifyAttrs {
			if modifyAttrs[i].Name == attr.Name {
				if attr.Value == "" {
					log.Debugf("Deleting attribute: %+v", modifyAttrs[i])
					if i == len(modifyAttrs)-1 {
						modifyAttrs = modifyAttrs[:len(modifyAttrs)-1]
					} else {
						modifyAttrs = append(modifyAttrs[:i], modifyAttrs[i+1:]...)
					}
				} else {
					log.Debugf("Updating existing attribute from '%+v' to '%+v'", modifyAttrs[i], attr)
					modifyAttrs[i].Value = attr.Value
					modifyAttrs[i].ECert = attr.ECert
				}
				found = true
				break
			}
		}
		if !found && attr.Value != "" {
			log.Debugf("Adding '%+v' as new attribute", attr)
			modifyAttrs = append(modifyAttrs, attr)
		}
	}
	return modifyAttrs
}
