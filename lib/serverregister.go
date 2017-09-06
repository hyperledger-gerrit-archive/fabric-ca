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

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

func newRegisterEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: registerHandler,
		Server:  s,
	}
}

// Handle a register request
func registerHandler(ctx *serverRequestContext) (interface{}, error) {
	// Read request body
	var req api.RegistrationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	// Get the target CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Register User
	secret, err := registerUser(&req, callerID, ca)
	if err != nil {
		return nil, err
	}
	// Return response
	resp := &api.RegistrationResponseNet{
		RegistrationResponse: api.RegistrationResponse{Secret: secret},
	}
	return resp, nil
}

// RegisterUser will register a user and return the secret
func registerUser(req *api.RegistrationRequestNet, registrar string, ca *CA) (string, error) {

	secret := req.Secret
	req.Secret = "<<user-specified>>"
	log.Debugf("Received registration request from %s: %+v", registrar, req)
	req.Secret = secret

	var err error
	var user spi.User

	if registrar != "" {
		user, err = ca.registry.GetUser(registrar, nil)
		if err != nil {
			return "", errors.WithMessage(err, "Registrar does not exist")
		}

		// Check the permissions of member named 'registrar' to perform this registration
		err = canRegister(registrar, req, user)
		if err != nil {
			log.Debugf("Registration of '%s' failed: %s", req.Name, err)
			return "", err
		}
	}

	err = validateID(req, ca)
	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' to validate", req.Name))
	}

	err = validateRequestedAttr(req.Attributes, user)
	if err != nil {
		return "", errors.WithMessage(err, "Registrar is not allowed to register the requested attributes")
	}

	secret, err = registerUserID(req, ca)

	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' failed", req.Name))
	}

	return secret, nil
}

func validateID(req *api.RegistrationRequestNet, ca *CA) error {
	log.Debug("Validate ID")
	// Check whether the affiliation is required for the current user.
	if requireAffiliation(req.Type) {
		// If yes, is the affiliation valid
		err := isValidAffiliation(req.Affiliation, ca)
		if err != nil {
			return err
		}
	}
	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func registerUserID(req *api.RegistrationRequestNet, ca *CA) (string, error) {
	log.Debugf("Registering user id: %s\n", req.Name)
	var err error

	if req.Secret == "" {
		req.Secret = util.RandomString(12)
	}

	req.MaxEnrollments, err = getMaxEnrollments(req.MaxEnrollments, ca.Config.Registry.MaxEnrollments)
	if err != nil {
		return "", err
	}

	// Make sure delegateRoles is not larger than roles
	roles := GetAttrValue(req.Attributes, attrRoles)
	delegateRoles := GetAttrValue(req.Attributes, attrDelegateRoles)
	err = util.IsSubsetOf(delegateRoles, roles)
	if err != nil {
		return "", errors.WithMessage(err, "The delegateRoles field is a superset of roles")
	}

	insert := spi.UserInfo{
		Name:           req.Name,
		Pass:           req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
	}

	registry := ca.registry

	_, err = registry.GetUser(req.Name, nil)
	if err == nil {
		return "", errors.Errorf("Identity '%s' is already registered", req.Name)
	}

	err = registry.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return req.Secret, nil
}

func isValidAffiliation(affiliation string, ca *CA) error {
	log.Debug("Validating affiliation: " + affiliation)

	_, err := ca.registry.GetAffiliation(affiliation)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed getting affiliation '%s'", affiliation))
	}

	return nil
}

func requireAffiliation(idType string) bool {
	log.Debugf("An affiliation is required for identity type %s", idType)
	// Require an affiliation for all identity types
	return true
}

func canRegister(registrar string, req *api.RegistrationRequestNet, user spi.User) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	var roles []string
	rolesStr := user.GetAttribute("hf.Registrar.Roles")
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	} else {
		roles = make([]string, 0)
	}
	if req.Type == "" {
		req.Type = "user"
	}
	if !util.StrContained(req.Type, roles) {
		return fmt.Errorf("Identity '%s' may not register type '%s'", registrar, req.Type)
	}
	return nil
}

// Validate that the registrar can register the requested attributes
func validateRequestedAttr(reqAttrs []api.Attribute, registrar spi.User) error {
	registrarAllAttrs := registrar.GetAllAttributes()
	log.Debugf("Validating that registrar '%s' with attributes '%s' is authorized to register the requested attributes '%+v'", registrar.GetName(), registrarAllAttrs, reqAttrs)
	if len(reqAttrs) == 0 {
		return nil
	}

	var hfRegistrarAttrsSlice []string
	// Check if registrar has 'hf.Registrar.Attributes' attribute and gets its value
	registrarAttrs, hasRegistrarAttrs := registrarAllAttrs[attrRegistrarAttr]
	if hasRegistrarAttrs {
		hfRegistrarAttrsSlice = strings.Split(strings.Replace(registrarAttrs, " ", "", -1), ",") // Remove any whitespace between the values and split on comma
	}

	// Function will iterate through the values of registrar's 'hf.Registrar.Attributes' attribute to check if registrar can register the requested attributes
	registrarHasAttr := func(requestedAttr string) error {
		for _, regAttr := range hfRegistrarAttrsSlice {
			if strings.HasSuffix(regAttr, "*") { // Wildcard matching
				if strings.Contains(requestedAttr, strings.TrimRight(regAttr, "*")) {
					return nil // Requested attribute found, break out of loop
				}
			} else {
				if requestedAttr == regAttr { // Exact name matching
					return nil // Requested attribute found, break out of loop
				}
			}
		}
		return errors.Errorf("Attribute is not part of '%s' attribute", attrRegistrarAttr)
	}

	for _, reqAttr := range reqAttrs {
		reqAttrName := reqAttr.Name // Name of the requested attribute

		// Requesting 'hf.Registrar.Attributes' attribute
		if reqAttrName == attrRegistrarAttr {
			// Check if registrar also has this attribute
			if hasRegistrarAttrs {
				reqRegistrarAttrsSlice := strings.Split(strings.Replace(reqAttr.Value, " ", "", -1), ",") // Remove any whitespace between the values and split on comma
				// Loop through the requested values for 'hf.Registrar.Attributes' to see if they can be registered
				for _, reqRegistrarAttr := range reqRegistrarAttrsSlice {
					err := registrarHasAttr(reqRegistrarAttr)
					if err != nil {
						return errors.WithMessage(err, fmt.Sprintf("Registrar is not allowed to register attribute '%s'", reqRegistrarAttr))
					}
				}
			} else {
				return errors.Errorf("Registrar cannot register '%s' attribute", attrRegistrarAttr)
			}
			continue // Continue to next requested attribute
		}

		_, registrarOwnsAttr := registrarAllAttrs[reqAttrName] // Check if requested attribute is owned by the registrar, if so registrar can register attribute
		if registrarOwnsAttr {
			return nil
		}

		log.Debugf("Requested attr '%s' is not owned by registrar, checking registrar's value for '%s'", reqAttrName, attrRegistrarAttr)

		// Check if registrar has attribute 'hf.Registrar.Attributes'
		if !hasRegistrarAttrs {
			return errors.Errorf("Registrar does not own '%s' attribute nor does it posses the '%s' attribute", reqAttrName, attrRegistrarAttr)
		}

		// Iterate through the values of 'hf.Registrar.Attributes' to check if it can register the requested attribute
		err := registrarHasAttr(reqAttrName)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Registrar does not own '%s' attribute", reqAttrName))
		}
	}

	return nil
}
