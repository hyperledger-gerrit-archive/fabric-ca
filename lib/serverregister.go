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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

// registerHandler for register requests
type registerHandler struct {
	server *Server
}

// NewRegisterHandler is constructor for register handler
func NewRegisterHandler(server *Server) (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &cfsslapi.HTTPHandler{
		Handler: &registerHandler{server: server},
		Methods: []string{"POST"},
	}, nil
}

// Handle a register request
func (h *registerHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("Register request received")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Parse request body
	var req api.RegistrationRequestNet
	err = json.Unmarshal(reqBody, &req)
	if err != nil {
		return err
	}

	// Register User
	callerID := r.Header.Get(enrollmentIDHdrName)
	secret, err := h.RegisterUser(req.Name, req.Type, req.Affiliation, req.Attributes, callerID, req.MaxEnrollments)
	if err != nil {
		return err
	}

	resp := &api.RegistrationResponseNet{RegistrationResponse: api.RegistrationResponse{Secret: secret}}

	log.Debugf("Registration completed - sending response %+v", &resp)
	return cfsslapi.SendResponse(w, resp)
}

// RegisterUser will register a user
func (h *registerHandler) RegisterUser(id string, userType string, affiliation string, attributes []api.Attribute, registrar string, maxEnrollments int, opt ...string) (string, error) {
	log.Debugf("Received request to register user with id: %s, group: %s, attributes: %+v, maxEnrollments: %d, registrar: %s\n",
		id, affiliation, attributes, maxEnrollments, registrar)

	var tok string
	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = h.canRegister(registrar, userType)
		if err != nil {
			log.Debugf("Registration of '%s' failed: %s", id, err)
			return "", err
		}
	}

	err = h.validateID(id, userType, affiliation)
	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", id, err)
		return "", err
	}

	tok, err = h.registerUserID(id, userType, affiliation, attributes, maxEnrollments, opt...)

	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", id, err)
		return "", err
	}

	return tok, nil
}

func (h *registerHandler) validateID(id string, userType string, affiliation string) error {
	log.Debug("Validate ID")
	// Check whether the affiliation is required for the current user.
	if h.requireAffiliation(userType) {
		// If yes, is the affiliation valid
		err := h.isValidAffiliation(affiliation)
		if err != nil {
			return err
		}
	}
	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func (h *registerHandler) registerUserID(id string, userType string, affiliation string, attributes []api.Attribute, newMaxEnrollments int, opt ...string) (string, error) {
	log.Debugf("Registering user id: %s\n", id)

	var tok string
	if len(opt) > 0 && len(opt[0]) > 0 {
		tok = opt[0]
	} else {
		tok = util.RandomString(12)
	}

	maxEnrollments := h.server.Config.Registry.MaxEnrollments

	if (newMaxEnrollments > maxEnrollments && maxEnrollments != 0) || (newMaxEnrollments < 0) {
		return "", fmt.Errorf("Invalid max enrollment value specified, value must be equal to or less then %d", maxEnrollments)
	}

	if newMaxEnrollments == 0 && maxEnrollments != 0 {
		return "", fmt.Errorf("Unlimited enrollments not allowed, value must be equal to or less then %d", maxEnrollments)
	}

	insert := spi.UserInfo{
		Name:           id,
		Pass:           tok,
		Type:           userType,
		Affiliation:    affiliation,
		Attributes:     attributes,
		MaxEnrollments: newMaxEnrollments,
	}

	registry := h.server.registry

	_, err := registry.GetUser(id, nil)
	if err == nil {
		return "", fmt.Errorf("User '%s' is already registered", id)
	}

	err = registry.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return tok, nil
}

func (h *registerHandler) isValidAffiliation(affiliation string) error {
	log.Debug("Validating affiliation: " + affiliation)

	_, err := h.server.registry.GetAffiliation(affiliation)
	if err != nil {
		return fmt.Errorf("Failed getting affiliation '%s': %s", affiliation, err)
	}

	return nil
}

func (h *registerHandler) requireAffiliation(idType string) bool {
	log.Debugf("An affiliation is required for identity type %s", idType)
	// Require an affiliation for all identity types
	return true
}

func (h *registerHandler) canRegister(registrar string, userType string) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	user, err := h.server.registry.GetUser(registrar, nil)
	if err != nil {
		return fmt.Errorf("Registrar does not exist: %s", err)
	}

	var roles []string
	rolesStr := user.GetAttribute("hf.Registrar.Roles")
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	} else {
		roles = make([]string, 0)
	}
	if userType != "" {
		if !util.StrContained(userType, roles) {
			return fmt.Errorf("User '%s' may not register type '%s'", registrar, userType)
		}
	} else {
		return errors.New("No user type provied. Please provide user type")
	}

	return nil
}
