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

// newRegisterHandler is constructor for register handler
func newRegisterHandler(server *Server) (h http.Handler, err error) {
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
	secret, err := h.RegisterUser(&req, callerID)
	if err != nil {
		return err
	}

	resp := &api.RegistrationResponseNet{RegistrationResponse: api.RegistrationResponse{Secret: secret}}

	log.Debugf("Registration completed - sending response %+v", &resp)
	return cfsslapi.SendResponse(w, resp)
}

// RegisterUser will register a user
func (h *registerHandler) RegisterUser(req *api.RegistrationRequestNet, registrar string) (string, error) {

	secret := req.Secret
	req.Secret = "<<user-specified>>"
	log.Debugf("Received registration request from %s: %+v", registrar, req)
	req.Secret = secret

	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = h.canRegister(registrar, req.Type)
		if err != nil {
			log.Debugf("Registration of '%s' failed: %s", req.Name, err)
			return "", err
		}
	}

	err = h.validateID(req)
	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", req.Name, err)
		return "", err
	}

	secret, err = h.registerUserID(req)

	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", req.Name, err)
		return "", err
	}

	return secret, nil
}

func (h *registerHandler) validateID(req *api.RegistrationRequestNet) error {
	log.Debug("Validate ID")
	// Check whether the affiliation is required for the current user.
	if h.requireAffiliation(req.Type) {
		// If yes, is the affiliation valid
		err := h.isValidAffiliation(req.Affiliation)
		if err != nil {
			return err
		}
	}
	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func (h *registerHandler) registerUserID(req *api.RegistrationRequestNet) (string, error) {
	log.Debugf("Registering user id: %s\n", req.Name)
	var err error

	if req.Secret == "" {
		req.Secret = util.RandomString(12)
	}

	caMaxEnrollments := h.server.Config.Registry.MaxEnrollments

	req.MaxEnrollments, err = h.getMaxEnrollments(req.MaxEnrollments, caMaxEnrollments)
	if err != nil {
		return "", err
	}

	insert := spi.UserInfo{
		Name:           req.Name,
		Pass:           req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
	}

	registry := h.server.registry

	_, err = registry.GetUser(req.Name, nil)
	if err == nil {
		return "", fmt.Errorf("User '%s' is already registered", req.Name)
	}

	err = registry.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return req.Secret, nil
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

func (h *registerHandler) getMaxEnrollments(userMaxEnrollment int, caMaxEnrollment int) (int, error) {
	log.Debugf("Max enrollment value verification - User specified max enrollment: %d, CA max enrollment: %d", userMaxEnrollment, caMaxEnrollment)
	if userMaxEnrollment < -1 {
		return 0, fmt.Errorf("Max enrollment in registration request may not be less than -1, but was %d", userMaxEnrollment)
	}
	switch caMaxEnrollment {
	case -1:
		if userMaxEnrollment == 0 {
			// The user is requesting the matching limit of the CA, so gets infinite
			return -1, nil
		}
		// There is no CA max enrollment limit, so simply use the user requested value
		return userMaxEnrollment, nil
	case 0:
		// The CA max enrollment is 0, so registration is disabled.
		return 0, errors.New("Registration is disabled")
	default:
		switch userMaxEnrollment {
		case -1:
			// User requested infinite enrollments is not allowed
			return 0, errors.New("Registration for infinite enrollments is not allowed")
		case 0:
			// User is requesting the current CA maximum
			return caMaxEnrollment, nil
		default:
			// User is requesting a specific positive value; make sure it doesn't exceed the CA maximum.
			if userMaxEnrollment > caMaxEnrollment {
				return 0, fmt.Errorf("Requested enrollments (%d) exceeds maximum allowable enrollments (%d)",
					userMaxEnrollment, caMaxEnrollment)
			}
			// otherwise, use the requested maximum
			return userMaxEnrollment, nil
		}
	}
}
