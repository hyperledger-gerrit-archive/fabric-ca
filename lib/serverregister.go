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
	caName string
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

	h.caName = r.Header.Get("caname")
	if h.caName == "" {
		h.caName = DefaultCAName
	}

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

	caMaxEnrollments := h.server.CAs[h.caName].Config.Registry.MaxEnrollments

	maxEnrollment, err := checkMaxEnrollments(req.MaxEnrollments, caMaxEnrollments)
	if err != nil {
		return "", err
	}

	insert := spi.UserInfo{
		Name:           req.Name,
		Pass:           req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: maxEnrollment,
	}

	registry := h.server.CAs[h.caName].registry

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

	_, err := h.server.CAs[h.caName].registry.GetAffiliation(affiliation)
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

	user, err := h.server.CAs[h.caName].registry.GetUser(registrar, nil)
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

func checkMaxEnrollments(userMaxEnrollment int, caMaxEnrollment int) (int, error) {
	log.Debugf("Max enrollment value verification - User specified max enrollment: %d, CA max enrollment: %d", userMaxEnrollment, caMaxEnrollment)
	maxEnrollment := userMaxEnrollment

	if userMaxEnrollment < -1 {
		return 0, fmt.Errorf("Invalid value of %d specified for max enrollment", userMaxEnrollment)
	}

	if userMaxEnrollment == 0 && caMaxEnrollment == 0 {
		log.Debug("CA set to not allow enrollments, and registration request has zero specified for max enrollments. Defaulting request to be -1 (infinite enrollments)")
		maxEnrollment = -1
	} else if (userMaxEnrollment >= 1 || userMaxEnrollment == -1) && caMaxEnrollment == 0 {
		log.Debug("CA set to not allow enrollments, and registration request has non-zero value specified for max enrollments. Using user specified max enrollment")
		maxEnrollment = userMaxEnrollment
	} else if userMaxEnrollment == 0 && caMaxEnrollment != 0 {
		// Zero value for max enrollment specified in registration request, use CA max enrollment value
		log.Debugf("%d specified for max enrollment in registration request, using CA max enrollment value of %d", userMaxEnrollment, caMaxEnrollment)
		maxEnrollment = caMaxEnrollment
	} else if userMaxEnrollment == -1 && caMaxEnrollment > 0 {
		// A negative value for max enrollment specified in registration request, check
		// CA max enrollment value to see if infinite registration is allowed

		return 0, fmt.Errorf("Unlimited enrollments not allowed, value must be equal to or less then %d", caMaxEnrollment)
	} else if userMaxEnrollment > caMaxEnrollment && caMaxEnrollment > 0 {
		// A positive value for max enrollment specified in registration request, check
		// to see if value is less than or equal to max enrollment allowed by CA

		return 0, fmt.Errorf("Invalid max enrollment (%d) value specified, value must be equal to or less then %d", userMaxEnrollment, caMaxEnrollment)
	}

	return maxEnrollment, nil
}
