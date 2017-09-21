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
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
)

func newConfigEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: configHandler,
		Server:  s,
	}
}

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
	log.Debugf("Received configuration update request from %s: %+v", callerID, req)
	if err != nil {
		return nil, err
	}

	perm := &permissions{}
	err = callerPermissions(ctx, perm)
	if err != nil {
		return nil, err
	}

	resp, err := processConfigUpdate(ctx, req, perm)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Check to see what permission caller has in regards to updating server's configuration
func callerPermissions(ctx *serverRequestContext, perm *permissions) error {
	_, err := ctx.GetCaller()
	if err != nil {
		return err
	}

	log.Debugf("Checking if caller '%s' has permission to update config", ctx.caller.GetName())

	hasRegistrar := ctx.caller.GetAttribute("hf.Registrar.Roles")
	hasModifyConfig := ctx.caller.GetAttribute("hf.ModifyConfig")

	if hasRegistrar == "" && hasModifyConfig == "" {
		return newHTTPErr(400, ErrUpdateConfigAuth, "Caller does not have authority to dynamically update server's configuration")
	}

	if hasRegistrar != "" {
		log.Debug("Caller has permission to update identities")
		perm.updateIdentities = true
	}

	if hasModifyConfig != "" {
		log.Debug("Caller has permission to update affiliations")
		perm.updateAffiliations = true
	}

	return nil
}

func processConfigUpdate(ctx *serverRequestContext, req *api.UpdateConfigRequest, perm *permissions) (interface{}, error) {
	log.Debugf("Process request for dynamic config update: %+v", req)

	if req.List {
		log.Debug("Requesting list of server side configurations that support dynamic updates")
		// TODO: Implement
		return nil, newHTTPErr(400, ErrUpdateConfig, "List not yet implemented")
	}

	if len(req.Add) > 0 {
		log.Debugf("Requesting to add '%s' to server's configuration", req.Add)
		// TODO: Implement
		return nil, newHTTPErr(400, ErrUpdateConfig, "Add not yet implemented")
	}

	if len(req.Remove) > 0 {
		log.Debugf("Requesting to remove '%s' from server's configuration", req.Remove)
		// TODO: Implement
		return nil, newHTTPErr(400, ErrUpdateConfig, "Remove not yet implemented")
	}

	if len(req.Modify) > 0 {
		log.Debugf("Requesting to modify '%s' in server's configuration", req.Modify)
		// TODO: Implement
		return nil, newHTTPErr(400, ErrUpdateConfig, "Modify not yet implemented")
	}

	return nil, nil
}
