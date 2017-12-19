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
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

type attributeType int

const (
	// BOOLEAN indicates that the attribute is of type boolean
	BOOLEAN attributeType = 1 + iota
	// LIST indicates that the attribute is of type list
	LIST
	// FIXED indicates that the attribute value is fixed and can't be modified
	FIXED
	// CUSTOM indicates that the attribute is a custom attribute
	CUSTOM
)

// Attribute names
const (
	attrRoles          = "hf.Registrar.Roles"
	attrDelegateRoles  = "hf.Registrar.DelegateRoles"
	attrRevoker        = "hf.Revoker"
	attrIntermediateCA = "hf.IntermediateCA"
	attrGenCRL         = "hf.GenCRL"
	attrRegistrarAttr  = "hf.Registrar.Attributes"
	attrAffiliationMgr = "hf.AffiliationMgr"
	attrEnrollmentID   = "hf.EnrollmentID"
	attrType           = "hf.Type"
	attrAffiliation    = "hf.Affiliation"
)

type attributeControl struct {
	name              string
	requiresOwnership bool
	attrType          attributeType
}

func getAttributeControl() map[string]*attributeControl {
	var attributeMap = make(map[string]*attributeControl)

	booleanAttributes := []string{attrRevoker, attrIntermediateCA, attrGenCRL, attrAffiliationMgr}

	for _, attr := range booleanAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: true,
			attrType:          BOOLEAN,
		}
	}

	listAttributes := []string{attrRoles, attrDelegateRoles, attrRegistrarAttr}

	for _, attr := range listAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: true,
			attrType:          LIST,
		}
	}

	fixedValueAttributes := []string{attrEnrollmentID, attrType, attrAffiliation}

	for _, attr := range fixedValueAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: false,
			attrType:          FIXED,
		}
	}

	return attributeMap
}

func (ac *attributeControl) getName() string {
	return ac.name
}

func (ac *attributeControl) isOwnershipRequired() bool {
	return ac.requiresOwnership
}

func (ac *attributeControl) isRegistrarAuthorized(callersAttr, requestedAttr *api.Attribute) error {
	requestedAttrName := requestedAttr.GetName()
	requestedAttrValue := requestedAttr.GetValue()
	callersAttrValue := callersAttr.GetValue()

	log.Debugf("Checking if caller is authorized to register attribute '%s' with the requested value of '%s'", requestedAttrName, requestedAttrValue)

	switch ac.attrType {
	case BOOLEAN:
		if callersAttrValue == "false" && requestedAttrValue == "true" {
			return errors.Errorf("Caller has a value of 'false' for boolean attribute '%s', can't request a value of 'true' for this attribute", requestedAttrName)
		}
	case LIST:
		// hf.Registrar.Attribute is a special type of list attribute. Need to check all the
		// requested attribute names to make sure caller is allowed register
		if ac.getName() == attrRegistrarAttr {
			requestedAttrSlice := strings.Split(strings.Replace(requestedAttrValue, " ", "", -1), ",")    // Remove any whitespace between the values and split on comma
			callerRegisterAttrSlice := strings.Split(strings.Replace(callersAttrValue, " ", "", -1), ",") // Remove any whitespace between the values and split on comma

			for _, requestedAttr := range requestedAttrSlice {
				err := ac.registrarCanRegisterAttrValues(requestedAttr, callerRegisterAttrSlice)
				if err != nil {
					return errors.Errorf("Registrar is not allowed to register attribute '%s': %s", requestedAttr, err)
				}
			}
			return nil
		}
		// For all other list type attributes, need to make sure requested value is a subset of caller's value
		err := util.IsSubsetOf(requestedAttrValue, callersAttrValue)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("The requested values for attribute '%s' is a superset of the caller's attribute value", requestedAttrName))
		}
	}

	return nil
}

func (ac *attributeControl) registrarCanRegisterAttrValues(requestedAttrValue string, callerRegisterAttrSlice []string) error {
	log.Debug("Checking if registrar can register the values of 'hf.Registrar.Attribute': ", requestedAttrValue)

	for _, regAttr := range callerRegisterAttrSlice {
		if strings.HasSuffix(regAttr, "*") { // Wildcard matching
			if strings.HasPrefix(requestedAttrValue, strings.TrimRight(regAttr, "*")) {
				return nil
			}
		} else {
			if requestedAttrValue == regAttr { // Exact name matching
				return nil
			}
		}
	}

	return errors.Errorf("Attribute is not part of '%s' attribute", callerRegisterAttrSlice)
}
