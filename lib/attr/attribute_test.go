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

package attr

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type testUser struct {
	name       string
	attributes []api.Attribute
}

func getUser(name string, attrs []api.Attribute) AttributeControl {
	return &testUser{
		name:       name,
		attributes: attrs,
	}
}

func (tu *testUser) GetAttribute(name string) (*api.Attribute, error) {
	attrs := make(map[string]api.Attribute)
	for _, attr := range tu.attributes {
		attrs[attr.Name] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}
	value, hasAttr := attrs[name]
	if !hasAttr {
		return nil, errors.Errorf("User does not have attribute '%s'", name)
	}
	return &value, nil
}

func TestCanRegisterAttributes(t *testing.T) {
	negativeTests(t)
	positiveTests(t)
}

func negativeTests(t *testing.T) {
	var err error

	requestedAttrs := []api.Attribute{}
	user := getUser("testuser", []api.Attribute{})
	registrar := getUser("admin", []api.Attribute{})

	// Negative Case: Registrar does not have 'hf.Registrar.Attribute'
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer,client",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar does not have 'hf.Registrar.Attribute'")

	// Negative Case: Registrar does not have any value for 'hf.Registrar.Attribute'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar does not have any value for 'hf.Registrar.Attribute'")

	// Negative Case: Registrar does not have 'hf.Registrar.Roles' as a value for 'hf.Registrar.Attribute'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Revoker",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar does not have any value for 'hf.Registrar.Attribute'")

	// Negative Case: Registrar has 'hf.Registrar.Roles' as a value for 'hf.Registrar.Attribute' but does not own 'hf.Registrar.Roles'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar has 'hf.Registrar.Roles' as a value for 'hf.Registrar.Attribute' but does not own 'hf.Registrar.Roles'")

	// Negative Case: Registrar has 'hf.Registrar.Roles' with a value of 'peer', can't register a request for 'hf.Registrar.Roles=peer,client'. Must
	// be a equal or subset.
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer,client",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar can't register a request for 'hf.Registrar.Roles=peer,client'")

	// Negative Case: User has 'hf.Registrar.Roles' with a value of 'peer', can't register a request for 'hf.Registrar.DeletgateRoles=peer,client'. Must
	// be a equal or subset.
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "client,peer",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles,hf.Registrar.DelegateRoles",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "peer,client",
		},
	}
	user = getUser("testuser", []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar can't register a request for 'hf.Registrar.DeletgateRoles=peer,client'")

	// Negative Case: Registrar does not have 'hf.Revoker' as a value for 'hf.Registrar.Attributes'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "client,peer",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles,hf.Registrar.DelegateRoles,hf.Registrar.Attributes",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar does not have 'hf.Revoker' as a value for 'hf.Registrar.Attributes'")

	// Negative Case: User requesting value of 'hf.Revoker' for 'hf.Registrar.Attribute' attribute, but the
	// user does not own 'hf.Revoker'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "client,peer",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles,hf.Registrar.DelegateRoles,hf.Registrar.Attributes,hf.Revoker",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, user does not own 'hf.Revoker'")

	// Negative Case: User is nil (i.e. New registration request, not a modification) requesting value of 'hf.Revoker' for 'hf.Registrar.Attribute' attribute, but the
	// user is not being registered with 'hf.Revoker'
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	user = nil
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, user not being registered with 'hf.Revoker', must possess attribute to have as value for 'hf.Registrar.Attribute'")

	// Negative Case: User requesting attribute 'hf.FakeAttribute' using reserved 'hf.' attribute fix for an
	// invalid attribute name
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  "hf.FakeAttribute",
			Value: "fakeValue",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  "hf.FakeAttribute",
			Value: "fakeValue2",
		},
	}
	user = getUser("testuser", []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, 'hf.FakeAttribute' is not existing reservered attribute")

	// BOOLEAN ATTRIBUTES
	// Negative Case: Registrar registered with a non-bool value, should result in an error when registering
	// a boolean attribute
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "nonbool_value",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "false",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar registered with a non-bool value")

	// Negative Case: Registrar registered with a false value, should result in an error when registering
	// a boolean attribute as true
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "false",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar registered with a false value")

	// Negative Case: Registrar requesting a non-boolean value
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "nonbool_value",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar requesting a non-boolean value")

	// Negative Case: Registrar requesting to delete an attribute it doesn't posses
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar requesting to delete an attribute it doesn't posses")

	// Negative Case: Registrar requesting to modify a fixed attribute
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Type,
			Value: "client",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar requesting an attribute that cannot be modified")

	// Negative Case: Registrar requesting to modify a fixed attribute
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Affiliation,
			Value: "client",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar requesting an attribute that cannot be modified")

	// Negative Case: Registrar requesting to modify a fixed attribute
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  EnrollmentID,
			Value: "client",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, registrar requesting an attribute that cannot be modified")

	// CUSTOM ATTRIBUTE
	// Registrar requesting custom attribute that does not match pattern that is allowed
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "custom.*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  "CustomAttr",
			Value: "CustomValue",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.Error(t, err, "Should fail, requested attribute does not match pattern")
}

func positiveTests(t *testing.T) {
	var err error

	requestedAttrs := []api.Attribute{}
	user := getUser("testuser", []api.Attribute{})
	registrar := getUser("admin", []api.Attribute{})

	// Requesting no attributes
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Failed to register attribute")

	// Registrar owns hf.IntermediateCA and is allowed to register it
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Failed to register attribute")

	// Registrar can give user to permission to register 'hf.IntermediateCA'
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.IntermediateCA",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Failed to register attribute")

	// Valid value for hf.Registrar.DelegateRoles requested
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "client,peer",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Registrar.Roles,hf.Registrar.DelegateRoles",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  DelegateRoles,
			Value: "peer",
		},
	}
	user = getUser("testuser", []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer",
		},
	})
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Failed to register attribute")

	// Registrar requesting to delete an attribute it
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  IntermediateCA,
			Value: "",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Registrar failed to delete attribute")

	// Registrar requesting to delete an attribute it
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "peer,client",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Roles,
			Value: "",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Registrar failed to delete attribute")

	// Registrar requesting to register a custom attribute, no ownership required
	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "custom.*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  "custom.Attr",
			Value: "customValue",
		},
	}
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Registrar failed to register custom attribute")

	registrar = getUser("admin", []api.Attribute{
		api.Attribute{
			Name:  Revoker,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "*",
		},
	})
	requestedAttrs = []api.Attribute{
		api.Attribute{
			Name:  Revoker,
			Value: "true",
		},
		api.Attribute{
			Name:  RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	user = nil
	err = CanRegisterRequestedAttributes(requestedAttrs, user, registrar)
	assert.NoError(t, err, "Should not fail, user being registered with 'hf.Revoker', must possess attribute to have as value for 'hf.Registrar.Attribute'")
}

func TestCaseInsensitiveAttr(t *testing.T) {
	_, err := getAttributeControl("hf.Registrar.Roles")
	assert.NoError(t, err, "Should not result in error, if using mix of uppercase and lowercase")

	_, err = getAttributeControl("hf.registrar.roles")
	assert.NoError(t, err, "Should not result in error, if using all lowercase")

	_, err = getAttributeControl("hf.Revoker")
	assert.NoError(t, err, "Should not result in error, if using mix of uppercase and lowercase")

	_, err = getAttributeControl("hf.revoker")
	assert.NoError(t, err, "Should not result in error, if using all lowercase")
}
