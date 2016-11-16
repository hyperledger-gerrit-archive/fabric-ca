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

package server

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/viper"
)

// Bootstrap is used for bootstrapping database
type Bootstrap struct {
	cfg *Config
}

// BootstrapDB is a constructor to bootstrap the database at server startup
func BootstrapDB() *Bootstrap {
	b := new(Bootstrap)
	b.cfg = CFG
	return b
}

// PopulateUsersTable populates the user table with the users defined in the server configuration file
func (b *Bootstrap) PopulateUsersTable() error {
	log.Debug("populateUsersTable")
	for name, info := range b.cfg.Users {
		metaDataBytes, _ := json.Marshal(info.Attributes)

		id := name
		userType := info.Type
		group := info.Group
		metadata := string(metaDataBytes)
		registrar := ""
		pass := info.Pass

		reg := NewRegisterUser()
		reg.RegisterUser(id, userType, group, metadata, registrar, pass)
	}
	return nil
}

func (b *Bootstrap) populateGroup(name, parent, key string, level int) {
	b.registerGroup(name, parent)
	newKey := key + "." + name

	if level == 0 {
		affiliationGroups := viper.GetStringSlice(newKey)
		for ci := range affiliationGroups {
			b.registerGroup(affiliationGroups[ci], name)
		}
	} else {
		affiliationGroups := viper.GetStringMapString(newKey)
		for childName := range affiliationGroups {
			b.populateGroup(childName, name, newKey, level-1)
		}
	}
}

// PopulateGroupsTable populates affiliation groups table based on the groups defined in the server configuration file
func (b *Bootstrap) PopulateGroupsTable() {
	log.Debug("PopulateGroupsTable")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	base := filepath.Base(b.cfg.ConfigFile)
	filename := strings.Split(base, ".")
	name := filename[0]
	typ := filename[1]

	viper.SetConfigName(name)
	viper.SetConfigType(typ)

	configPath := filepath.Dir(b.cfg.ConfigFile)
	viper.AddConfigPath(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Fatal error when reading cop config file: %s", err)
	}

	key := "groups"
	affiliationGroups := viper.GetStringMapString(key)
	if len(affiliationGroups) == 0 {
		log.Info("No groups specified in configuration file")
	}
	for name := range affiliationGroups {
		b.populateGroup(name, "", key, 1)
	}
}

func (b *Bootstrap) registerGroup(name string, parentName string) error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Debug("Registering affiliation group " + name + " parent " + parentName + ".")

	var err error
	_, _, err = b.cfg.DBAccessor.GetGroup(name)
	if err == nil {
		log.Error("Group already registered")
		return errors.New("Group already registered")
	}

	err = b.cfg.DBAccessor.InsertGroup(name, parentName)
	if err != nil {
		log.Error(err)
	}

	return err

}
