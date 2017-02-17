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

package util

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// RegisterFlags registers flags for all fields in config
func RegisterFlags(flags *pflag.FlagSet, config interface{}) error {
	fr := &flagRegistrar{Flags: flags}
	return ParseObj(config, fr.Register)
}

type flagRegistrar struct {
	Flags *pflag.FlagSet
}

func (fr *flagRegistrar) Register(f *Field) (err error) {
	// Don't register non-leaf fields
	if !f.Leaf {
		return nil
	}
	// Don't register fields with no address
	if f.Addr == nil {
		log.Warningf("Not registering flag for '%s' because it is not addressable\n", f.Path)
		return nil
	}
	skip := f.Tag.Get("skip")
	if skip != "" {
		return nil
	}
	help := f.Tag.Get("help")
	opt := f.Tag.Get("opt")
	def := f.Tag.Get("def")
	switch f.Kind {
	case reflect.String:
		fr.Flags.StringVarP(f.Addr.(*string), f.Path, opt, def, help)
	case reflect.Int:
		var intDef int
		if def != "" {
			intDef, err = strconv.Atoi(def)
			if err != nil {
				return fmt.Errorf("Invalid integer value in 'def' tag of %s field", f.Path)
			}
		}
		fr.Flags.IntVarP(f.Addr.(*int), f.Path, opt, intDef, help)
	case reflect.Bool:
		var boolDef bool
		if def != "" {
			boolDef, err = strconv.ParseBool(def)
			if err != nil {
				return fmt.Errorf("Invalid boolean value in 'def' tag of %s field", f.Path)
			}
		}
		fr.Flags.BoolVarP(f.Addr.(*bool), f.Path, opt, boolDef, help)
	default:
		//log.Warningf("Not registering flag for '%s' because it is a currently unsupported type: %s\n",
		//	f.Path, f.Kind)
		return nil
	}
	bindFlag(fr.Flags, f.Path)
	return nil
}

// CmdRunBegin is called at the beginning of each cobra run function
func CmdRunBegin() {
	// If -d or --debug, set debug logging level
	if viper.GetBool("debug") {
		log.Level = log.LevelDebug
	}
}

// FlagString sets up a flag for a string, binding it to its name
func FlagString(flags *pflag.FlagSet, name, short string, def string, desc string) {
	flags.StringP(name, short, def, desc)
	bindFlag(flags, name)
}

// FlagInt sets up a flag for an int, binding it to its name
func FlagInt(flags *pflag.FlagSet, name, short string, def int, desc string) {
	flags.IntP(name, short, def, desc)
	bindFlag(flags, name)
}

// FlagBool sets up a flag for a bool, binding it to its name
func FlagBool(flags *pflag.FlagSet, name, short string, def bool, desc string) {
	flags.BoolP(name, short, def, desc)
	bindFlag(flags, name)
}

// common binding function
func bindFlag(flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(fmt.Errorf("failed to lookup '%s'", name))
	}
	viper.BindPFlag(name, flag)
}
