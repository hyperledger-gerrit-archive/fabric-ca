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
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Field is a field of an arbitrary struct
type Field struct {
	Name  string
	Path  string
	Type  reflect.Type
	Kind  reflect.Kind
	Leaf  bool
	Depth int
	Tag   reflect.StructTag
	Value interface{}
	Addr  interface{}
}

// ParseObj parses an object structure, calling back with field info
// for each field
func ParseObj(obj interface{}, cb func(*Field) error) error {
	if cb == nil {
		return errors.New("nil callback")
	}
	return parse(obj, cb, nil)
}

func parse(ptr interface{}, cb func(*Field) error, parent *Field) error {
	var path string
	var depth int
	v := reflect.ValueOf(ptr).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		vf := v.Field(i)
		tf := t.Field(i)
		name := strings.ToLower(tf.Name)
		if tf.Name[0] == name[0] {
			continue // skip unexported fields
		}
		if parent != nil {
			path = fmt.Sprintf("%s.%s", parent.Path, name)
			depth = parent.Depth + 1
		} else {
			path = name
		}
		kind := vf.Kind()
		leaf := kind != reflect.Struct && kind != reflect.Ptr
		field := &Field{
			Name:  name,
			Path:  path,
			Type:  tf.Type,
			Kind:  kind,
			Leaf:  leaf,
			Depth: depth,
			Tag:   tf.Tag,
			Value: vf.Interface(),
			Addr:  vf.Addr().Interface(),
		}
		err := cb(field)
		if err != nil {
			return err
		}
		if kind == reflect.Struct {
			err := parse(field.Addr, cb, field)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckForMissingValues checks the CA config struct for missing values and
// replaces them with value from server config struct
func CheckForMissingValues(src, dst interface{}) {
	s := reflect.ValueOf(src).Elem()
	d := reflect.ValueOf(dst).Elem()

	for i := 0; i < s.NumField(); i++ {
		sf := s.Field(i)
		kind := sf.Kind()
		df := d.Field(i)

		switch kind {
		case reflect.String:
			if sf.String() == "" {
				sf.SetString(df.String())
			}
		case reflect.Slice:
			if sf.Len() == 0 {
				sf.Set(df)
			}
		case reflect.Ptr:
			if sf.IsNil() {
				sf.Set(df)
			}
		case reflect.Struct:
			CheckForMissingValues(sf.Addr().Interface(), df.Addr().Interface())
		}
	}
}
