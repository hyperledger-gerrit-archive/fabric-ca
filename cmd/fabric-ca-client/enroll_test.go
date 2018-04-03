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

package main

import (
	"reflect"
	"testing"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewEnrollCmd(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	enrollCmd := newEnrollCmd(cmd)
	assert.NotNil(t, enrollCmd)
}

func TestGetEnrollCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	enrollCmd := newEnrollCmd(cmd)
	cobraCmd := enrollCmd.getCommand()
	assert.NotNil(t, cobraCmd)
	assert.Equal(t, cobraCmd.Name(), "enroll")
	assert.Equal(t, cobraCmd.Short, enrollCmdShortDesc)
	assert.Equal(t, cobraCmd.Long, enrollCmdLongDesc)
	assert.Equal(t, cobraCmd.Use, enrollCmdUsage)

	f1 := reflect.ValueOf(cobraCmd.PreRunE)
	f2 := reflect.ValueOf(enrollCmd.preRunEnroll)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "PreRunE function variable of the getcacert cobra command must be preRunEnroll function of the enrollCmd struct")

	f1 = reflect.ValueOf(cobraCmd.RunE)
	f2 = reflect.ValueOf(enrollCmd.runEnroll)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "RunE function variable of the getcacert cobra command must be runEnroll function of the enrollCmd struct")
}

func TestBadConfigPreRunEnroll(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	enrollCmd := newEnrollCmd(cmd)
	cobraCmd := enrollCmd.getCommand()
	err := enrollCmd.preRunEnroll(cobraCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Failed to initialize config")
}

func TestGoodConfigPreRunEnroll(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	enrollCmd := newEnrollCmd(cmd)
	cobraCmd := enrollCmd.getCommand()
	err := enrollCmd.preRunEnroll(cobraCmd, []string{})
	assert.NoError(t, err)
}
