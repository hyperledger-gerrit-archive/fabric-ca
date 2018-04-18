/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package command_test

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	libmocks "github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewEnrollCmd(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	enrollCmd := NewEnrollCmd(cmd)
	assert.NotNil(t, enrollCmd)
	assert.Equal(t, enrollCmd.Name(), "enroll")
	assert.Equal(t, enrollCmd.Short, EnrollCmdShortDesc)
	assert.Equal(t, enrollCmd.Long, EnrollCmdLongDesc)
	assert.Equal(t, enrollCmd.Use, EnrollCmdUsage)
}

func TestPreRunEnrollBadConfig(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	enrollCmd := NewEnrollCmd(cmd)
	err := enrollCmd.PreRunE(enrollCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Failed to initialize config")
}

func TestPreRunEnrollGoodConfig(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetClientCfg").Return(&libmocks.ClientConfig{})
	enrollCmd := NewEnrollCmd(cmd)
	err := enrollCmd.PreRunE(enrollCmd, []string{})
	assert.NoError(t, err)
}

func TestRunEnrollError(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetCfgFileName").Return("fabric-ca-client-cfg.yml")
	cfg := new(libmocks.ClientConfig)
	cmd.On("GetClientCfg").Return(cfg)
	cfg.On("GetURL").Return("localhost:7064")
	cfg.On("GetEnrollmentRequest").Return(&api.EnrollmentRequest{})
	cfg.On("Enroll", cfg.GetURL(), ".").Return(nil, errors.New("Enroll failed"))
	enrollCmd := NewEnrollCmd(cmd)
	err := enrollCmd.RunE(enrollCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Enroll failed")
}

// func TestGoodConfigRunEnroll(t *testing.T) {
// 	cmd := new(mocks.Command)
// 	cmd.On("GetViper").Return(viper.New())
// 	cmd.On("ConfigInit").Return(nil)
// 	cmd.On("GetCfgFileName").Return("fabric-ca-client-cfg.yml")
// 	cfg := new(mocks.Config)
// 	cmd.On("GetClientCfg").Return(cfg)
// 	cfg.On("GetURL").Return("localhost:7064")
// 	id := &lib.Identity{
// 		name:
// 	}
// 	resp := &lib.EnrollmentResponse{}
// 	cfg.On("Enroll", cfg.GetURL(), ".").Return(resp, nil)
// 	enrollCmd := NewEnrollCmd(cmd)
// 	cobraCmd := enrollCmd.GetCommand()
// 	err := enrollCmd.RunEnroll(cobraCmd, []string{})
// 	assert.NoError(t, err)
// }
