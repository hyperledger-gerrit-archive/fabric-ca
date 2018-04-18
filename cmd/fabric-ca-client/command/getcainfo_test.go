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

	. "github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewGetCACertCmd(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	getcacertCmd := NewGetCAInfoCmd(cmd)
	assert.NotNil(t, getcacertCmd)
	assert.Equal(t, getcacertCmd.Name(), "getcainfo")
	assert.Equal(t, getcacertCmd.Short, GetCAInfoCmdShortDesc)
	assert.Equal(t, getcacertCmd.Use, GetCAInfoCmdUsage)
}

func TestPreRunGetCACertBadConfig(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	getcainfoCmd := NewGetCAInfoCmd(cmd)
	err := getcainfoCmd.PreRunE(getcainfoCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Failed to initialize config")
}

func TestPreRunGetCACertGoodConfig(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetClientCfg").Return(&lib.ClientConfigImpl{})
	getcainfoCmd := NewGetCAInfoCmd(cmd)
	err := getcainfoCmd.PreRunE(getcainfoCmd, []string{})
	assert.NoError(t, err)
}
