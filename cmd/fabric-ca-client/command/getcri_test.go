/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"reflect"
	"testing"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewGetCRICmd(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	getcricmd := newGetCRICmd(cmd)
	assert.NotNil(t, getcricmd)
}

func TestGetCommandCRI(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	getcricmd := newGetCRICmd(cmd)
	cobraCmd := getcricmd.getCommand()
	assert.NotNil(t, cobraCmd)
	assert.Equal(t, cobraCmd.Name(), "getcri")
	assert.Equal(t, cobraCmd.Short, GetCRICmdShortDesc)
	assert.Equal(t, cobraCmd.Long, GetCRICmdShortDesc)
	assert.Equal(t, cobraCmd.Use, GetCRICmdUsage)

	f1 := reflect.ValueOf(cobraCmd.PreRunE)
	f2 := reflect.ValueOf(getcricmd.preRunGetCRI)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "PreRunE function variable of the getcri cobra command must be preRunGetCRI function of the getCRICmd struct")

	f1 = reflect.ValueOf(cobraCmd.RunE)
	f2 = reflect.ValueOf(getcricmd.runGetCRI)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "RunE function variable of the getcri cobra command must be runGetCRI function of the getCRICmd struct")
}

func TestBadConfigPreRunGetCRI(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	getcricmd := newGetCRICmd(cmd)
	cobraCmd := getcricmd.getCommand()
	err := getcricmd.preRunGetCRI(cobraCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Failed to initialize config")
}

func TestGoodConfigPreRunGetCRI(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	getcricmd := newGetCRICmd(cmd)
	cobraCmd := getcricmd.getCommand()
	err := getcricmd.preRunGetCRI(cobraCmd, []string{})
	assert.NoError(t, err)
}
