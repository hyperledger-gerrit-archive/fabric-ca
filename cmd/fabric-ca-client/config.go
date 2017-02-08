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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"
)

const (
	longName     = "Hyperledger Fabric Certificate Authority Client"
	shortName    = "fabric-ca client"
	cmdName      = "fabric-ca-client"
	envVarPrefix = "FABRIC_CA_CLIENT"
	homeEnvVar   = "FABRIC_CA_CLIENT_HOME"
)

const (
	defaultCfg = `
   #############################################################################
   #   This is a configuration file for the fabric-ca-client command.
   #
   #   COMMAND LINE ARGUMENTS AND ENVIRONMENT VARIABLES
   #   ------------------------------------------------
   #   Each configuration element can be overridden via command line
   #   arguments or environment variables.  The precedence for determining
   #   the value of each element is as follows:
   #   1) command line argument
   #      Examples:
   #      a) --url https://localhost:7054
   #         To set the fabric-ca server url
   #   2) environment variable
   #      Examples:
   #      a) FABRIC_CA_CLIENT_URL=https://localhost:7054
   #         To set the fabric-ca server url
   #   3) configuration file
   #   4) default value (if there is one)
   #      All default values are shown beside each element below.
   #
   #   FILE NAME ELEMENTS
   #   ------------------
   #   All filename elements below end with the word "file".
   #   For example, see "certfile" and "keyfile" in the "ca" section.
   #   The value of each filename element can be a simple filename, a
   #   relative path, or an absolute path.  If the value is not an
   #   absolute path, it is interpretted as being relative to the location
   #   of this configuration file.
   #
   #############################################################################

   #############################################################################
   # Client Configuration
   #############################################################################

   # URL of the Fabric-ca-server (default: http://localhost:7054)
   serverURL: <<<URL>>>

   #############################################################################
   #    TLS section for the client's listenting port
   #############################################################################
   tls:
      # Enable TLS (default: false)
      enabled: false

      # TLS for the client's listenting port (default: false)
      caFile:
      certFile:
      keyFile:

`
)

var (
	// cfgFileName is the name of the client's config file
	cfgFileName string
)

func configInit() error {

	var err error

	// Make the config file name absolute
	if !filepath.IsAbs(cfgFileName) {
		cfgFileName, err = filepath.Abs(cfgFileName)
		if err != nil {
			return fmt.Errorf("Failed to get full path of config file: %s", err)
		}
	}

	// If the config file doesn't exist, create a default one
	if !util.FileExists(cfgFileName) {
		err = createDefaultConfigFile()
		if err != nil {
			return fmt.Errorf("Failed to create default configuration file: %s", err)
		}
		log.Infof("Created a default configuration file at %s", cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", cfgFileName)
	}

	// Call viper to read the config
	viper.SetConfigFile(cfgFileName)
	viper.AutomaticEnv() // read in environment variables that match
	err = viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Failed to read config file: %s", err)
	}

	return nil

}

// Get the default path for the config file to display in usage message
func getDefaultConfigFile() (string, error) {
	var fname = fmt.Sprintf("%s-config.yaml", cmdName)
	// First check home env variables
	home := os.Getenv("FABRIC_CA_CLIENT_HOME")
	if home == "" {
		home = os.Getenv("FABRIC_CA_HOME")
	}

	if home != "" {
		home = path.Join(home, ".fabric-ca-client")
		return path.Join(home, fname), nil
	}

	home = os.Getenv("HOME")
	home = path.Join(home, ".fabric-ca-client")
	return path.Join(home, fname), nil
}

func createDefaultConfigFile() error {
	// Create a default config, if URL provided via CLI or envar update config files
	url := viper.GetString("url")
	if url == "" {
		url = getDefaultServerURL()
	}

	// Do string subtitution to get the default config
	cfg := strings.Replace(defaultCfg, "<<<URL>>>", url, 1)
	// Now write the file
	err := os.MkdirAll(filepath.Dir(cfgFileName), 0755)
	if err != nil {
		return err
	}
	// Now write the file
	return ioutil.WriteFile(cfgFileName, []byte(cfg), 0755)
}

func getDefaultServerURL() string {
	url := "http://localhost:7054"
	return url
}
