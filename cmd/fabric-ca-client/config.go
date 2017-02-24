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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/tls"
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
	defaultCfgTemplate = `
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
#			 b) --tls.client.certfile certfile.pem
#					To set the client certificate for TLS
#   2) environment variable
#      Examples:
#      a) FABRIC_CA_CLIENT_URL=https://localhost:7054
#         To set the fabric-ca server url
#			 b) FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE=certfile.pem
#					To set the client certificate for TLS
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
URL: <<<URL>>>

#############################################################################
#    TLS section for the client's listenting port
#############################################################################
tls:
  # Enable TLS (default: false)
  enabled: false

  # TLS for the client's listenting port (default: false)
  certfiles: 				# Comma Separated (e.g. root.pem, root2.pem)
  client:
    certfile:
    keyfile:

#############################################################################
#  Certificate Signing Request section for generating the CSR for
#  an enrollment certificate (ECert)
#############################################################################
csr:
  cn: <<<ENROLLMENT_ID>>>
  names:
    - C: US
      ST: "North Carolina"
      L:
      O: Hyperledger
      OU: Fabric
  hosts:
    - <<<MYHOST>>>
  ca:
    pathlen:
    pathlenzero:
    expiry:

#############################################################################
#  Registration section used to register a new user with fabric-ca server
#############################################################################
id:
  name:
  type:
  group:
  attributes:
    - name:
      value:
`
)

var (
	// cfgFileName is the name of the client's config file
	cfgFileName string

	// clientCfg is the client's config
	clientCfg *lib.ClientConfig
)

func configInit() error {

	var err error

	if cfgFileName != "" {
		log.Infof("User provided config file: %s\n", cfgFileName)
	}

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
	viper.SetConfigType("yaml")
	viper.AutomaticEnv() // read in environment variables that match
	err = viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Failed to read config file: %s", err)
	}

	// Unmarshal the config into 'clientCfg'
	err = viper.Unmarshal(clientCfg)
	if err != nil {
		util.Fatal("Failed to unmarshall client config: %s", err)
	}

	purl, err := url.Parse(clientCfg.URL)
	if err != nil {
		return err
	}

	clientCfg.TLS.Enabled = purl.Scheme == "https"

	processCertFiles(&clientCfg.TLS)
	if clientCfg.ID.Attr != "" {
		processAttributes()
	}
	return nil
}

func createDefaultConfigFile() error {
	// Create a default config, if URL provided via CLI or envar update config files
	var cfg string
	fabricCAServerURL := viper.GetString("url")
	if fabricCAServerURL == "" {
		fabricCAServerURL = util.GetServerURL()
	} else {
		URL, err := url.Parse(fabricCAServerURL)
		if err != nil {
			return err
		}
		fabricCAServerURL = fmt.Sprintf("%s://%s", URL.Scheme, URL.Host) // URL.Scheme + "://" + URL.Host
	}

	myhost := viper.GetString("myhost")

	// Do string subtitution to get the default config
	cfg = strings.Replace(defaultCfgTemplate, "<<<URL>>>", fabricCAServerURL, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)

	// Now write the file
	err := os.MkdirAll(filepath.Dir(cfgFileName), 0755)
	if err != nil {
		return err
	}
	// Now write the file
	return ioutil.WriteFile(cfgFileName, []byte(cfg), 0755)
}

// processCertFiles parses comma seperated string to generate a string array
func processCertFiles(cfg *tls.ClientTLSConfig) {
	CertFiles := strings.Split(cfg.CertFiles, ",")
	cfg.CertFilesList = make([]string, 0)

	for i := range CertFiles {
		cfg.CertFilesList = append(cfg.CertFilesList, strings.TrimSpace(CertFiles[i]))
	}
}

// processAttributes parses attributes from command line
func processAttributes() {
	splitAttr := strings.Split(clientCfg.ID.Attr, "=")
	clientCfg.ID.Attributes[0].Name = splitAttr[0]
	clientCfg.ID.Attributes[0].Value = strings.Join(splitAttr[1:], "")
}
