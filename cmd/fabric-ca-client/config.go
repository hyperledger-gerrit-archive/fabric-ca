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

	"reflect"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
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
#      b) --tls.client.certfile certfile.pem
#         To set the client certificate for TLS
#   2) environment variable
#      Examples:
#      a) FABRIC_CA_CLIENT_URL=https://localhost:7054
#         To set the fabric-ca server url
#      b) FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE=certfile.pem
#         To set the client certificate for TLS
#   3) configuration file
#   4) default value (if there is one)
#      All default values are shown beside each element below.
#
#   FILE NAME ELEMENTS
#   ------------------
#   The value of all fields whose name ends with "file" or "files" are
#   name or names of other files.
#   For example, see "tls.certfiles" and "tls.client.certfile".
#   The value of each of these fields can be a simple filename, a
#   relative path, or an absolute path.  If the value is not an
#   absolute path, it is interpretted as being relative to the location
#   of this configuration file.
#
#############################################################################

#############################################################################
# Client Configuration
#############################################################################

# URL of the Fabric-ca-server (default: http://localhost:7054)
url: <<<URL>>>

# Membership Service Provider (MSP) directory
# This is useful when the client is used to enroll a peer or orderer, so
# that the enrollment artifacts are stored in the format expected by MSP.
mspdir:

#############################################################################
#    TLS section for secure socket connection
#
#  certfiles - PEM-encoded list of trusted root certificate files
#  client:
#    certfile - PEM-encoded certificate file for when client authentication
#    is enabled on server
#    keyfile - PEM-encoded key file for when client authentication
#    is enabled on server
#############################################################################
tls:
  # TLS section for secure socket connection
  certfiles:
  client:
    certfile:
    keyfile:

#############################################################################
#  Certificate Signing Request section for generating the CSR for
#  an enrollment certificate (ECert)
#
#  cn - Used by CAs to determine which domain the certificate is to be generated for
#  names -  A list of name objects. Each name object should contain at least one
#  "C", "L", "O", "OU", or "ST" value (or any combination of these). These values are:
#      "C": country
#      "L": locality or municipality (such as city or town name)
#      "O": organisation
#      "OU": organisational unit, such as the department responsible for owning the key;
#      it can also be used for a "Doing Business As" (DBS) name
#      "ST": the state or province
#  hosts - A list of space-separated host names which the certificate should be valid for
#
#  NOTE: The serialnumber field below, if specified, becomes part of the issued
#  certificate's DN (Distinguished Name).  For example, one use case for this is
#  a company with its own CA (Certificate Authority) which issues certificates
#  to its employees and wants to include the employee's serial number in the DN
#  of its issued certificates.
#
#  WARNING: This serialnumber field should not be confused with the certificate's
#  serial number which is set by the CA but is not a component of the
#  certificate's DN.
#############################################################################
csr:
  cn: <<<ENROLLMENT_ID>>>
  serialnumber:
  names:
    - C: US
      ST: North Carolina
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
#  Registration section used to register a new identity with fabric-ca server
#
#  name - Unique name of the identity
#  type - Type of identity being registered (e.g. 'peer, app, user')
#  affiliation - The identity's affiliation
#  maxenrollments - The maximum number of times the secret can be reused to enroll.
#                   Specially, -1 means unlimited; 0 means disabled
#  attributes - List of name/value pairs of attribute for identity
#############################################################################
id:
  name:
  type:
  affiliation:
  maxenrollments: -1
  attributes:
    - name:
      value:

#############################################################################
#  Enrollment section used to enroll an identity with fabric-ca server
#
#  profile - Name of the signing profile to use in issuing the certificate
#  label - Label to use in HSM operations
#############################################################################
enrollment:
  profile:
  label:

#############################################################################
# Name of the CA to connect to within the fabric-ca server
#############################################################################
caname:

#############################################################################
# BCCSP (BlockChain Crypto Service Provider) section allows to select which
# crypto implementation library to use
#############################################################################
bccsp:
    default: SW
    sw:
        hash: SHA2
        security: 256
        filekeystore:
            # The directory used for the software file-based keystore
            keystore: msp/keystore
`
)

func (c *ClientCmd) configInit() error {
	var err error

	if c.cfgFileName != "" {
		log.Infof("User provided config file: %s\n", c.cfgFileName)
	}

	// Make the config file name absolute
	if !filepath.IsAbs(c.cfgFileName) {
		c.cfgFileName, err = filepath.Abs(c.cfgFileName)
		if err != nil {
			return fmt.Errorf("Failed to get full path of config file: %s", err)
		}
	}

	// Commands other than 'enroll' and 'getcacert' require that client already
	// be enrolled
	if c.requiresEnrollment() {
		err = checkForEnrollment(c.cfgFileName, c.clientCfg)
		if err != nil {
			return err
		}
	}

	// If the config file doesn't exist, create a default one if enroll
	// command being executed. Enroll should be the first command to be
	// executed, and furthermore the default configuration file requires
	// enrollment ID to populate CN field which is something the enroll
	// command requires
	if c.shouldCreateDefaultConfig() {
		if !util.FileExists(c.cfgFileName) {
			err = c.createDefaultConfigFile()
			if err != nil {
				return fmt.Errorf("Failed to create default configuration file: %s", err)
			}
			log.Infof("Created a default configuration file at %s", c.cfgFileName)
		}
	} else {
		log.Infof("Configuration file location: %s", c.cfgFileName)
	}

	// Call viper to read the config
	viper.SetConfigFile(c.cfgFileName)
	viper.AutomaticEnv() // read in environment variables that match
	if util.FileExists(c.cfgFileName) {
		err = viper.ReadInConfig()
		if err != nil {
			return fmt.Errorf("Failed to read config file: %s", err)
		}
	}

	// Unmarshal the config into 'clientCfg'
	// When viper bug https://github.com/spf13/viper/issues/327 is fixed
	// and vendored, the work around code can be deleted.
	viperIssue327WorkAround := true
	if viperIssue327WorkAround {
		sliceFields := []string{
			"csr.hosts",
			"tls.certfiles",
		}
		err = util.ViperUnmarshal(c.clientCfg, sliceFields, viper.GetViper())
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", c.cfgFileName, err)
		}
	} else {
		err = viper.Unmarshal(c.clientCfg)
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", c.cfgFileName, err)
		}
	}

	purl, err := url.Parse(c.clientCfg.URL)
	if err != nil {
		return err
	}

	c.clientCfg.TLS.Enabled = purl.Scheme == "https"

	err = processAttributes(c.cfgAttrs, c.clientCfg)
	if err != nil {
		return err
	}

	err = c.processCsrNames()
	if err != nil {
		return err
	}

	// Check for separaters and insert values back into slice
	normalizeStringSlices(c.clientCfg)

	return nil
}

func (c *ClientCmd) createDefaultConfigFile() error {
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
		fabricCAServerURL = fmt.Sprintf("%s://%s", URL.Scheme, URL.Host)
	}

	myhost := viper.GetString("myhost")

	// Do string subtitution to get the default config
	cfg = strings.Replace(defaultCfgTemplate, "<<<URL>>>", fabricCAServerURL, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)

	var user string
	var err error

	if c.requiresUser() {
		user, _, err = util.GetUser()
		if err != nil {
			return err
		}
	} else {
		user = ""
	}
	cfg = strings.Replace(cfg, "<<<ENROLLMENT_ID>>>", user, 1)

	// Create the directory if necessary
	cfgDir := filepath.Dir(c.cfgFileName)
	err = os.MkdirAll(cfgDir, 0755)
	if err != nil {
		return err
	}
	// Now write the file
	return ioutil.WriteFile(c.cfgFileName, []byte(cfg), 0755)
}

// processAttributes parses attributes from command line or env variable
func processAttributes(cfgAttrs []string, cfg *lib.ClientConfig) error {
	if cfgAttrs != nil {
		cfg.ID.Attributes = make([]api.Attribute, len(cfgAttrs))
		for idx, attr := range cfgAttrs {
			sattr := strings.SplitN(attr, "=", 2)
			if len(sattr) != 2 {
				return fmt.Errorf("Attribute '%s' is missing '=' ; it must be of the form <name>=<value>", attr)
			}
			cfg.ID.Attributes[idx].Name = sattr[0]
			cfg.ID.Attributes[idx].Value = sattr[1]
		}
	}
	return nil
}

// processAttributes parses attributes from command line or env variable
func (c *ClientCmd) processCsrNames() error {
	if c.cfgCsrNames != nil {
		c.clientCfg.CSR.Names = make([]csr.Name, len(c.cfgCsrNames))
		for idx, name := range c.cfgCsrNames {
			sname := strings.SplitN(name, "=", 2)
			if len(sname) != 2 {
				return fmt.Errorf("CSR name/value '%s' is missing '=' ; it must be of the form <name>=<value>", name)
			}
			v := reflect.ValueOf(&c.clientCfg.CSR.Names[idx]).Elem().FieldByName(sname[0])
			if v.IsValid() {
				v.SetString(sname[1])
			} else {
				return fmt.Errorf("Invalid CSR name: '%s'", sname[0])
			}
		}
	}
	return nil
}

func checkForEnrollment(cfgFileName string, cfg *lib.ClientConfig) error {
	log.Debug("Checking for enrollment")
	client := lib.Client{
		HomeDir: filepath.Dir(cfgFileName),
		Config:  cfg,
	}
	return client.CheckEnrollment()
}

func normalizeStringSlices(cfg *lib.ClientConfig) {
	fields := []*[]string{
		&cfg.CSR.Hosts,
		&cfg.TLS.CertFiles,
	}
	for _, namePtr := range fields {
		norm := util.NormalizeStringSlice(*namePtr)
		*namePtr = norm
	}
}
