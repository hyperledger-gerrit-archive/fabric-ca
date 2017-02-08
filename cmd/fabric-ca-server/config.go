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
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"
)

const (
	longName     = "Hyperledger Fabric Certificate Authority Server"
	shortName    = "fabric-ca server"
	cmdName      = "fabric-ca-server"
	envVarPrefix = "FABRIC_CA_SERVER"
	homeEnvVar   = "FABRIC_CA_SERVER_HOME"
)

const (
	defaultCfgTemplate = `
   #############################################################################
   #   This is a configuration file template for the fabric-ca-server command.
   #
   #   COMMAND LINE ARGUMENTS AND ENVIRONMENT VARIABLES
   #   ------------------------------------------------
   #   Each configuration element can be overridden via command line
   #   arguments or environment variables.  The precedence for determining
   #   the value of each element is as follows:
   #   1) command line argument
   #      Examples:
   #      a) --port 443
   #         To set the listening port
   #      b) --ca-keyfile ../mykey.pem
   #         To set the "keyfile" element in the "ca" section below;
   #         note the '-' separator character.
   #   2) environment variable
   #      Examples:
   #      a) FABRIC_CA_SERVER_PORT=443
   #         To set the listening port
   #      b) FABRIC_CA_SERVER_CA_KEYFILE="../mykey.pem"
   #         To set the "keyfile" element in the "ca" section below;
   #         note the '_' separator character.
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

   # Server's listening port (default: 7054)
   port: 7054

   # Server's listening address (default: 0.0.0.0)
   addr: 0.0.0.0

   # Enables debug logging (default: false)
   debug: false

   #############################################################################
   #  TLS section for the server's listening port
   #############################################################################
   tls:
     # Enable TLS (default: false)
     enabled: false
     cafile: root.pem
     certfile: tls_server-cert.pem
     keyfile: tls_server-key.pem

   #############################################################################
   #  The CA section contains the key and certificate files used when
   #  issuing enrollment certificates (ECerts) and transaction
   #  certificates (TCerts).
   #############################################################################
   ca:
     # Certificate file (default: ca-cert.pem)
     certfile: ca-cert.pem
     # Key file (default: ca-key.pem)
     keyfile: ca-key.pem

   #############################################################################
   #  The registry section controls how the fabric-ca-server does two things:
   #  1) authenticates enrollment requests which contain a username and password
   #     (also known as an enrollment ID and secret).
   #  2) once authenticated, retrieves the identity's attribute names and
   #     values which the fabric-ca-server optionally puts into TCerts
   #     which it issues for transacting on the Hyperledger Fabric blockchain.
   #     These attributes are useful for making access control decisions in
   #     chaincode.
   #  There are two main configuration options:
   #  1) The fabric-ca-server is the registry
   #  2) An LDAP server is the registry, in which case the fabric-ca-server
   #     calls the LDAP server to perform these tasks.
   #############################################################################
   registry:
     # Maximum number of times a password/secret can be reused for enrollment.
     # A value of 0 means there is no limit.
     # Default: 0
     maxEnrollments: 0

     # Contains user information which is used when LDAP is disabled
     identities:
       - id: <<<ADMIN>>>
         pass: <<<ADMINPW>>>
         type: client
         affiliation: org1.department1
         attrs:
            hf.Registrar.Roles: "client,user,peer,validator,auditor"
            hf.Registrar.DelegateRoles: "client,user,validator,auditor"
            hf.Revoker: true

   #############################################################################
   # Database section
   # Supported types are: "sqlite3", "postgres", and "mysql".
   # The datasource value depends on the type.
   # If the type is "sqlite3", the datasource value is a file name to use
   # as the database store.  Since "sqlite3" is an embedded database, it
   # may not be used if you want to run the fabric-ca-server in a cluster.
   # To run the fabric-ca-server in a cluster, you must choose "postgres"
   # or "mysql".
   #############################################################################
   database:
     type: sqlite3
     datasource: fabric-ca-server.db
     tls:
         enabled: false
         certfiles:
           - db-server-cert.pem
         client:
           certfile: db-client-cert.pem
           keyfile: db-client-key.pem

   #############################################################################
   # LDAP section
   # The URL is of the form: ldap://adminDN:adminPassword@host:port/base
   #############################################################################
   ldap:
      # Enables or disables the LDAP client
      enabled: false
      # The URL is of the form: ldap://adminDN:adminPassword@host:port/base
      url:
      base:
      userfilter:  "(uid=%s)"
      groupfilter: "(memberUid=%s)"

   #############################################################################
   #  Affiliation section
   #############################################################################
   affiliations:
      org1:
         - department1
         - department2
      org2:
         - department1

   #############################################################################
   #    Signing profiles.  A default signing profile is required, but
   #    other profiles may also be provided.  The caller may specify
   #    which profile to use, but by default the "default" profile is used.
   #############################################################################
   signing:
       default:
         usage:
           - cert sign
         expiry: 8000h
       profiles:

   #############################################################################
   #  Certificate Signing Request section for generating the CA certificate
   #############################################################################
   csr:
      cn: fabric-ca-server
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
   #   Crypto section configures the crypto primitives used for all
   #############################################################################
   crypto:
     software:
        hash_family: SHA2
        security_level: 256
        ephemeral: false
        key_store_dir: keys
   `
)

var (
	// cfgFileName is the name of the config file
	cfgFileName string
	// serverCfg is the server's config
	serverCfg *lib.ServerConfig
)

// configInit reads in config file and ENV variables if set.
// It also initilizes 'cfg'
func configInit() {

	var err error

	// Make the config file name absolute
	if !filepath.IsAbs(cfgFileName) {
		cfgFileName, err = filepath.Abs(cfgFileName)
		if err != nil {
			util.Fatal("Failed to get full path of config file: %s", err)
		}
	}

	// If the config file doesn't exist, create a default one
	if !util.FileExists(cfgFileName) {
		err = createDefaultConfigFile()
		if err != nil {
			util.Fatal("Failed to create default configuration file: %s", err)
		}
		log.Infof("Created default configuration file at %s", cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", cfgFileName)
	}

	// Read the config
	viper.SetConfigFile(cfgFileName)
	viper.AutomaticEnv() // read in environment variables that match
	err = viper.ReadInConfig()
	if err != nil {
		util.Fatal("Failed to read config file: %s", err)
	}

	// Unmarshal the config into 'serverCfg'
	serverCfg = new(lib.ServerConfig)
	err = viper.Unmarshal(serverCfg)
	if err != nil {
		util.Fatal("Incorrect format in file '%s': %s", cfgFileName, err)
	}

	// Make all file paths in config absolute relative to the location
	// of the config file
	makeFileNamesAbsolute(serverCfg)

}

func makeFileNamesAbsolute(cfg *lib.ServerConfig) {
	makeFileNameAbsolute(&cfg.CA.Certfile)
	makeFileNameAbsolute(&cfg.CA.Keyfile)
}

func makeFileNameAbsolute(fileNamePtr *string) {
	fileName, err := util.MakeFileAbs(*fileNamePtr, filepath.Dir(cfgFileName))
	if err != nil {
		util.Fatal("Failed to convert '%s' to an absolute path", *fileNamePtr)
	}
	*fileNamePtr = fileName
}

// Get the default path for the config file to display in usage message
func getDefaultConfigFile() (string, error) {
	var fname = fmt.Sprintf("%s-config.yaml", cmdName)
	// First check home env variables
	home := os.Getenv("FABRIC_CA_SERVER_HOME")
	if home == "" {
		home = os.Getenv("FABRIC_CA_HOME")
	}
	if home != "" {
		return path.Join(home, fname), nil
	}
	return fname, nil
}

func createDefaultConfigFile() error {
	// Create a default config, but only if they provided a
	// bootstrap user ID and password
	up := viper.GetString("user")
	if up == "" {
		return fmt.Errorf("The '-u user:pass' option is required; see '%s init -h'", cmdName)
	}
	ups := strings.Split(up, ":")
	if len(ups) < 2 {
		return fmt.Errorf("The value '%s' on the command line is missing a colon separator", up)
	}
	if len(ups) > 2 {
		ups = []string{ups[0], strings.Join(ups[1:], ":")}
	}
	// Get hostname
	myhost, err := os.Hostname()
	if err != nil {
		return err
	}
	// Do string subtitution to get the default config
	cfg := strings.Replace(defaultCfgTemplate, "<<<ADMIN>>>", ups[0], 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", ups[1], 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	// Now write the file
	err = os.MkdirAll(filepath.Dir(cfgFileName), 0644)
	if err != nil {
		return err
	}
	// Now write the file
	return ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
}

// Make the file name absolute relative to the config file
// if not already absolute
func makeAbs(file string) (string, error) {
	return util.MakeFileAbs(file, filepath.Dir(cfgFileName))
}
