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

package tcert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
)

var (
	attributeSeparator      = "#"
	attributeIndexIdentifer = "->"
	attributeBaseIdentifier = 9
)

// AttributeMgr provides attribute retrieval functionalities
type AttributeMgr struct {
	attrs []Attribute
}

// GetAttributeManagerInstance creates attributeList from certificate
// @certBuf : Byte for certificates which contains encrypted attributes
// @keys : Map containing attribute decryption key
// @returns : New Instance of Attribute Manager
func GetAttributeManagerInstance(certBuf []byte, keys map[string][]byte) (*AttributeMgr, error) {
	if certBuf == nil {
		return nil, errors.New("Certificate buffer cannot be nil")
	}
	attributes, error := getAttributesFromTCert(certBuf, keys)
	if error != nil {
		return nil, fmt.Errorf("Retrieving attributes from tcert failed with error : %s", error)
	}

	attrMgr := new(AttributeMgr)
	attrMgr.attrs = attributes

	return attrMgr, nil
}

// GetNames returns attribute names present in TCert
func (attrMgr *AttributeMgr) GetNames() []string {

	attributes := attrMgr.attrs
	noOfAttributes := len(attributes)
	if noOfAttributes == 0 {
		return nil
	}
	var attrNames []string

	for i := 0; i < noOfAttributes; i++ {
		attrNames = append(attrNames, attributes[i].Name)
	}

	return attrNames

}

// GetValue returns attribute value for the attribute identified by attribute name
func (attrMgr *AttributeMgr) GetValue(attrName string) (string, error) {

	attributes := attrMgr.attrs
	noOfAttributes := len(attributes)
	if noOfAttributes == 0 {
		return "", errors.New("This TCert contains no attribute")
	}

	var attributeName string
	var attribute Attribute
	for i := 0; i < noOfAttributes; i++ {
		attribute = attributes[i]
		attributeName = attribute.Name
		if strings.Compare(attributeName, attrName) == 0 {
			return attribute.Value, nil
		}
	}
	return "", fmt.Errorf("Attribute value could not be found for attribute [%s]", attrName)
}

// GetValues returns attribute name value pair of the attributes
func (attrMgr *AttributeMgr) GetValues(attrNames []string) map[string]string {

	noOfAttributes := len(attrNames)
	if noOfAttributes == 0 {
		return nil
	}

	var attributeName string
	attributes := attrMgr.attrs
	attrMap := make(map[string]string)
	var attribute Attribute

	noOfAttributesInTCert := len(attributes)
	if noOfAttributesInTCert == 0 {
		return nil
	}

	for i := 0; i < noOfAttributes; i++ {
		for j := 0; j < noOfAttributesInTCert; j++ {
			attribute = attributes[j]
			attributeName = attribute.Name
			if strings.Compare(attrNames[i], attributeName) == 0 {
				attrMap[attributeName] = attribute.Value
				break
			}
		}
	}
	return attrMap
}

// GetAllValues retuurns map of Attribute Name / Value of all attributes in TCert
func (attrMgr *AttributeMgr) GetAllValues() map[string]string {
	attrs := attrMgr.attrs
	noOfAttributes := len(attrs)
	if noOfAttributes == 0 {
		return nil
	}
	attrMap := make(map[string]string)
	var attribute Attribute

	for i := 0; i < noOfAttributes; i++ {
		attribute = attrs[i]
		attrMap[attribute.Name] = attribute.Value
	}

	return attrMap
}

func getAttributesFromTCert(certBuf []byte, keys map[string][]byte) ([]Attribute, error) {

	if certBuf == nil {
		return nil, errors.New("Cert is nil")
	}
	cert, error := GetCertificate(certBuf)
	if error != nil {
		return nil, fmt.Errorf("Golang Certificate Object from byte array failed with error : %s", error)
	}
	//Get Extension
	extraExtension := cert.Extensions
	extraExtensionLength := len(extraExtension)
	var extension pkix.Extension
	var id asn1.ObjectIdentifier
	var critical bool
	var headerValue []byte

	for i := 0; i < extraExtensionLength; i++ {
		extension = extraExtension[i]
		id = extension.Id
		critical = extension.Critical
		if id.Equal(TCertAttributesHeaders) && !critical {
			headerValue = extension.Value

			attrs, error := processAttributeHeader(string(headerValue), extraExtension, keys)
			if error != nil {
				return nil, fmt.Errorf("Attribute retrieval failed with error : %s", error)
			}
			return attrs, nil
		}
	}
	log.Debug("Attributes Created")
	return nil, nil
}

// processAttributeHeader processes header attribute set in the certificate
// @headerValue : Attribute header value
// @extension  :  TCert Certificate Extension
// @keys : Map containing attribute decryption key
//@returns : Array of Attributes with name/value pair
func processAttributeHeader(headerValue string, extension []pkix.Extension, keys map[string][]byte) ([]Attribute, error) {

	if len(headerValue) == 0 {
		return nil, errors.New("Header value cannot be empty or of zero length")
	}

	attributeBlock := strings.Split(headerValue, attributeSeparator)
	attributeBlockLength := len(attributeBlock)
	if attributeBlockLength == 0 {
		return nil, errors.New("Attributes are not present in the cert")
	}

	var attributeName, attributeValue, attributeIdentifierString string
	var attribute []string
	var attributeIdentifier, sliceLength int
	var err error
	var shouldDecrypt, isKeyNil bool
	var attrBuf []byte

	if keys == nil {
		isKeyNil = true
	}
	var attrs []Attribute
	for i := 0; i < attributeBlockLength; i++ {
		if attributeBlock[i] != "" {
			attribute = strings.Split(attributeBlock[i], attributeIndexIdentifer)
			attributeName = attribute[0]
			if (keys[attributeName] != nil) && !isKeyNil {
				shouldDecrypt = true
			}
			attributeIdentifierString = attribute[1]
			attributeIdentifier, err = strconv.Atoi(attributeIdentifierString)
			if err != nil {
				return nil, fmt.Errorf("String to Integer conversion for attribute[%s] failed with error : %s", attributeName, err)
			}

			attributeValue = getExtensionValueFromCert(asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, attributeIdentifier + attributeBaseIdentifier}, extension)
			if shouldDecrypt {
				attrBuf, err = CBCPKCS7Decrypt(keys[attributeName], []byte(attributeValue))
				if err != nil {
					return nil, fmt.Errorf("The attribute value decryption for attribute [%s] failed with error : %s", attributeName, err)
				}
				sliceLength = len(attrBuf) - 16
				attributeValue = string(attrBuf[:sliceLength])
			}
			attrs = append(attrs, Attribute{attributeName, attributeValue})
		}
	}
	log.Debug("Attribute List Created")
	return attrs, nil
}

// Given an ASN , it returns extension value
func getExtensionValueFromCert(asnID asn1.ObjectIdentifier, extensions []pkix.Extension) string {
	noOfExtensions := len(extensions)
	var extension pkix.Extension
	var id asn1.ObjectIdentifier
	var critical bool
	var attrValue string

	for i := 0; i < noOfExtensions; i++ {
		extension = extensions[i]
		id = extension.Id
		critical = extension.Critical

		if id.Equal(asnID) && !critical {
			attrValue = string(extension.Value)
			return attrValue
		}
	}
	return ""
}
