/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	proto "github.com/golang/protobuf/proto"
	amcl "github.com/milagro-crypto/amcl/version3/go/amcl/FP256BN"
	"github.com/pkg/errors"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/streamer"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/idemix"
	mspprotos "github.com/hyperledger/fabric/protos/msp"
	"github.com/mitchellh/mapstructure"
)

// Client is the fabric-ca client object
type Client struct {
	// The client's home directory
	HomeDir string `json:"homeDir,omitempty"`
	// The client's configuration
	Config *ClientConfig
	// Denotes if the client object is already initialized
	initialized bool
	// File and directory paths
	keyFile, certFile, idemixCredFile, idemixCredsDir, caCertsDir string
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
	// HTTP client associated with this Fabric CA client
	httpClient *http.Client
}

// GetServerInfoResponse is the response from the GetServerInfo call
type GetServerInfoResponse struct {
	// CAName is the name of the CA
	CAName string
	// CAChain is the PEM-encoded bytes of the fabric-ca-server's CA chain.
	// The 1st element of the chain is the root CA cert
	CAChain []byte
	// Idemix issuer public key of the CA
	IssuerPublicKey []byte
	// Version of the server
	Version string
}

// EnrollmentResponse is the response from Client.Enroll and Identity.Reenroll
type EnrollmentResponse struct {
	Identity   *Identity
	ServerInfo GetServerInfoResponse
}

// Init initializes the client
func (c *Client) Init() error {
	if !c.initialized {
		cfg := c.Config
		log.Debugf("Initializing client with config: %+v", cfg)
		if cfg.MSPDir == "" {
			cfg.MSPDir = "msp"
		}
		mspDir, err := util.MakeFileAbs(cfg.MSPDir, c.HomeDir)
		if err != nil {
			return err
		}
		cfg.MSPDir = mspDir
		// Key directory and file
		keyDir := path.Join(mspDir, "keystore")
		err = os.MkdirAll(keyDir, 0700)
		if err != nil {
			return errors.Wrap(err, "Failed to create keystore directory")
		}
		c.keyFile = path.Join(keyDir, "key.pem")

		// Cert directory and file
		certDir := path.Join(mspDir, "signcerts")
		err = os.MkdirAll(certDir, 0755)
		if err != nil {
			return errors.Wrap(err, "Failed to create signcerts directory")
		}
		c.certFile = path.Join(certDir, "cert.pem")

		// CA certs directory
		c.caCertsDir = path.Join(mspDir, "cacerts")
		err = os.MkdirAll(c.caCertsDir, 0755)
		if err != nil {
			return errors.Wrap(err, "Failed to create cacerts directory")
		}

		// idemix credentials directory
		c.idemixCredsDir = path.Join(mspDir, "user")
		err = os.MkdirAll(c.idemixCredsDir, 0755)
		if err != nil {
			return errors.Wrap(err, "Failed to create idemix credentials directory")
		}
		c.idemixCredFile = path.Join(c.idemixCredsDir, "SignerConfig")

		// Initialize BCCSP (the crypto layer)
		c.csp, err = util.InitBCCSP(&cfg.CSP, mspDir, c.HomeDir)
		if err != nil {
			return err
		}
		// Create http.Client object and associate it with this client
		err = c.initHTTPClient()
		if err != nil {
			return err
		}

		// Successfully initialized the client
		c.initialized = true
	}
	return nil
}

func (c *Client) initHTTPClient() error {
	tr := new(http.Transport)
	if c.Config.TLS.Enabled {
		log.Info("TLS Enabled")

		err := tls.AbsTLSClient(&c.Config.TLS, c.HomeDir)
		if err != nil {
			return err
		}

		tlsConfig, err2 := tls.GetClientTLSConfig(&c.Config.TLS, c.csp)
		if err2 != nil {
			return fmt.Errorf("Failed to get client TLS config: %s", err2)
		}
		tr.TLSClientConfig = tlsConfig
	}
	c.httpClient = &http.Client{Transport: tr}
	return nil
}

// GetCAInfo returns generic CA information
func (c *Client) GetCAInfo(req *api.GetCAInfoRequest) (*GetServerInfoResponse, error) {
	err := c.Init()
	if err != nil {
		return nil, err
	}
	body, err := util.Marshal(req, "GetCAInfo")
	if err != nil {
		return nil, err
	}
	cainforeq, err := c.newPost("cainfo", body)
	if err != nil {
		return nil, err
	}
	netSI := &serverInfoResponseNet{}
	err = c.SendReq(cainforeq, netSI)
	if err != nil {
		return nil, err
	}
	localSI := &GetServerInfoResponse{}
	err = c.net2LocalServerInfo(netSI, localSI)
	if err != nil {
		return nil, err
	}
	return localSI, nil
}

// Convert from network to local server information
func (c *Client) net2LocalServerInfo(net *serverInfoResponseNet, local *GetServerInfoResponse) error {
	caChain, err := util.B64Decode(net.CAChain)
	if err != nil {
		return err
	}
	if net.IssuerPublicKey != "" {
		ipk, err := util.B64Decode(net.IssuerPublicKey)
		if err != nil {
			return err
		}
		local.IssuerPublicKey = ipk
	}
	local.CAName = net.CAName
	local.CAChain = caChain
	local.Version = net.Version
	return nil
}

// Enroll enrolls a new identity
// @param req The enrollment request
func (c *Client) Enroll(req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	log.Debugf("Enrolling %+v", req)

	err := c.Init()
	if err != nil {
		return nil, err
	}

	if req.Idemix {
		return c.handleIdemixEnroll(req)
	}
	return c.handleX509Enroll(req)
}

func (c *Client) handleX509Enroll(req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	// Generate the CSR
	csrPEM, key, err := c.GenCSR(req.CSR, req.Name)
	if err != nil {
		return nil, errors.WithMessage(err, "Failure generating CSR")
	}

	reqNet := &api.EnrollmentRequestNet{
		CAName:   req.CAName,
		AttrReqs: req.AttrReqs,
	}

	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile
	reqNet.SignRequest.Label = req.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}

	// Send the CSR to the fabric-ca server with basic auth header
	post, err := c.newPost("enroll", body)
	if err != nil {
		return nil, err
	}
	post.SetBasicAuth(req.Name, req.Secret)
	var result enrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}

	// Create the enrollment response
	return c.newEnrollmentResponse(&result, req.Name, key)
}

func (c *Client) handleIdemixEnroll(req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	// Send idemix credential request
	reqNet := &api.IdemixEnrollmentRequestNet{
		CAName: req.CAName,
		//AttrReqs: req.AttrReqs,
	}

	// Get nonce from the CA
	body, err := util.Marshal(reqNet, "NonceRequest")
	if err != nil {
		return nil, err
	}
	post, err := c.newPost("idemix/enroll", body)
	if err != nil {
		return nil, err
	}
	// TODO: support authentication token based on X509 certificate
	post.SetBasicAuth(req.Name, req.Secret)

	// Send the request and process the response
	var result idemixEnrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := util.B64Decode(result.Nonce)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode nonce that was returned by the CA")
	}
	nonce := amcl.FromBytes(nonceBytes)

	// Create credential request
	credReq, sk, rand, err := c.newIdemixCredentialRequest(nonce)
	if err != nil {
		return nil, err
	}
	reqNet.CredRequest = credReq

	body, err = util.Marshal(reqNet, "CredentialRequest")
	if err != nil {
		return nil, err
	}
	log.Debugf("Sending idemix enroll request: %s", string(body))

	// Send the cred request to the fabric-ca server with basic auth header
	post, err = c.newPost("idemix/enroll", body)
	if err != nil {
		return nil, err
	}
	post.SetBasicAuth(req.Name, req.Secret)
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}
	return c.newIdemixEnrollmentResponse(&result, sk, rand, req.Name)
}

// newEnrollmentResponse creates a client enrollment response from a network response
// @param result The result from server
// @param id Name of identity being enrolled or reenrolled
// @param key The private key which was used to sign the request
func (c *Client) newEnrollmentResponse(result *enrollmentResponseNet, id string, key bccsp.Key) (*EnrollmentResponse, error) {
	log.Debugf("newEnrollmentResponse %s", id)
	certByte, err := util.B64Decode(result.Cert)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid response format from server")
	}
	signer, err := newSigner(key, certByte)
	if err != nil {
		return nil, err
	}
	x509Cred := newX509Credential(c.certFile, c.keyFile, c)
	err = x509Cred.SetVal(signer)
	if err != nil {
		return nil, err
	}
	resp := &EnrollmentResponse{
		Identity: newIdentity(c, id, []Credential{x509Cred}),
	}
	err = c.net2LocalServerInfo(&result.ServerInfo, &resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// newIdemixEnrollmentResponse creates a client enrollment response from a network response
// @param result The result from server
// @param id Name of identity being enrolled
func (c *Client) newIdemixEnrollmentResponse(result *idemixEnrollmentResponseNet, sk, rand *amcl.BIG, id string) (*EnrollmentResponse, error) {
	log.Debugf("newEnrollmentResponse %s", id)
	credBytes, err := util.B64Decode(result.Credential)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid response format from server")
	}
	icred := &idemix.Credential{}
	err = proto.Unmarshal(credBytes, icred)
	if err != nil {
		return nil, err
	}
	icred.Complete(rand)
	ccredBytes, err := proto.Marshal(icred)
	signerConfig := &mspprotos.IdemixMSPSignerConfig{Cred: ccredBytes, Sk: idemix.BigToBytes(sk),
		IsAdmin: false, OrganizationalUnitIdentifier: ""} //TODO: get isadmin and ou identifier
	cred := newIdemixCredential(c.idemixCredFile, c)
	err = cred.SetVal(signerConfig)
	if err != nil {
		return nil, err
	}
	identity := newIdentity(c, id, []Credential{cred})
	resp := &EnrollmentResponse{
		Identity: identity,
	}
	err = c.net2LocalServerInfo(&result.ServerInfo, &resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GenCSR generates a CSR (Certificate Signing Request)
func (c *Client) GenCSR(req *api.CSRInfo, id string) ([]byte, bccsp.Key, error) {
	log.Debugf("GenCSR %+v", req)

	err := c.Init()
	if err != nil {
		return nil, nil, err
	}

	cr := c.newCertificateRequest(req)
	cr.CN = id

	if cr.KeyRequest == nil {
		cr.KeyRequest = newCfsslBasicKeyRequest(api.NewBasicKeyRequest())
	}

	key, cspSigner, err := util.BCCSPKeyRequestGenerate(cr, c.csp)
	if err != nil {
		log.Debugf("failed generating BCCSP key: %s", err)
		return nil, nil, err
	}

	csrPEM, err := csr.Generate(cspSigner, cr)
	if err != nil {
		log.Debugf("failed generating CSR: %s", err)
		return nil, nil, err
	}

	return csrPEM, key, nil
}

// newCertificateRequest creates a certificate request which is used to generate
// a CSR (Certificate Signing Request)
func (c *Client) newCertificateRequest(req *api.CSRInfo) *csr.CertificateRequest {
	cr := csr.CertificateRequest{}
	if req != nil && req.Names != nil {
		cr.Names = req.Names
	}
	if req != nil && req.Hosts != nil {
		cr.Hosts = req.Hosts
	} else {
		// Default requested hosts are local hostname
		hostname, _ := os.Hostname()
		if hostname != "" {
			cr.Hosts = make([]string, 1)
			cr.Hosts[0] = hostname
		}
	}
	if req != nil && req.KeyRequest != nil {
		cr.KeyRequest = newCfsslBasicKeyRequest(req.KeyRequest)
	}
	if req != nil {
		cr.CA = req.CA
		cr.SerialNumber = req.SerialNumber
	}
	return &cr
}

func (c *Client) newIdemixCredentialRequest(nonce *amcl.BIG) (*idemix.CredRequest, *amcl.BIG, *amcl.BIG, error) {
	rng, err := idemix.GetRand()
	if err != nil {
		log.Errorf("Error getting rng: \"%s\"", err)
		return nil, nil, nil, err
	}

	sk := idemix.RandModOrder(rng)
	randCred := idemix.RandModOrder(rng)
	issuerPubKey, err := c.getIssuerPubKey()
	if err != nil {
		return nil, nil, nil, err
	}
	return idemix.NewCredRequest(sk, randCred, nonce, issuerPubKey, rng), sk, randCred, nil
}

func (c *Client) getIssuerPubKey() (*idemix.IssuerPublicKey, error) {
	ipkFileName := filepath.Join(c.Config.MSPDir, "IssuerPublicKey")
	ipk, err := ioutil.ReadFile(ipkFileName)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read file at '%s'", ipkFileName)
	}
	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(ipk, pubKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// StoreMyIdentity stores my identity to disk
func (c *Client) StoreMyIdentity(creds []Credential) error {
	err := c.Init()
	if err != nil {
		return err
	}
	for _, cred := range creds {
		err = cred.Store()
		if err != nil {
			return err
		}
	}
	log.Info("Succesfully stored client credential")
	return nil
}

// LoadMyIdentity loads the client's identity from disk
func (c *Client) LoadMyIdentity() (*Identity, error) {
	err := c.Init()
	if err != nil {
		return nil, err
	}
	return c.LoadIdentity(c.keyFile, c.certFile, c.idemixCredFile)
}

// LoadIdentity loads an identity from disk
func (c *Client) LoadIdentity(keyFile, certFile, idemixCredFile string) (*Identity, error) {
	log.Debugf("Loading identity: keyFile=%s, certFile=%s", keyFile, certFile)
	err := c.Init()
	if err != nil {
		return nil, err
	}
	x509Cred := newX509Credential(certFile, keyFile, c)
	err = x509Cred.Load()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to load X509 credential")
	}
	idemixCred := newIdemixCredential(idemixCredFile, c)
	err = idemixCred.Load()
	if err != nil {
		log.Debugf("No idemix credential found at %s", idemixCredFile)
	}
	creds := []Credential{x509Cred, idemixCred}
	return c.NewIdentity(creds)
}

// NewIdentity creates a new identity
func (c *Client) NewIdentity(creds []Credential) (*Identity, error) {
	// Get the enrollment ID from the creds...they all should return same
	// value.
	// TODO
	name, err := creds[0].GetEnrollmentID()
	if err != nil {
		return nil, err
	}
	return newIdentity(c, name, creds), nil
}

// LoadCSRInfo reads CSR (Certificate Signing Request) from a file
// @parameter path The path to the file contains CSR info in JSON format
func (c *Client) LoadCSRInfo(path string) (*api.CSRInfo, error) {
	csrJSON, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var csrInfo api.CSRInfo
	err = util.Unmarshal(csrJSON, &csrInfo, "LoadCSRInfo")
	if err != nil {
		return nil, err
	}
	return &csrInfo, nil
}

// GetCertFilePath returns the path to the certificate file for this client
func (c *Client) GetCertFilePath() string {
	return c.certFile
}

// newGet create a new GET request
func (c *Client) newGet(endpoint string) (*http.Request, error) {
	curl, err := c.getURL(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", curl, bytes.NewReader([]byte{}))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed creating GET request for %s", curl)
	}
	return req, nil
}

// newPut create a new PUT request
func (c *Client) newPut(endpoint string, reqBody []byte) (*http.Request, error) {
	curl, err := c.getURL(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("PUT", curl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed creating PUT request for %s", curl)
	}
	return req, nil
}

// newDelete create a new DELETE request
func (c *Client) newDelete(endpoint string) (*http.Request, error) {
	curl, err := c.getURL(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("DELETE", curl, bytes.NewReader([]byte{}))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed creating DELETE request for %s", curl)
	}
	return req, nil
}

// NewPost create a new post request
func (c *Client) newPost(endpoint string, reqBody []byte) (*http.Request, error) {
	curl, err := c.getURL(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed posting to %s", curl)
	}
	return req, nil
}

// SendReq sends a request to the fabric-ca-server and fills in the result
func (c *Client) SendReq(req *http.Request, result interface{}) (err error) {

	reqStr := util.HTTPRequestToString(req)
	log.Debugf("Sending request\n%s", reqStr)

	err = c.Init()
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "%s failure of request: %s", req.Method, reqStr)
	}
	var respBody []byte
	if resp.Body != nil {
		respBody, err = ioutil.ReadAll(resp.Body)
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				log.Debugf("Failed to close the response body: %s", err.Error())
			}
		}()
		if err != nil {
			return errors.Wrapf(err, "Failed to read response of request: %s", reqStr)
		}
		log.Debugf("Received response\n%s", util.HTTPResponseToString(resp))
	}
	var body *cfsslapi.Response
	if respBody != nil && len(respBody) > 0 {
		body = new(cfsslapi.Response)
		err = json.Unmarshal(respBody, body)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse response: %s", respBody)
		}
		if len(body.Errors) > 0 {
			var errorMsg string
			for _, err := range body.Errors {
				msg := fmt.Sprintf("Response from server: Error Code: %d - %s\n", err.Code, err.Message)
				if errorMsg == "" {
					errorMsg = msg
				} else {
					errorMsg = errorMsg + fmt.Sprintf("\n%s", msg)
				}
			}
			return errors.Errorf(errorMsg)
		}
	}
	scode := resp.StatusCode
	if scode >= 400 {
		return errors.Errorf("Failed with server status code %d for request:\n%s", scode, reqStr)
	}
	if body == nil {
		return errors.Errorf("Empty response body:\n%s", reqStr)
	}
	if !body.Success {
		return errors.Errorf("Server returned failure for request:\n%s", reqStr)
	}
	log.Debugf("Response body result: %+v", body.Result)
	if result != nil {
		return mapstructure.Decode(body.Result, result)
	}
	return nil
}

// StreamResponse reads the response as it comes back from the server
func (c *Client) StreamResponse(req *http.Request, stream string, cb func(*json.Decoder) error) (err error) {

	reqStr := util.HTTPRequestToString(req)
	log.Debugf("Sending request\n%s", reqStr)

	err = c.Init()
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "%s failure of request: %s", req.Method, reqStr)
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	err = streamer.StreamJSONArray(dec, stream, cb)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) getURL(endpoint string) (string, error) {
	nurl, err := NormalizeURL(c.Config.URL)
	if err != nil {
		return "", err
	}
	rtn := fmt.Sprintf("%s/%s", nurl, endpoint)
	return rtn, nil
}

// CheckEnrollment returns an error if this client is not enrolled
func (c *Client) CheckEnrollment() error {
	err := c.Init()
	if err != nil {
		return err
	}
	keyFileExists := util.FileExists(c.keyFile)
	certFileExists := util.FileExists(c.certFile)
	if keyFileExists && certFileExists {
		return nil
	}
	// If key file does not exist, but certFile does, key file is probably
	// stored by bccsp, so check to see if this is the case
	if certFileExists {
		_, _, _, err := util.GetSignerFromCertFile(c.certFile, c.csp)
		if err == nil {
			// Yes, the key is stored by BCCSP
			return nil
		}
	}
	return errors.New("Enrollment information does not exist. Please execute enroll command first. Example: fabric-ca-client enroll -u http://user:userpw@serverAddr:serverPort")
}

func newCfsslBasicKeyRequest(bkr *api.BasicKeyRequest) *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{A: bkr.Algo, S: bkr.Size}
}

// NormalizeURL normalizes a URL (from cfssl)
func NormalizeURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if u.Opaque != "" {
		u.Host = net.JoinHostPort(u.Scheme, u.Opaque)
		u.Opaque = ""
	} else if u.Path != "" && !strings.Contains(u.Path, ":") {
		u.Host = net.JoinHostPort(u.Path, util.GetServerPort())
		u.Path = ""
	} else if u.Scheme == "" {
		u.Host = u.Path
		u.Path = ""
	}
	if u.Scheme != "https" {
		u.Scheme = "http"
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		_, port, err = net.SplitHostPort(u.Host + ":" + util.GetServerPort())
		if err != nil {
			return nil, err
		}
	}
	if port != "" {
		_, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}
