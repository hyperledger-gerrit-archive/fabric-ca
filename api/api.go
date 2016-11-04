/*
 * This file contains interfaces for the COP library.
 * COP provides police-like security functions for Hyperledger Fabric.
 */

package api

import(
	"math/big"
	"time"
)
// Mgr is the main interface to COP functionality
type Mgr interface {

	// NewCertMgr creates a COP certificate manager
	NewCertMgr() CertMgr
}

// Client is a COP client
type Client interface {
	// TCertBatchReq returns a *TCertBatchResp which contains a batch of tcerts
	TCertBatchReq(tcertrequest *TCertBatchRequest) (*TCertBatchResp, error)
	// GetHomeDir returns the home directory
	GetHomeDir() string

	// SetHomeDir sets the home directory
	SetHomeDir(dir string)

	// GetServerAddr returns the server address
	GetServerAddr() string

	// SetServerAddr sets the server address
	SetServerAddr(dir string)

	// Register a new identity
	Register(registration *RegisterRequest) Error

	// Enroll a registered identity
	//	Enroll(user, pass string) (Identity, Error)
	Enroll(enroll *EnrollRequest, csrJSON string) ([]byte, Error)

	// RegisterAndEnroll registers and enrolls a new identity
	RegisterAndEnroll(registration *RegisterRequest) (Identity, Error)

	/*
		// SubmitJoinRequest submits a join request, implicitly approving by the caller
		// Returns the join request ID
		SubmitJoinRequest(participantFilePath string) (JoinRequest, Error)

		// ApproveJoinRequest approves the join request
		ApproveJoinRequest(joinRequestID string) Error

		// DenyJoinRequest denies the join request
		DenyJoinRequest(joinRequestID string) Error

		// ListJoinRequests lists the currently outstanding join requests for the blockchain network
		ListJoinRequests() ([]JoinRequest, Error)

		// ListParticipants lists the current participants in the blockchain network
		ListParticipants() ([]string, Error)

		// Set the listener to be called when a JoinRequestEvent is emitted
		SetJoinRequestListener(listener JoinRequestListener)
	*/
}
// TCertBatchRequest is the structure for the request of tcert batch
type TCertBatchRequest struct {
	//required fields
	UserID string
	Num    int64 `json:"num"`

	//optional fields
	RootPreKey                   *big.Int
	Attribute_Encryption_Enabled bool // default is false
	AttributeSet                 []Attribute
	ValidityPeriod               float64
	CSRData                      CertData
}
// CertData is the tcert data
type CertData struct {
	C  string
	L  string
	O  string
	OU string
	ST string
	CN string
}

// TCertBatchResp is the request for getting batch of tcerts
type TCertBatchResp struct {
	Certs CertSet `json:"TCertBatch,omitempty"`
}

// CertSet contains the set of tcerts
type CertSet struct {
	Ts 		time.Time
	Id    string                 `json:"id,omitempty"`
	Key   string                 `json:"key,omitempty"`  //Base64 encoded string
	Certs []TCert `json:"TCertList,omitempty"` //Base64 encoded string
}

//TCert is the tcert in string format
type TCert struct {
	Cert string `json:"TCert,omitempty"` //base64 encoded string
	Keys map[string]string  `json:"keys,omitempty"` //base64 encoded string as value
}
// JoinRequest is the state of a request to join the blockchain network
type JoinRequest struct {
	ID        string             // Unique ID of join request
	Info      string             // The original JSON request from the participant
	Status    JoinRequestStatus  // waiting, approved, or denied
	Responses [JRTCount][]string // participant names of approvers
}

// JoinRequestListener is a listener for join requests
type JoinRequestListener func(JoinRequest)

// JoinRequestStatus is the status of a join request
type JoinRequestStatus int

// Values denoting the possible values of the JoinRequestStatus
const (
	JRSWaiting JoinRequestStatus = iota
	JRSApproved
	JRSDenied
)

// JoinResponseType are the types of responses which can be provided to a JoinRequest
type JoinResponseType int

// Values denoting the possible values of the JoinResponseType
const (
	JRTApprove JoinResponseType = iota
	JRTDeny
	JRTAbstain
	JRTCount
)

// CertMgr is the interface for all certificate-based management
type CertMgr interface {

	// GenCert generates a certificate
	GenCert(csr string, prefix string, participantFile string) Error

	// InitSelfSign generates self-signed certs and updates the participant file
	InitSelfSign(domain string, path string) Error

	// InitLego gets certificates from Let's Encrypt and updates the participant file
	InitLego(host string) Error

	// SetECAKey sets the ECA key
	SetECAKey(key []byte) Error

	// SetTCAKey sets the TCA key
	SetTCAKey(key []byte) Error

	// Set the path for the participant file
	SetParticipantFilePath(path string) Error

	// UpdateParticipantFile
	UpdateParticipantFile() Error

	// LoadFromString
	//LoadFromString(str string) Error

	// StoreToString
	//StoreToString() string

	// NewCertHandler creates a COP certificate handler
	NewCertHandler(cert []byte) (CertHandler, Error)

	// NewKeyHandler creates a COP key handler
	NewKeyHandler(key []byte) (KeyHandler, Error)
}

// CertHandler provides functions related to a certificate
type CertHandler interface {
	// GetId returns the ID of the owner of this cert
	GetID() string
	// GetPartipantId returns the participant ID associated with this cert
	GetParticipantID() string
	// Determine if the caller has a specific role (e.g. 'orderer', 'peer', etc)
	IsType(role string) bool
	// Verify a signature against this certificate
	Verify(buf []byte, signature []byte) (bool, Error)
}

// KeyHandler provides functions related to a key
type KeyHandler interface {
	CertHandler
	// Create a signature using this key
	Sign(buf []byte) ([]byte, Error)
}

// RegisterRequest information
type RegisterRequest struct {
	User       string      `json:"user"`
	Group      string      `json:"group"`
	Attributes []Attribute `json:"attrs,omitempty"`
	CallerID   string      `json:"callerID"`
}

type EnrollRequest struct {
	User  string `json:"user"`
	Token []byte `json:"token"`
	CSR   []byte `json:"csr"`
}

// Attribute is an arbitrary name/value pair
type Attribute struct {
	Name  string   `json:"name"`
	Value []string `json:"value"`
}

type Enrollment struct {
	ID           string
	EnrollSecret []byte
}

// Database api

// UserRecord used for inserting into database
type UserRecord struct {
	ID           string `db:"id"`
	EnrollmentID string `db:"enrollmentId"`
	Token        string `db:"token"`
	Metadata     string `db:"metadata"`
	State        int    `db:"state"`
	Key          int    `db:"key"`
}

// Accessor abstracts the CRUD of certdb objects from a DB.
type Accessor interface {
	InsertUser(user UserRecord) error
	DeleteUser(id string) error
	UpdateUser(user UserRecord) error
	GetUser(id string) (UserRecord, error)
	InsertGroup(name string, parentID string) error
	DeleteGroup(name string) error
	GetGroup(name string) (string, string, error)
}

// Identity is any type of identity which is opaque for now
type Identity interface{}

var mgr Mgr

// SetMgr sets the COP manager
func SetMgr(m Mgr) {
	mgr = m
}

// NewCertMgr creates a COP certificate manager
func NewCertMgr() CertMgr {
	return mgr.NewCertMgr()
}
