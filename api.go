/*
 * This file is simply a mirror of the interfaces in interfaces/interfaces.go.
 * This was done in order to prevent an import cycle.
 */

package cop

import (
	"os"

	"github.com/cloudflare/cfssl/log"
	real "github.com/hyperledger/fabric-cop/api"
	def "github.com/hyperledger/fabric-cop/lib/defaultImpl"
)

// Mgr is the main interface to COP functionality
type Mgr interface {
	real.Mgr
}

// CertMgr is a COP certificate manager
type CertMgr interface {
	real.CertMgr
}

// JoinRequest is the state of a request to join the blockchain network
type JoinRequest struct {
	real.JoinRequest
}

// JoinRequestListener is a listener for join requests
type JoinRequestListener real.JoinRequestListener

// JoinRequestStatus is the status of a join request
type JoinRequestStatus real.JoinRequestStatus

// Values denoting the possible values of the JoinRequestStatus
const (
	JRSWaiting  = real.JRSWaiting
	JRSApproved = real.JRSApproved
	JRSDenied   = real.JRSDenied
)

// JoinResponseType are the types of responses which can be provided to a JoinRequest
type JoinResponseType real.JoinResponseType

// Values denoting the possible values of the JoinResponseType
const (
	JRTApprove = real.JRTApprove
	JRTDeny    = real.JRTDeny
	JRTAbstain = real.JRTAbstain
	JRTCount   = real.JRTCount
)

// CertHandler provides functions related to a certificate
type CertHandler interface {
	real.CertHandler
}

// KeyHandler provides functions related to a key
type KeyHandler interface {
	real.KeyHandler
}

// RegisterRequest information
type RegisterRequest struct {
	real.RegisterRequest
}

type EnrollRequest struct {
	real.EnrollRequest
}

type UserRecord struct {
	real.UserRecord
}

// Identity is any type of identity which is opaque for now
type Identity real.Identity

// The following are all the error codes returned by COP.
// The values begin with "100000" to avoid overlap with CFSSL errors.
// Add all new errors to the end of the current list.
const (
	// NotImplemented means not yet implemented but plans to support
	NotImplemented = real.NotImplemented
	// NotSupported means no current plans to support
	NotSupported        = real.NotSupported
	InvalidProviderName = real.InvalidProviderName
	TooManyArgs         = real.TooManyArgs
	NotInitialized      = real.NotInitialized
)

// Error is an interface with a Code method
type Error interface {
	real.Error
}

func init() {
	provider := os.Getenv("COP.PROVIDER")
	if provider == "" {
		provider = "default"
	}
	if provider == "default" {
		real.SetMgr(new(def.Mgr))
	} else {
		log.Debugf("invalid COP provider: %s\n", provider)
		os.Exit(1)
	}
}

// NewCertMgr creates a COP certificate manager
func NewCertMgr() CertMgr {
	return real.NewCertMgr()
}
