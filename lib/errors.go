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
	"encoding/json"
	"fmt"
	"net/http"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
)

// Error codes
const (
	ErrUnknown = iota
	ErrMethodNotAllowed
	ErrNoAuthHdr
	ErrReadingReqBody
	ErrEmptyReqBody
	ErrBadReqBody
	ErrBadReqToken
	ErrNotRevoker
	ErrRevCertNotFound
	ErrCertNotOwnedBy
	ErrRevokeIDNotFound
	ErrRevokeFailure
	ErrRevokeUserInfoNotFound
	ErrRevokeUpdateUser
	ErrNoCertsRevoked
	ErrMissingRevokeArgs
	ErrGettingAffiliation
	ErrRevokerNotAffiliated
	ErrSendingResponse
	ErrCANotFound
	ErrBasicAuthNotAllowed
	ErrNoUserPass
	ErrInvalidUser
	ErrInvalidPass
	ErrInvalidToken
	ErrRevokeCheckingFailed
	ErrRevokedOrExpired
	ErrCertNotFound
	ErrRevoked
	ErrBadCSR
	ErrNoPreKey
	ErrHandler
	ErrBadInternalState
)

func newErr(code, scode int, format string, args ...interface{}) *augerr {
	msg := fmt.Sprintf(format, args...)
	return &augerr{
		code:  code,
		scode: scode,
		msg:   msg,
	}
}

// augerr is an augmented error
type augerr struct {
	code  int    // error code
	scode int    // HTTP status code
	msg   string // error message
}

// Error returns the string representation
func (ae *augerr) Error() string {
	return ae.String()
}

// String returns a string representation of this augmented error
func (ae *augerr) String() string {
	s := ""
	if ae.code != 0 {
		s = fmt.Sprintf("code: %d, ", ae.code)
	}
	if ae.scode != 0 {
		s = fmt.Sprintf("%sHTTP status code: %d, ", s, ae.scode)
	}
	return fmt.Sprintf("%s%s", s, ae.msg)
}

// Write the server's HTTP error response
func (ae *augerr) writeResponse(w http.ResponseWriter) error {
	response := cfsslapi.NewErrorResponse(ae.msg, ae.code)
	jsonMessage, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Failed to marshal error to JSON: %v", err)
		return err
	}
	msg := string(jsonMessage)
	http.Error(w, msg, ae.scode)
	return nil
}
