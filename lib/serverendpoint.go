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

package lib

import (
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
)

// Endpoint represents a particular endpoint (e.g. to "/api/v1/enroll")
type Endpoint struct {
	// The HTTP methods ("GET", "POST", etc) which the function will handle
	Methods []string
	// Handler
	Handler func(ctx *serverRequestContext) (interface{}, error)
	// Server
	Server *Server
}

// ServeHTTP encapsulates the call to underlying Handlers to handle the request
// and return the response with proper HTTP status code
func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	log.Debugf("Received request for %s", url)
	err := e.validateMethod(r)
	var resp interface{}
	if err == nil {
		resp, err = e.Handler(newServerRequestContext(r, w, e))
	}
	scode := 200
	if err != nil {
		scode = e.handleError(err, w)
		log.Debugf("Error response for %s: %s", url, err)
	} else {
		api.SendResponse(w, resp)
		log.Debugf("Sent response for %s: %+v", url, resp)
	}
	log.Infof("%s - \"%s %s\" %d", r.RemoteAddr, r.Method, r.URL, scode)
}

func (e *Endpoint) validateMethod(r *http.Request) error {
	for _, m := range e.Methods {
		if m == r.Method {
			return nil
		}
	}
	return newErr(ErrMethodNotAllowed, 405, "Method %s is not allowed", r.Method)
}

func (e *Endpoint) handleError(err error, w http.ResponseWriter) int {
	scode := 200
	if err != nil {
		var aerr *augerr
		switch err.(type) {
		case *augerr:
			aerr = err.(*augerr)
		default:
			aerr = newErr(ErrUnknown, 500, err.Error())
		}
		aerr.writeResponse(w)
		scode = aerr.scode
	}
	return scode
}
