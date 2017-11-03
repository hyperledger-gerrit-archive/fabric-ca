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
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
)

// serverEndpoint represents a particular endpoint (e.g. to "/api/v1/enroll")
type serverEndpoint struct {
	// The HTTP methods ("GET", "POST", etc) which the function will handle
	Methods []string
	// The HTTP return code for success responses
	successRC int
	// Handler is the handler function for this endpoint
	Handler func(ctx *serverRequestContext) (interface{}, error)
	// Server which hosts this endpoint
	Server *Server
	// Indicates if endpoint will be streaming data to client
	Streaming bool
}

// ServeHTTP encapsulates the call to underlying Handlers to handle the request
// and return the response with a proper HTTP status code
func (se *serverEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	log.Debugf("Received request for %s", url)
	err := se.validateMethod(r)
	var resp interface{}
	if err == nil {
		if r.Method == "GET" && se.Streaming {
			log.Debug("Response will be streamed back to client")
			w.Header().Set("Connection", "Keep-Alive")
			w.Header().Set("Transfer-Encoding", "chunked")
			// Write the beginning of the JSON object
			w.Write([]byte("{\"result\":{"))
		}
		resp, err = se.Handler(newServerRequestContext(r, w, se))
	}
	if r.Method == "HEAD" {
		w.Header().Set("Content-Length", "0")
		he := getHTTPErr(err)
		if he != nil {
			w.WriteHeader(he.scode)
			log.Infof(`%s %s %s %d %d "%s"`, r.RemoteAddr, r.Method, r.URL, he.scode, he.lcode, he.lmsg)
		} else {
			w.WriteHeader(se.getSuccessRC())
			log.Infof(`%s %s %s %d 0 "OK"`, r.RemoteAddr, r.Method, r.URL, se.getSuccessRC())
		}
	} else if err == nil {
		w.WriteHeader(se.getSuccessRC())
		if r.Method == "GET" && se.Streaming {
			msg := ", \"errors\":[], \"messages\":[],\"success\":\"true\"}"
			w.Write([]byte(msg))
			w.(http.Flusher).Flush()
		} else {
			err = api.SendResponse(w, resp)
			if err != nil {
				log.Warning("Failed to send response for %s: %+v", url, err)
			}
		}
		log.Infof(`%s %s %s %d 0 "OK"`, r.RemoteAddr, r.Method, r.URL, se.getSuccessRC())
	} else {
		he := getHTTPErr(err)
		if r.Method == "GET" && se.Streaming {
			msg := fmt.Sprintf("]}, \"errors\":[{\"code\":%d,\"message\":\"%s\"}], \"messages\":[], \"success\":\"false\"}", he.rcode, he.rmsg)
			w.Write([]byte(msg))
			w.(http.Flusher).Flush()
		} else {
			he.writeResponse(w)
		}
		log.Debugf("Sent error for %s: %+v", url, err)
		log.Infof(`%s %s %s %d %d "%s"`, r.RemoteAddr, r.Method, r.URL, he.scode, he.lcode, he.lmsg)
	}
}

func (se *serverEndpoint) getSuccessRC() int {
	if se.successRC == 0 {
		return 200
	}
	return se.successRC
}

// Validate that the HTTP method is supported for this endpoint
func (se *serverEndpoint) validateMethod(r *http.Request) error {
	for _, m := range se.Methods {
		if m == r.Method {
			return nil
		}
	}
	return newHTTPErr(405, ErrMethodNotAllowed, "Method %s is not allowed", r.Method)
}

// Get the top-most HTTP error from the cause stack.
// If not found, create one with an unknown error code.
func getHTTPErr(err error) *httpErr {
	if err == nil {
		return nil
	}
	type causer interface {
		Cause() error
	}
	curErr := err
	for curErr != nil {
		switch curErr.(type) {
		case *httpErr:
			return curErr.(*httpErr)
		case causer:
			curErr = curErr.(causer).Cause()
		default:
			return createHTTPErr(500, ErrUnknown, err.Error())
		}
	}
	return createHTTPErr(500, ErrUnknown, "nil error")
}
