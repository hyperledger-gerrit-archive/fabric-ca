/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import "github.com/hyperledger/fabric/common/metrics"

var (
	// APICounterOpts define the counter opts for database APIs
	APICounterOpts = metrics.CounterOpts{
		Namespace:  "db_api_request",
		Subsystem:  "",
		Name:       "count",
		Help:       "Number of requests made to a database API",
		LabelNames: []string{"ca_name", "func_name", "dbapi_name"},
		LabelHelp: map[string]string{
			"dbapi_name":  "example dbapi_names: affiliations/{affiliation}, affiliations, certificates, enroll, reenroll, gencrl, idemix/cri, identities, register, revoke, tcert,  idemix/credential, identities/{id}. ",
			"status_code": "Http status code. https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
		},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{func_name}.%{dbapi_name}",
	}

	// APIDurationOpts define the duration opts for database APIs
	APIDurationOpts = metrics.HistogramOpts{
		Namespace:  "db_api_request",
		Subsystem:  "",
		Name:       "duration",
		Help:       "Time taken in seconds for the request to a database API to be completed",
		LabelNames: []string{"ca_name", "func_name", "dbapi_name"},
		LabelHelp: map[string]string{
			"dbapi_name":  "example dbapi_names: affiliations/{affiliation}, affiliations, certificates, enroll, reenroll, gencrl, idemix/cri, identities, register, revoke, tcert,  idemix/credential, identities/{id}. ",
			"status_code": "Http status code. https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
		},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{func_name}.%{dbapi_name}",
	}
)

// Metrics is the set of meters for the database
type Metrics struct {
	// APICounter keeps track of number of times a database API is called
	APICounter metrics.Counter
	// APIDuration keeps track of time taken for request to complete to a database API
	APIDuration metrics.Histogram
}
