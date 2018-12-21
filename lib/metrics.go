/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import "github.com/hyperledger/fabric/common/metrics"

var (
	apiCounterOpts = metrics.CounterOpts{
		Namespace:    "api_request",
		Subsystem:    "",
		Name:         "count",
		Help:         "Number of requests made to an API",
		LabelNames:   []string{"ca_name", "api_name"},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{api_name}",
	}

	apiErrorCounterOpts = metrics.CounterOpts{
		Namespace:    "api_request",
		Subsystem:    "",
		Name:         "error_count",
		Help:         "Number of errors that have occurred for requests to an API",
		LabelNames:   []string{"ca_name", "api_name", "error_code"},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{api_name}.%{error_code}",
	}

	apiDurationOpts = metrics.HistogramOpts{
		Namespace:    "api_request",
		Subsystem:    "",
		Name:         "duration",
		Help:         "Time taken in seconds for the request to an API to be completed",
		LabelNames:   []string{"ca_name", "api_name"},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{api_name}",
	}
)

// Metrics are the metrics tracked by server
type Metrics struct {
	// APICounter keeps track of number of times an API endpoint is called
	APICounter metrics.Counter
	// APIErrorCounter keeps track of number of errors that have occured on requests to an API
	APIErrorCounter metrics.Counter
	// APIDuration keeps track of time taken for request to complete for an API
	APIDuration metrics.Histogram
}
