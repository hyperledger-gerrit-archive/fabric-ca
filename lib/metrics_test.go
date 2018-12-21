/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	. "github.com/onsi/gomega"
)

func TestAPICountMetric(t *testing.T) {
	gt := NewGomegaWithT(t)

	se := &serverEndpoint{
		Path: "/test",
	}

	router := mux.NewRouter()
	router.Handle(se.Path, se).Name(se.Path)

	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	fakeErrCounter := &metricsfakes.Counter{}
	fakeErrCounter.WithReturns(fakeErrCounter)
	fakeHist := &metricsfakes.Histogram{}
	fakeHist.WithReturns(fakeHist)
	server := &Server{
		CA: CA{
			Config: &CAConfig{
				CA: CAInfo{
					Name: "ca1",
				},
			},
		},
		Metrics: Metrics{
			APICounter:      fakeCounter,
			APIErrorCounter: fakeErrCounter,
			APIDuration:     fakeHist,
		},
		mux: router,
	}

	server.mux.Use(server.middleware)
	se.Server = server

	req, err := http.NewRequest("GET", se.Path, nil)
	gt.Expect(err).NotTo(HaveOccurred())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	gt.Expect(fakeCounter.AddCallCount()).To(Equal(1))
	gt.Expect(fakeCounter.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeCounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test"}))

	gt.Expect(fakeErrCounter.AddCallCount()).To(Equal(1))
	gt.Expect(fakeErrCounter.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeErrCounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test", "error_code", "405"}))

	gt.Expect(fakeHist.ObserveCallCount()).To(Equal(1))
	gt.Expect(fakeHist.WithArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeHist.WithArgsForCall(0)).To(Equal([]string{"ca_name", "ca1", "api_name", "/test"}))
}
