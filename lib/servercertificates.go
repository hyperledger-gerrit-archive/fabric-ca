/*
Copyright IBM Corp. 2018 All Rights Reserved.

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
)

type certPEM struct {
	PEM string `db:"pem"`
}

func newCertificateEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "DELETE"},
		Handler:   certificatesHandler,
		Server:    s,
		successRC: 200,
	}
}

func certificatesHandler(ctx *serverRequestContext) (interface{}, error) {
	var err error
	// Authenticate
	_, err = ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	err = authChecks(ctx)
	if err != nil {
		return nil, err
	}
	// Process Request
	err = processCertificateRequest(ctx)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func authChecks(ctx *serverRequestContext) error {
	log.Debug("Performing attribute authorization checks for certificates endpoint")

	_, err := ctx.caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		err = ctx.HasRole("hf.Revoker")
		if err != nil {
			return newAuthErr(ErrAuthFailure, "Caller does not posses either hf.Registrar.Roles or hf.Revoker attribute")
		}
	}

	return nil
}

// processCertificateRequest will process the certificate request
func processCertificateRequest(ctx *serverRequestContext) error {
	log.Debug("Processing certificate request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return processGetCertificateRequest(ctx)
	case "DELETE":
		return errors.New("DELETE Not Implemented")
	default:
		return errors.Errorf("Invalid request: %s", method)
	}
}

func processGetCertificateRequest(ctx *serverRequestContext) error {
	log.Debug("Processing GET certificate request")
	var err error

	_, err = getTimes(ctx)
	if err != nil {
		return newHTTPErr(400, ErrGettingCert, "Invalid Request: %s", err)
	}

	return nil
}

type timeFilters struct {
	revokedStart *time.Time
	revokedEnd   *time.Time
	expiredStart *time.Time
	expiredEnd   *time.Time
}

func getTimes(ctx *serverRequestContext) (*timeFilters, error) {
	times := &timeFilters{}
	var err error

	revokedStart := ctx.GetQueryParm("revoked_start")
	if revokedStart != "" {
		times.revokedStart, err = getTime(revokedStart)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid 'revoked_begin' value")
		}
	}

	revokedEnd := ctx.GetQueryParm("revoked_end")
	if revokedEnd != "" {
		times.revokedEnd, err = getTime(revokedEnd)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid 'revoked_end' value")
		}
	}

	expiredStart := ctx.GetQueryParm("expired_start")
	if expiredStart != "" {
		times.expiredStart, err = getTime(expiredStart)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid 'expired_begin' value")
		}
	}

	expiredEnd := ctx.GetQueryParm("expired_end")
	if expiredEnd != "" {
		times.expiredEnd, err = getTime(expiredEnd)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid 'expired_end' value")
		}
	}

	return times, nil
}

func getTime(timeStr string) (*time.Time, error) {
	log.Debugf("Convert time string (%s) to time type", timeStr)

	if strings.HasPrefix(timeStr, "+") || strings.HasPrefix(timeStr, "-") {
		timeStr = strings.ToLower(timeStr)

		if strings.HasSuffix(timeStr, "m") || strings.HasSuffix(timeStr, "y") {
			return nil, errors.Errorf("Invalid time format, month (m) and year (y) are not supported, please check: %s", timeStr)
		}

		currentTime := time.Now().UTC()

		if strings.HasSuffix(timeStr, "d") {
			log.Debug("Duration specified in days, converting to hours")

			re := regexp.MustCompile("\\d+")
			durationValDays, err := strconv.Atoi(re.FindString(timeStr))
			if err != nil {
				return nil, errors.Errorf("Invalid time format, integer values required for duration, please check: %s", timeStr)
			}
			durationValHours := 24 * durationValDays
			timeStr = string(timeStr[0]) + strconv.Itoa(durationValHours) + "h"

			log.Debug("Duration value in hours: ", timeStr)
		}

		dur, err := time.ParseDuration(timeStr)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse duration")
		}
		newTime := currentTime.Add(dur)

		return &newTime, nil
	}

	if !strings.Contains(timeStr, "T") {
		timeStr = timeStr + "T00:00:00Z"
	}

	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, err
	}

	return &parsedTime, nil
}
