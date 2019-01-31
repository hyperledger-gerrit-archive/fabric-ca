/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"context"
	"strings"
	"testing"

	docker "github.com/docker/docker/client"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestRunner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Runner Suite")
}

func ContainerExists(ctx context.Context, client *docker.Client, name string) func() bool {
	return func() bool {
		_, err := client.ContainerInspect(ctx, name)
		if strings.Contains(err.Error(), "NoSuch") {
			return false
		}
		return false
	}
}
