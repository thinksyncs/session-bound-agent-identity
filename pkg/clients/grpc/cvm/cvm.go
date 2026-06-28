// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cvm

import (
	"github.com/thinksyncs/agents-secure-binding/agent/cvms"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewCVMClient(cfg clients.StandardClientConfig) (grpc.Client, cvms.ServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cvms.NewServiceClient(client.Connection()), nil
}
