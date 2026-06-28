// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"github.com/thinksyncs/agents-secure-binding/manager"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg clients.StandardClientConfig) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, manager.NewManagerServiceClient(client.Connection()), nil
}
