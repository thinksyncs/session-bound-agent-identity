// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"github.com/thinksyncs/agtp-atls-profile/manager"
	"github.com/thinksyncs/agtp-atls-profile/pkg/clients"
	"github.com/thinksyncs/agtp-atls-profile/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg clients.StandardClientConfig) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, manager.NewManagerServiceClient(client.Connection()), nil
}
