// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cvm

import (
	"github.com/thinksyncs/agtp-atls-profile/agent/cvms"
	"github.com/thinksyncs/agtp-atls-profile/pkg/clients"
	"github.com/thinksyncs/agtp-atls-profile/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewCVMClient(cfg clients.StandardClientConfig) (grpc.Client, cvms.ServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cvms.NewServiceClient(client.Connection()), nil
}
