// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/thinksyncs/agents-secure-binding/agent/events"
	logpb "github.com/thinksyncs/agents-secure-binding/agent/log"
	logclient "github.com/thinksyncs/agents-secure-binding/pkg/clients/grpc/log"
)

type adapter struct {
	client logclient.Client
	svc    string
}

func NewAdapter(client logclient.Client, svc string) events.Service {
	return &adapter{
		client: client,
		svc:    svc,
	}
}

func (a *adapter) SendEvent(cmpID, event, status string, details json.RawMessage) {
	err := a.client.SendEvent(context.Background(), &logpb.EventEntry{
		EventType:     event,
		ComputationId: cmpID,
		Details:       details,
		Originator:    a.svc,
		Status:        status,
	})
	if err != nil {
		slog.Error("failed to send event to log-forwarder", "error", err)
	}
}
