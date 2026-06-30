// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

func TestNewProviderRejectsRemoteHTTPTraceURL(t *testing.T) {
	traceURL, err := url.Parse("http://collector.example.com:4318")
	if err != nil {
		t.Fatal(err)
	}

	provider, err := NewProvider(context.Background(), "manager", *traceURL, "instance-a", 1)

	if provider != nil {
		t.Fatal("expected nil provider")
	}
	if !errors.Is(err, ErrInsecureTraceURL) {
		t.Fatalf("NewProvider() error = %v, want %v", err, ErrInsecureTraceURL)
	}
}
