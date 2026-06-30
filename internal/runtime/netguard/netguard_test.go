// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net/url"
	"testing"
)

func TestPlaintextTargetAllowed(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "unix URI", target: "unix:///run/agents-secure-binding/agent.sock", want: true},
		{name: "absolute socket path", target: "/run/agents-secure-binding/agent.sock", want: true},
		{name: "relative socket path", target: "./agent.sock", want: true},
		{name: "localhost TCP", target: "localhost:7001", want: true},
		{name: "IPv4 loopback TCP", target: "127.0.0.1:7001", want: true},
		{name: "IPv6 loopback TCP", target: "[::1]:7001", want: true},
		{name: "all interfaces", target: "0.0.0.0:7001", want: false},
		{name: "remote host", target: "agent.example.com:7001", want: false},
		{name: "empty", target: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PlaintextTargetAllowed(tt.target); got != tt.want {
				t.Fatalf("PlaintextTargetAllowed(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestInsecureHTTPAllowed(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   bool
	}{
		{name: "localhost http", rawURL: "http://localhost:4318", want: true},
		{name: "loopback http", rawURL: "http://127.0.0.1:4318", want: true},
		{name: "remote http", rawURL: "http://collector.example.com:4318", want: false},
		{name: "remote https", rawURL: "https://collector.example.com:4318", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			if got := InsecureHTTPAllowed(*parsed); got != tt.want {
				t.Fatalf("InsecureHTTPAllowed(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}
