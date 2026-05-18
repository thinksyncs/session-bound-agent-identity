// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLocalBindHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "localhost", host: "localhost", want: true},
		{name: "IPv4 loopback", host: "127.0.0.1", want: true},
		{name: "IPv6 loopback", host: "::1", want: true},
		{name: "bracketed IPv6 loopback", host: "[::1]", want: true},
		{name: "all IPv4 interfaces", host: "0.0.0.0", want: false},
		{name: "all IPv6 interfaces", host: "::", want: false},
		{name: "empty host", host: "", want: false},
		{name: "public host", host: "manager.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLocalBindHost(tt.host))
		})
	}
}
