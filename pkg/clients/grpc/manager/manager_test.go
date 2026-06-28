// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thinksyncs/hardware-aware-tls-identity-binding/internal/errors"
	"github.com/thinksyncs/hardware-aware-tls-identity-binding/pkg/clients"
)

func TestNewManagerClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  clients.StandardClientConfig
		err  error
	}{
		{
			name: "Valid config",
			cfg: clients.StandardClientConfig{
				URL: "localhost:7001",
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewManagerClient(tt.cfg)
			assert.True(t, errors.Contains(err, tt.err))
		})
	}
}
