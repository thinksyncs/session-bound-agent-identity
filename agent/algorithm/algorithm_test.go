// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestAlgorithmTypeFromContext(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(AlgoTypeKey, string(AlgoTypePython)))

	assert.Equal(t, string(AlgoTypePython), AlgorithmTypeFromContext(ctx))
}

func TestAlgorithmTypeFromContextMissingMetadata(t *testing.T) {
	assert.Empty(t, AlgorithmTypeFromContext(context.Background()))
}
