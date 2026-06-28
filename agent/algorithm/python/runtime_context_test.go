// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package python

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPythonRunTimeFromContextMissingMetadata(t *testing.T) {
	assert.Empty(t, PythonRunTimeFromContext(context.Background()))
}
