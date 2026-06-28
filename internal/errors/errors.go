// Copyright (c) 2026 ToppyMicroServices OU
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

func New(text string) error {
	return stderrors.New(text)
}

func Wrap(first, second error) error {
	switch {
	case first == nil:
		return second
	case second == nil:
		return first
	default:
		return fmt.Errorf("%w: %w", first, second)
	}
}

func Contains(err, target error) bool {
	if target == nil {
		return err == nil
	}
	if stderrors.Is(err, target) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), target.Error())
}
