// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"testing"
)

func TestValidateAcceptsMatchingRequiredLayers(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L2B: true,
			L3:  true,
			L4:  true,
			L5:  true,
		},
		Expected: Values{
			Service:              "payments",
			Tenant:               "tenant-a",
			Deployment:           "prod",
			Environment:          "us-east",
			Workload:             "settlement",
			Agent:                "agent-a",
			AgentPublicKey:       "agent-key",
			ComputationID:        "cmp-1",
			TaskID:               "task-1",
			ThreadID:             "thread-1",
			DelegationID:         "delegation-1",
			Scopes:               []string{"read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	observed := Values{
		Service:              "payments",
		Tenant:               "tenant-a",
		Deployment:           "prod",
		Environment:          "us-east",
		Workload:             "settlement",
		Agent:                "agent-a",
		AgentPublicKey:       "agent-key",
		ComputationID:        "cmp-1",
		TaskID:               "task-1",
		ThreadID:             "thread-1",
		DelegationID:         "delegation-1",
		Scopes:               []string{"read:orders", "write:audit"},
		Resources:            []string{"orders", "audit-log"},
		AuthorizationDetails: []string{"settle", "notify"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingExpectedValue(t *testing.T) {
	policy := Policy{
		Require: Requirements{L2B: true},
	}

	err := Validate(policy, Values{Service: "payments"})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsMissingObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Validate() error = %T, want *ValidationError", err)
	}
	if validationErr.Layer != LayerL3 || validationErr.Field != "agent" {
		t.Fatalf("Validate() error layer/field = %s/%s", validationErr.Layer, validationErr.Field)
	}
}

func TestValidateRejectsMismatchedObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{ComputationID: "cmp-1"},
	}

	err := Validate(policy, Values{ComputationID: "cmp-2"})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateRejectsMissingScope(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{Scopes: []string{"read:orders", "write:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders"}})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateSkipsUnrequiredLayers(t *testing.T) {
	policy := Policy{
		Expected: Values{
			Service: "payments",
			Agent:   "agent-a",
		},
	}

	if err := Validate(policy, Values{}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
