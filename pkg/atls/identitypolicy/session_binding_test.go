// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"testing"
	"time"
)

func TestNewAssertionFromSessionBindingAcceptsGrantConfirmationKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)

	assertion, err := NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
	if assertion.Issuer != grant.Issuer {
		t.Fatalf("Assertion.Issuer = %q, want %q", assertion.Issuer, grant.Issuer)
	}
	if assertion.Values.Agent != grant.Values.Agent {
		t.Fatalf("Assertion.Values.Agent = %q, want %q", assertion.Values.Agent, grant.Values.Agent)
	}
	if assertion.Binding.LeafPublicKeySHA256 != statement.Binding.LeafPublicKeySHA256 {
		t.Fatalf("Assertion.Binding.LeafPublicKeySHA256 = %q, want %q",
			assertion.Binding.LeafPublicKeySHA256, statement.Binding.LeafPublicKeySHA256)
	}
}

func TestNewAssertionFromSessionBindingAcceptsGrantAgentPublicKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ConfirmationKey = ""
	statement := testSessionBindingStatement(now)
	statement.SignerKey = grant.Values.AgentPublicKey

	assertion, err := NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}

	policy := Policy{
		Require:  Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: Values{Service: "payments", Agent: "agent-a", TaskID: "task-1", Scopes: []string{"orders:read"}},
	}
	if err := ValidateAssertion(policy, assertion, statement.Binding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingRejectsArbitraryEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.SignerKey = "endpoint-key-not-in-grant"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsIssuerKeyAsBindingKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.IssuerKey = "manager-key-1"
	grant.ConfirmationKey = "manager-key-1"
	statement := testSessionBindingStatement(now)
	statement.SignerKey = "manager-key-1"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsGrantWithoutBindingKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ConfirmationKey = ""
	grant.Values.AgentPublicKey = ""
	grant.AuthorizedEndpointKeys = nil
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMissingExpected)
	}
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeGrantValue(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.Values.Service = "<script>"
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeAuthorizedEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.AuthorizedEndpointKeys = []string{"<script>"}
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestNewAssertionFromSessionBindingAcceptsAuthorizedEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.AuthorizedEndpointKeys = []string{"endpoint-key-bound-by-policy"}
	statement := testSessionBindingStatement(now)
	statement.SignerKey = "endpoint-key-bound-by-policy"

	if _, err := NewAssertionFromSessionBinding(grant, statement, now); err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingWithOptionsRejectsReplay(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	cache := newTestReplayCache()
	opts := SessionBindingOptions{Now: now, ReplayCache: cache}

	if _, err := NewAssertionFromSessionBindingWithOptions(grant, statement, opts); err != nil {
		t.Fatalf("NewAssertionFromSessionBindingWithOptions() first error = %v", err)
	}
	_, err := NewAssertionFromSessionBindingWithOptions(grant, statement, opts)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("NewAssertionFromSessionBindingWithOptions() replay error = %v, want %v", err, ErrReplayDetected)
	}
}

func TestNewAssertionFromSessionBindingRejectsGrantHashMismatch(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.GrantHash = "sha256:other-grant"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMismatch)
	}
}

type testReplayCache struct {
	seen map[string]time.Time
}

func newTestReplayCache() *testReplayCache {
	return &testReplayCache{seen: make(map[string]time.Time)}
}

func (c *testReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}

func TestNewAssertionFromSessionBindingRejectsAudienceMismatch(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Audience = "other-client"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMismatch)
	}
}

func TestNewAssertionFromSessionBindingRejectsMissingRequiredBindingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerifiedSessionBindingStatement)
	}{
		{
			name: "leaf public key hash",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.LeafPublicKeySHA256 = ""
			},
		},
		{
			name: "request context hash",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.RequestContextSHA256 = ""
			},
		},
		{
			name: "nonce",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.Nonce = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			grant := testVerifiedGrant(now)
			statement := testSessionBindingStatement(now)
			tt.mutate(&statement)

			_, err := NewAssertionFromSessionBinding(grant, statement, now)
			if !errors.Is(err, ErrMissingBinding) {
				t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMissingBinding)
			}
		})
	}
}

func TestNewAssertionFromSessionBindingAcceptsMissingOptionalAttestationBinder(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.AttestationBinderSHA256 = ""

	if _, err := NewAssertionFromSessionBinding(grant, statement, now); err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingRejectsExpiredGrant(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ExpiresAt = now.Add(-time.Minute)
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsExpiredStatement(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.ExpiresAt = now.Add(-time.Minute)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsFutureStatementIssueTime(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.IssuedAt = now.Add(time.Minute)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrFutureAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrFutureAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeGrantIssuer(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.Issuer = "<script>"
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func testVerifiedGrant(now time.Time) VerifiedGrant {
	return VerifiedGrant{
		Issuer:          "manager-key-1",
		Audience:        "relying-client",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-confirmation-key",
		Values: Values{
			Service:        "payments",
			Tenant:         "tenant-a",
			Deployment:     "prod",
			Agent:          "agent-a",
			AgentPublicKey: "agent-key",
			TaskID:         "task-1",
			Scopes:         []string{"orders:read"},
		},
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func testSessionBindingStatement(now time.Time) VerifiedSessionBindingStatement {
	return VerifiedSessionBindingStatement{
		GrantHash: "sha256:grant",
		Audience:  "relying-client",
		SignerKey: "agent-confirmation-key",
		Binding: Binding{
			LeafPublicKeySHA256:     "sha256:leaf",
			RequestContextSHA256:    "sha256:context",
			AttestationBinderSHA256: "sha256:binder",
			Nonce:                   "binding-nonce",
			IssuedAt:                now.Add(-time.Minute),
			ExpiresAt:               now.Add(time.Minute),
		},
	}
}
