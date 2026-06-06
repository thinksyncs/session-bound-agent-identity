// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ultravioletrs/cocos/pkg/atls/identitypolicy"
)

func TestVerifyIdentityGrantJWTMapsClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
		"tenant":       "tenant-a",
		"deployment":   "prod",
		"scope":        "orders:read orders:write",
		"resource":     "orders",
	})

	grant, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}

	if grant.Issuer != "manager" || grant.Audience != "client-a" {
		t.Fatalf("grant issuer/audience = %q/%q", grant.Issuer, grant.Audience)
	}
	if grant.ConfirmationKey != "agent-key-1" {
		t.Fatalf("grant confirmation key = %q, want agent-key-1", grant.ConfirmationKey)
	}
	if grant.GrantHash != IdentityGrantHash(tokenString) {
		t.Fatalf("grant hash = %q, want profile hash", grant.GrantHash)
	}
	if grant.Values.Agent != "agent-a" {
		t.Fatalf("grant agent = %q, want sub fallback", grant.Values.Agent)
	}
	if !slices.Equal(grant.Values.Scopes, []string{"orders:read", "orders:write"}) {
		t.Fatalf("grant scopes = %#v", grant.Values.Scopes)
	}
	if !slices.Equal(grant.Values.Resources, []string{"orders"}) {
		t.Fatalf("grant resources = %#v", grant.Values.Resources)
	}
}

func TestVerifyIdentityGrantJWTAcceptsLocalKeySet(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	grant, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}
	if grant.ConfirmationKey != "agent-key-1" {
		t.Fatalf("grant confirmation key = %q, want agent-key-1", grant.ConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsDisabledLocalKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret"), Disabled: true},
		},
		Now: now,
	})
	if !errors.Is(err, ErrDisabledKeyID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrDisabledKeyID)
	}
}

func TestVerifyIdentityGrantJWTRejectsDisabledKeyFuncKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc: testKeyFunc(map[string][]byte{
			"manager-key": []byte("manager-secret"),
		}),
		DisabledKeyIDs: []string{"manager-key"},
		Now:            now,
	})
	if !errors.Is(err, ErrDisabledKeyID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrDisabledKeyID)
	}
}

func TestVerifyIdentityGrantJWTRejectsRevokedGrantID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		RevokedJWTIDs: []string{"grant-1"},
		Now:           now,
	})
	if !errors.Is(err, ErrRevokedJWTID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrRevokedJWTID)
	}
}

func TestVerifyIdentityGrantJWTRejectsAmbiguousKeySource(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		Now: now,
	})
	if !errors.Is(err, ErrAmbiguousKeySource) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrAmbiguousKeySource)
	}
}

func TestVerifyIdentityGrantJWTRejectsMissingConfirmationKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingConfirmationKey) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsThumbprintOnlyConfirmation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"jkt": "agent-key-thumbprint"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingConfirmationKey) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsWrongTokenType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeSessionBinding,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrInvalidTokenType) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrInvalidTokenType)
	}
}

func TestVerifyIdentityGrantJWTRejectsMissingJWTID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingJWTID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingJWTID)
	}
}

func TestVerifySessionBindingJWTFeedsIdentityPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	grant, err := VerifyIdentityGrantJWT(grantToken, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}

	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                       "agent-a",
		"aud":                       "client-a",
		"jti":                       "binding-1",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Minute).Unix(),
		"agtp_type":                 TokenTypeSessionBinding,
		"agtp_version":              ProfileVersion,
		"grant_hash":                grant.GrantHash,
		"leaf_public_key_sha256":    "sha256:leaf",
		"request_context_sha256":    "sha256:context",
		"attestation_binder_sha256": "sha256:binder",
		"nonce":                     "nonce-1",
	})
	statement, err := VerifySessionBindingJWT(bindingToken, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifySessionBindingJWT() error = %v", err)
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}

	policy := identitypolicy.Policy{
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service:    "payments",
			Deployment: "prod",
			Agent:      "agent-a",
			TaskID:     "task-1",
			Scopes:     []string{"orders:read"},
		},
	}
	expectedBinding := identitypolicy.Binding{
		LeafPublicKeySHA256:     "sha256:leaf",
		RequestContextSHA256:    "sha256:context",
		AttestationBinderSHA256: "sha256:binder",
		Nonce:                   "nonce-1",
	}
	if err := identitypolicy.ValidateAssertion(policy, assertion, expectedBinding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}
}

func TestVerifySessionIdentityJWTAcceptsManagerGrantAndLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	grantHash := IdentityGrantHash(grantToken)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             grantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	result, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if err != nil {
		t.Fatalf("VerifySessionIdentityJWT() error = %v", err)
	}
	if result.Grant.GrantHash != grantHash {
		t.Fatalf("result grant hash = %q, want %q", result.Grant.GrantHash, grantHash)
	}
	if result.Assertion.Values.Service != "payments" {
		t.Fatalf("result service = %q, want payments", result.Assertion.Values.Service)
	}
}

func TestVerifySessionIdentityJWTRejectsPeerSignedGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, ErrMissingKeyID) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, ErrMissingKeyID)
	}
}

func TestVerifySessionIdentityJWTRejectsLocalPolicyMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "wrong-service",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestVerifySessionIdentityJWTRejectsWrongGrantHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             "sha256:other-grant",
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestVerifySessionIdentityJWTRejectsWrongGrantIssuerOrAudience(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name string
		iss  string
		aud  string
	}{
		{name: "wrong issuer", iss: "peer", aud: "client-a"},
		{name: "wrong audience", iss: "manager", aud: "other-client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
				"iss":          tt.iss,
				"sub":          "agent-a",
				"aud":          tt.aud,
				"jti":          "grant-1",
				"iat":          now.Unix(),
				"exp":          now.Add(time.Minute).Unix(),
				"agtp_type":    TokenTypeIdentityGrant,
				"agtp_version": ProfileVersion,
				"cnf":          map[string]any{"kid": "agent-key-1"},
				"service":      "payments",
				"deployment":   "prod",
				"task_id":      "task-1",
				"scope":        "orders:read",
			})
			bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
				"iss":                    "agent-a",
				"aud":                    "client-a",
				"jti":                    "binding-1",
				"iat":                    now.Unix(),
				"exp":                    now.Add(time.Minute).Unix(),
				"agtp_type":              TokenTypeSessionBinding,
				"agtp_version":           ProfileVersion,
				"grant_hash":             IdentityGrantHash(grantToken),
				"leaf_public_key_sha256": "sha256:leaf",
				"request_context_sha256": "sha256:context",
				"nonce":                  "nonce-1",
			})

			if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now)); err == nil {
				t.Fatal("VerifySessionIdentityJWT() error = nil, want issuer or audience failure")
			}
		})
	}
}

func TestVerifySessionIdentityJWTRejectsMissingPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	_, err := VerifySessionIdentityJWT("grant", "binding", SessionIdentityJWTOptions{Now: now})
	if !errors.Is(err, ErrMissingIdentityPolicy) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, ErrMissingIdentityPolicy)
	}
}

func TestVerifySessionIdentityJWTRejectsExpiredGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["exp"] = now.Add(-time.Minute).Unix()
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestVerifySessionIdentityJWTRejectsExpiredSessionBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingClaims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
	bindingClaims["exp"] = now.Add(-time.Minute).Unix()
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), bindingClaims)

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestVerifySessionIdentityJWTRejectsUnauthorizedSessionBindingSigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "other-agent-key", []byte("other-agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.SessionBinding.KeyFunc = testKeyFunc(map[string][]byte{"other-agent-key": []byte("other-agent-secret")})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrUnauthorizedBindingKey)
	}
}

func TestVerifySessionIdentityJWTRejectsReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = newAGTPReplayCache()

	if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() first error = %v", err)
	}
	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("VerifySessionIdentityJWT() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestVerifySessionIdentityJWTDoesNotConsumeReplayOnPolicyMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	replay := newAGTPReplayCache()
	wrongGrantClaims := testDefaultGrantClaims(now)
	wrongGrantClaims["service"] = "analytics"
	wrongGrantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), wrongGrantClaims)
	wrongBindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(wrongGrantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = replay

	err := func() error {
		_, err := VerifySessionIdentityJWT(wrongGrantToken, wrongBindingToken, opts)
		return err
	}()
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() mismatch error = %v, want %v", err, identitypolicy.ErrMismatch)
	}

	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() after mismatch error = %v", err)
	}
}

func TestVerifySessionBindingJWTRejectsWrongSigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := identitypolicy.VerifiedGrant{
		Issuer:          "manager",
		Audience:        "client-a",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-key-1",
		Values:          identitypolicy.Values{Agent: "agent-a"},
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}
	bindingToken := signTestJWT(t, "other-agent-key", []byte("other-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             grant.GrantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})
	statement, err := VerifySessionBindingJWT(bindingToken, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"other-agent-key": []byte("other-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifySessionBindingJWT() error = %v", err)
	}

	_, err = identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, identitypolicy.ErrUnauthorizedBindingKey)
	}
}

func TestVerifySessionBindingJWTRejectsWrongTokenType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                       "agent-a",
		"aud":                       "client-a",
		"jti":                       "binding-1",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Minute).Unix(),
		"agtp_type":                 TokenTypeIdentityGrant,
		"agtp_version":              ProfileVersion,
		"grant_hash":                "sha256:grant",
		"leaf_public_key_sha256":    "sha256:leaf",
		"request_context_sha256":    "sha256:context",
		"attestation_binder_sha256": "sha256:binder",
		"nonce":                     "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrInvalidTokenType) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrInvalidTokenType)
	}
}

func TestVerifySessionBindingJWTRejectsMissingGrantHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingGrantHash) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrMissingGrantHash)
	}
}

func TestVerifySessionBindingJWTRejectsMissingBindingField(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             "sha256:grant",
		"leaf_public_key_sha256": "sha256:leaf",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingBindingField) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrMissingBindingField)
	}
}

func TestVerifyJWTRejectsUnsafeSigningMethodAllowList(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"none"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrUnsafeSigningMethod) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrUnsafeSigningMethod)
	}
}

func signTestJWT(t *testing.T, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func testKeyFunc(keys map[string][]byte) KeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, ErrMissingKeyID
		}
		return key, nil
	}
}

func testDefaultGrantClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	}
}

func testDefaultBindingClaims(now time.Time, grantHash string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             grantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	}
}

type agtpReplayCache struct {
	seen map[string]time.Time
}

func newAGTPReplayCache() *agtpReplayCache {
	return &agtpReplayCache{seen: make(map[string]time.Time)}
}

func (c *agtpReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}

func testSessionIdentityOptions(now time.Time) SessionIdentityJWTOptions {
	return SessionIdentityJWTOptions{
		Grant: JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		},
		SessionBinding: JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		},
		Policy: identitypolicy.Policy{
			Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
			Expected: identitypolicy.Values{
				Service:    "payments",
				Deployment: "prod",
				Agent:      "agent-a",
				TaskID:     "task-1",
				Scopes:     []string{"orders:read"},
			},
		},
		ExpectedBinding: identitypolicy.Binding{
			LeafPublicKeySHA256:  "sha256:leaf",
			RequestContextSHA256: "sha256:context",
			Nonce:                "nonce-1",
		},
		Now: now,
	}
}
