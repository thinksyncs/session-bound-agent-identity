// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ultravioletrs/cocos/pkg/agtp"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/atls/ea"
	"github.com/ultravioletrs/cocos/pkg/atls/identitypolicy"
)

func TestAGTPObservedIdentityAcceptsSessionBoundJWT(t *testing.T) {
	now := time.Now()
	validation := validationResultForAGTP(t)
	expectedBinding, err := atls.IdentityBindingFromValidation(validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}

	grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    agtp.TokenTypeIdentityGrant,
		"agtp_version": agtp.ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
	})
	bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              agtp.TokenTypeSessionBinding,
		"agtp_version":           agtp.ProfileVersion,
		"grant_hash":             agtp.IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": expectedBinding.LeafPublicKeySHA256,
		"request_context_sha256": expectedBinding.RequestContextSHA256,
		"nonce":                  "nonce-1",
	})
	cfg := AttestedClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWT:   grantToken,
		IdentityBindingJWT: bindingToken,
		IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
			Now:              now,
		},
		IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
			Now:              now,
		},
		IdentityReplay: identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now }),
	}

	observedIdentity, err := cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() error = %v", err)
	}
	assertion, err := observedIdentity(&tls.ConnectionState{}, validation)
	if err != nil {
		t.Fatalf("observed identity error = %v", err)
	}
	if assertion.Values.Service != "payments" {
		t.Fatalf("assertion service = %q, want payments", assertion.Values.Service)
	}
	if assertion.Binding.LeafPublicKeySHA256 != expectedBinding.LeafPublicKeySHA256 {
		t.Fatalf("assertion leaf binding = %q, want %q", assertion.Binding.LeafPublicKeySHA256, expectedBinding.LeafPublicKeySHA256)
	}
}

func TestAGTPObservedIdentityAcceptsManagerIssuedGrantE2E(t *testing.T) {
	now := time.Now()
	validation := validationResultForAGTP(t)
	expectedBinding, err := atls.IdentityBindingFromValidation(validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}

	manager := clientTestJWTIssuer{keyID: "manager-key", secret: []byte("manager-secret")}
	agent := clientTestJWTIssuer{keyID: "agent-key-1", secret: []byte("agent-secret")}
	grantToken := manager.issueIdentityGrant(t, now, map[string]any{
		"service": "payments",
	})
	bindingToken := agent.issueSessionBinding(t, now, agtp.IdentityGrantHash(grantToken), expectedBinding, nil)
	cfg := AttestedClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWT:   grantToken,
		IdentityBindingJWT: bindingToken,
		IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
			Now:              now,
		},
		IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
			Now:              now,
		},
		IdentityReplay: identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now }),
	}

	observedIdentity, err := cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() error = %v", err)
	}
	assertion, err := observedIdentity(&tls.ConnectionState{}, validation)
	if err != nil {
		t.Fatalf("observed identity error = %v", err)
	}
	if assertion.Values.Agent != "agent-a" {
		t.Fatalf("assertion agent = %q, want agent-a", assertion.Values.Agent)
	}
	if assertion.Binding.Nonce != "nonce-1" {
		t.Fatalf("assertion binding nonce = %q, want nonce-1", assertion.Binding.Nonce)
	}
}

func TestAGTPObservedIdentityAcceptsHTTPJWKSAndRejectsRevocation(t *testing.T) {
	now := time.Now()
	validation := validationResultForAGTP(t)
	expectedBinding, err := atls.IdentityBindingFromValidation(validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}

	manager := clientTestJWTIssuer{keyID: "manager-key", secret: []byte("manager-secret")}
	agent := clientTestJWTIssuer{keyID: "agent-key-1", secret: []byte("agent-secret")}
	grantToken := manager.issueIdentityGrant(t, now, map[string]any{
		"service": "payments",
	})
	bindingToken := agent.issueSessionBinding(t, now, agtp.IdentityGrantHash(grantToken), expectedBinding, nil)
	registry := newClientTestIdentityRegistry(t, map[string][]byte{
		"manager-key": []byte("manager-secret"),
		"agent-key-1": []byte("agent-secret"),
	}, nil)

	cfg := AttestedClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWT:   grantToken,
		IdentityBindingJWT: bindingToken,
		IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          registry.keyFunc(t),
			RevokedJWTIDs:    registry.revokedJWTIDs(t),
			Now:              now,
		},
		IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          registry.keyFunc(t),
			Now:              now,
		},
		IdentityReplay: identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now }),
	}
	observedIdentity, err := cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() error = %v", err)
	}
	if _, err := observedIdentity(&tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("observed identity error = %v", err)
	}

	revokedRegistry := newClientTestIdentityRegistry(t, map[string][]byte{
		"manager-key": []byte("manager-secret"),
		"agent-key-1": []byte("agent-secret"),
	}, []string{"grant-1"})
	cfg.IdentityGrantJWTOptions.KeyFunc = revokedRegistry.keyFunc(t)
	cfg.IdentityGrantJWTOptions.RevokedJWTIDs = revokedRegistry.revokedJWTIDs(t)
	cfg.IdentityBindingJWTOptions.KeyFunc = revokedRegistry.keyFunc(t)
	cfg.IdentityReplay = identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now })
	observedIdentity, err = cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() with revocation source error = %v", err)
	}
	_, err = observedIdentity(&tls.ConnectionState{}, validation)
	if !errors.Is(err, agtp.ErrRevokedJWTID) {
		t.Fatalf("revoked observed identity error = %v, want %v", err, agtp.ErrRevokedJWTID)
	}
}

func TestAGTPObservedIdentityRedTeamRejectsAttacks(t *testing.T) {
	now := time.Now()
	validation := validationResultForAGTP(t)
	expectedBinding, err := atls.IdentityBindingFromValidation(validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}

	baseGrantClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss":          "manager",
			"sub":          "agent-a",
			"aud":          "client-a",
			"jti":          "grant-1",
			"iat":          now.Unix(),
			"exp":          now.Add(time.Minute).Unix(),
			"agtp_type":    agtp.TokenTypeIdentityGrant,
			"agtp_version": agtp.ProfileVersion,
			"cnf":          map[string]any{"kid": "agent-key-1"},
			"service":      "payments",
			"tenant":       "tenant-a",
			"deployment":   "prod",
		}
	}
	baseBindingClaims := func(grantToken string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss":                    "agent-a",
			"aud":                    "client-a",
			"jti":                    "binding-1",
			"iat":                    now.Unix(),
			"exp":                    now.Add(time.Minute).Unix(),
			"agtp_type":              agtp.TokenTypeSessionBinding,
			"agtp_version":           agtp.ProfileVersion,
			"grant_hash":             agtp.IdentityGrantHash(grantToken),
			"leaf_public_key_sha256": expectedBinding.LeafPublicKeySHA256,
			"request_context_sha256": expectedBinding.RequestContextSHA256,
			"nonce":                  "nonce-1",
		}
	}
	runObservedIdentity := func(grantToken, bindingToken string) error {
		cfg := AttestedClientConfig{
			IdentityPolicy: identitypolicy.Policy{
				Require: identitypolicy.Requirements{L3: true},
				Expected: identitypolicy.Values{
					Service:    "payments",
					Tenant:     "tenant-a",
					Deployment: "prod",
				},
			},
			IdentityGrantJWT:   grantToken,
			IdentityBindingJWT: bindingToken,
			IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
				ExpectedIssuer:   "manager",
				ExpectedAudience: "client-a",
				ValidMethods:     []string{"HS256"},
				KeyFunc:          clientTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
				Now:              now,
			},
			IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
				ExpectedIssuer:   "agent-a",
				ExpectedAudience: "client-a",
				ValidMethods:     []string{"HS256"},
				KeyFunc:          clientTestKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
				Now:              now,
			},
			IdentityReplay: identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now }),
		}
		observedIdentity, err := cfg.AGTPObservedIdentity()
		if err != nil {
			return err
		}
		_, err = observedIdentity(&tls.ConnectionState{}, validation)
		return err
	}

	t.Run("peer-signed grant cannot impersonate manager", func(t *testing.T) {
		grant := baseGrantClaims()
		grantToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), grant)
		bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), baseBindingClaims(grantToken))

		if err := runObservedIdentity(grantToken, bindingToken); err == nil {
			t.Fatal("observed identity error = nil, want peer-signed grant rejection")
		}
	})

	t.Run("diverted service identity cannot satisfy local policy", func(t *testing.T) {
		grant := baseGrantClaims()
		grant["service"] = "analytics"
		grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), grant)
		bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), baseBindingClaims(grantToken))

		err := runObservedIdentity(grantToken, bindingToken)
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("observed identity error = %v, want %v", err, identitypolicy.ErrMismatch)
		}
	})

	t.Run("diverted tenant or deployment cannot satisfy local policy", func(t *testing.T) {
		tests := []struct {
			name  string
			field string
			value string
		}{
			{name: "tenant", field: "tenant", value: "tenant-b"},
			{name: "deployment", field: "deployment", value: "staging"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				grant := baseGrantClaims()
				grant[tt.field] = tt.value
				grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), grant)
				bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), baseBindingClaims(grantToken))

				err := runObservedIdentity(grantToken, bindingToken)
				if !errors.Is(err, identitypolicy.ErrMismatch) {
					t.Fatalf("observed identity error = %v, want %v", err, identitypolicy.ErrMismatch)
				}
			})
		}
	})

	t.Run("borrowed binding cannot satisfy accepted aTLS session", func(t *testing.T) {
		grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), baseGrantClaims())
		binding := baseBindingClaims(grantToken)
		binding["leaf_public_key_sha256"] = "sha256:other-leaf"
		bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), binding)

		err := runObservedIdentity(grantToken, bindingToken)
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("observed identity error = %v, want %v", err, identitypolicy.ErrMismatch)
		}
	})

	t.Run("borrowed request context cannot satisfy accepted aTLS session", func(t *testing.T) {
		grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), baseGrantClaims())
		binding := baseBindingClaims(grantToken)
		binding["request_context_sha256"] = "sha256:other-context"
		bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), binding)

		err := runObservedIdentity(grantToken, bindingToken)
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("observed identity error = %v, want %v", err, identitypolicy.ErrMismatch)
		}
	})
}

func TestAGTPObservedIdentityRedTeamRejectsReplay(t *testing.T) {
	now := time.Now()
	validation := validationResultForAGTP(t)
	expectedBinding, err := atls.IdentityBindingFromValidation(validation)
	if err != nil {
		t.Fatalf("IdentityBindingFromValidation() error = %v", err)
	}

	grantToken := signClientTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    agtp.TokenTypeIdentityGrant,
		"agtp_version": agtp.ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "payments",
	})
	bindingToken := signClientTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              agtp.TokenTypeSessionBinding,
		"agtp_version":           agtp.ProfileVersion,
		"grant_hash":             agtp.IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": expectedBinding.LeafPublicKeySHA256,
		"request_context_sha256": expectedBinding.RequestContextSHA256,
		"nonce":                  "nonce-1",
	})
	cfg := AttestedClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWT:   grantToken,
		IdentityBindingJWT: bindingToken,
		IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
			Now:              now,
		},
		IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
			Now:              now,
		},
		IdentityReplay: identitypolicy.NewMemoryReplayCacheWithClock(func() time.Time { return now }),
	}

	observedIdentity, err := cfg.AGTPObservedIdentity()
	if err != nil {
		t.Fatalf("AGTPObservedIdentity() error = %v", err)
	}
	if _, err := observedIdentity(&tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("first observed identity error = %v", err)
	}
	_, err = observedIdentity(&tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("replay observed identity error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestAGTPObservedIdentityRejectsPartialJWTConfig(t *testing.T) {
	cfg := AttestedClientConfig{
		IdentityGrantJWT: "grant",
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
	}

	_, err := cfg.AGTPObservedIdentity()
	if !errors.Is(err, ErrInvalidIdentityJWTConfig) {
		t.Fatalf("AGTPObservedIdentity() error = %v, want %v", err, ErrInvalidIdentityJWTConfig)
	}
}

func TestAGTPObservedIdentityRejectsMissingPolicy(t *testing.T) {
	cfg := AttestedClientConfig{
		IdentityGrantJWT:   "grant",
		IdentityBindingJWT: "binding",
	}

	_, err := cfg.AGTPObservedIdentity()
	if !errors.Is(err, ErrInvalidIdentityJWTConfig) {
		t.Fatalf("AGTPObservedIdentity() error = %v, want %v", err, ErrInvalidIdentityJWTConfig)
	}
}

func TestAGTPObservedIdentityRejectsMissingJWTOptions(t *testing.T) {
	cfg := AttestedClientConfig{
		IdentityGrantJWT:   "grant",
		IdentityBindingJWT: "binding",
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
	}

	_, err := cfg.AGTPObservedIdentity()
	if !errors.Is(err, ErrInvalidIdentityJWTConfig) || !errors.Is(err, agtp.ErrMissingKeyFunc) {
		t.Fatalf("AGTPObservedIdentity() error = %v, want invalid config with missing key func", err)
	}
}

func TestAGTPObservedIdentityRejectsMissingReplayCache(t *testing.T) {
	cfg := AttestedClientConfig{
		IdentityGrantJWT:   "grant",
		IdentityBindingJWT: "binding",
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		},
		IdentityBindingJWTOptions: agtp.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          clientTestKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		},
	}

	_, err := cfg.AGTPObservedIdentity()
	if !errors.Is(err, ErrInvalidIdentityJWTConfig) {
		t.Fatalf("AGTPObservedIdentity() error = %v, want %v", err, ErrInvalidIdentityJWTConfig)
	}
}

func validationResultForAGTP(t *testing.T) *ea.ValidationResult {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agtp-client-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ea.ValidationResult{
		Context: []byte("agtp-request-context"),
		Chain:   []*x509.Certificate{leaf},
	}
}

func signClientTestJWT(t *testing.T, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func clientTestKeyFunc(keys map[string][]byte) agtp.KeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, agtp.ErrMissingKeyID
		}
		return key, nil
	}
}

type clientTestJWTIssuer struct {
	keyID  string
	secret []byte
}

func (i clientTestJWTIssuer) issueIdentityGrant(t *testing.T, now time.Time, overrides map[string]any) string {
	t.Helper()

	claims := jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    agtp.TokenTypeIdentityGrant,
		"agtp_version": agtp.ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	}
	for key, value := range overrides {
		claims[key] = value
	}
	return signClientTestJWT(t, i.keyID, i.secret, claims)
}

func (i clientTestJWTIssuer) issueSessionBinding(t *testing.T, now time.Time, grantHash string, binding identitypolicy.Binding, overrides map[string]any) string {
	t.Helper()

	claims := jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              agtp.TokenTypeSessionBinding,
		"agtp_version":           agtp.ProfileVersion,
		"grant_hash":             grantHash,
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  "nonce-1",
	}
	if binding.AttestationBinderSHA256 != "" {
		claims["attestation_binder_sha256"] = binding.AttestationBinderSHA256
	}
	for key, value := range overrides {
		claims[key] = value
	}
	return signClientTestJWT(t, i.keyID, i.secret, claims)
}

type clientTestIdentityRegistry struct {
	server *httptest.Server
	client *http.Client
}

func newClientTestIdentityRegistry(t *testing.T, keys map[string][]byte, revokedJWTIDs []string) *clientTestIdentityRegistry {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		type jwk struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			Key     string `json:"k"`
		}
		resp := struct {
			Keys []jwk `json:"keys"`
		}{}
		for keyID, key := range keys {
			resp.Keys = append(resp.Keys, jwk{
				KeyType: "oct",
				KeyID:   keyID,
				Key:     base64.RawURLEncoding.EncodeToString(key),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode jwks response: %v", err)
		}
	})
	mux.HandleFunc("/revocations", func(w http.ResponseWriter, _ *http.Request) {
		resp := struct {
			RevokedJWTIDs []string `json:"revoked_jtis"`
		}{
			RevokedJWTIDs: revokedJWTIDs,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode revocations response: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &clientTestIdentityRegistry{
		server: server,
		client: server.Client(),
	}
}

func (r *clientTestIdentityRegistry) keyFunc(t *testing.T) agtp.KeyFunc {
	t.Helper()

	return func(keyID string) (interface{}, error) {
		resp, err := r.client.Get(r.server.URL + "/jwks")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, agtp.ErrUnknownKeyID
		}
		var keySet struct {
			Keys []struct {
				KeyType string `json:"kty"`
				KeyID   string `json:"kid"`
				Key     string `json:"k"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
			return nil, err
		}
		for _, key := range keySet.Keys {
			if key.KeyType != "oct" || key.KeyID != keyID {
				continue
			}
			secret, err := base64.RawURLEncoding.DecodeString(key.Key)
			if err != nil {
				return nil, err
			}
			return secret, nil
		}
		return nil, agtp.ErrUnknownKeyID
	}
}

func (r *clientTestIdentityRegistry) revokedJWTIDs(t *testing.T) []string {
	t.Helper()

	resp, err := r.client.Get(r.server.URL + "/revocations")
	if err != nil {
		t.Fatalf("fetch revocations: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch revocations status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		RevokedJWTIDs []string `json:"revoked_jtis"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode revocations: %v", err)
	}
	return body.RevokedJWTIDs
}
