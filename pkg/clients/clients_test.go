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
	"errors"
	"math/big"
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
