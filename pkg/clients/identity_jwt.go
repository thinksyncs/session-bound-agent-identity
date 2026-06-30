// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

var (
	ErrMissingKeyFunc          = errors.New("binding jwt: missing key function")
	ErrMissingLocalKey         = errors.New("binding jwt: missing local key")
	ErrMissingValidMethods     = errors.New("binding jwt: missing allowed signing methods")
	ErrMissingExpectedIssuer   = errors.New("binding jwt: missing expected issuer")
	ErrMissingExpectedAudience = errors.New("binding jwt: missing expected audience")
	ErrMissingConfirmationKey  = errors.New("binding jwt: missing confirmation key")
	ErrMissingKeyID            = errors.New("binding jwt: missing key id")
	ErrUnknownKeyID            = errors.New("binding jwt: unknown key id")
	ErrDisabledKeyID           = errors.New("binding jwt: disabled key id")
	ErrDuplicateKeyID          = errors.New("binding jwt: duplicate key id")
	ErrAmbiguousKeySource      = errors.New("binding jwt: ambiguous key source")
	ErrMissingJWTID            = errors.New("binding jwt: missing jwt id")
	ErrRevokedJWTID            = errors.New("binding jwt: revoked jwt id")
	ErrMissingSubject          = errors.New("binding jwt: missing subject")
	ErrMissingGrantHash        = errors.New("binding jwt: missing grant hash")
	ErrMissingBindingField     = errors.New("binding jwt: missing session binding field")
	ErrMissingIdentityPolicy   = errors.New("binding jwt: missing identity policy")
	ErrMissingReplayCache      = errors.New("binding jwt: missing replay cache")
	ErrInvalidTokenType        = errors.New("binding jwt: invalid token type")
	ErrUnsupportedVersion      = errors.New("binding jwt: unsupported profile version")
	ErrUnsafeSigningMethod     = errors.New("binding jwt: unsafe signing method")
	ErrDuplicateJWTMember      = errors.New("binding jwt: duplicate json member")
)

const (
	ClaimTokenType      = "profile_type"
	ClaimProfileVersion = "profile_version"

	LegacyClaimTokenType      = "agtp_type"
	LegacyClaimProfileVersion = "agtp_version"

	TokenTypeIdentityGrant  = "sbaip.identity-grant"
	TokenTypeSessionBinding = "sbaip.session-binding"

	LegacyTokenTypeIdentityGrant  = "agtp.identity-grant"
	LegacyTokenTypeSessionBinding = "agtp.session-binding"

	ProfileVersion           = "1"
	identityGrantJWTHashSeed = "sbaip.identity-grant.jwt.v1\x00"
)

// KeyFunc resolves a JWT verification key by protected-header key id.
type KeyFunc func(keyID string) (interface{}, error)

// LocalKey is a locally configured JWT verification key.
type LocalKey struct {
	KeyID    string
	Key      interface{}
	Disabled bool
}

// JWTVerifyOptions contains local verification policy for Direct-Agent binding JWTs.
type JWTVerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ValidMethods     []string
	KeyFunc          KeyFunc
	LocalKeys        []LocalKey
	DisabledKeyIDs   []string
	RevokedJWTIDs    []string
	Now              time.Time
}

// SessionIdentityJWTOptions contains the local policy needed to accept a
// manager grant and an agent session-binding statement in one step.
type SessionIdentityJWTOptions struct {
	Grant           JWTVerifyOptions
	SessionBinding  JWTVerifyOptions
	Policy          identitypolicy.Policy
	ExpectedBinding identitypolicy.Binding
	ReplayCache     identitypolicy.ReplayCache
	Now             time.Time
}

// SessionIdentityJWTResult contains the verified identity material accepted by
// VerifySessionIdentityJWT.
type SessionIdentityJWTResult struct {
	Grant     identitypolicy.VerifiedGrant
	Statement identitypolicy.VerifiedSessionBindingStatement
	Assertion identitypolicy.Assertion
}

type bindingJWTClaims struct {
	jwt.RegisteredClaims

	ProfileType     string   `json:"profile_type,omitempty"`
	ProfileVersion  string   `json:"profile_version,omitempty"`
	LegacyType      string   `json:"agtp_type,omitempty"`
	LegacyVersion   string   `json:"agtp_version,omitempty"`
	Confirmation    cnf      `json:"cnf,omitempty"`
	EndpointKeyIDs  []string `json:"authorized_endpoint_keys,omitempty"`
	GrantHash       string   `json:"grant_hash,omitempty"`
	LeafKeySHA256   string   `json:"leaf_public_key_sha256,omitempty"`
	TLSExporter     string   `json:"tls_exporter_sha256,omitempty"`
	RequestContext  string   `json:"request_context_sha256,omitempty"`
	AttestationBind string   `json:"attestation_binder_sha256,omitempty"`
	Nonce           string   `json:"nonce,omitempty"`

	Service              string   `json:"service,omitempty"`
	Tenant               string   `json:"tenant,omitempty"`
	Deployment           string   `json:"deployment,omitempty"`
	Environment          string   `json:"environment,omitempty"`
	Workload             string   `json:"workload,omitempty"`
	Agent                string   `json:"agent,omitempty"`
	AgentPublicKey       string   `json:"agent_public_key,omitempty"`
	ComputationID        string   `json:"computation_id,omitempty"`
	TaskID               string   `json:"task_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty"`
	DelegationID         string   `json:"delegation_id,omitempty"`
	IntentRef            string   `json:"intent_ref,omitempty"`
	CapabilityRef        string   `json:"capability_ref,omitempty"`
	OntologyID           string   `json:"ontology_id,omitempty"`
	Scope                string   `json:"scope,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	Resources            []string `json:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty"`
}

type cnf struct {
	KeyID string `json:"kid,omitempty"`
}

// ValidateJWTVerifyOptions checks local JWT verification policy before a
// connection attempt uses it.
func ValidateJWTVerifyOptions(opts JWTVerifyOptions) error {
	if _, err := jwtParserOptions(opts); err != nil {
		return err
	}
	_, err := verificationKeyFunc(opts)
	return err
}

// IdentityGrantHash returns the domain-separated hash of the exact signed grant
// bytes. The session-binding statement carries this value.
func IdentityGrantHash(tokenString string) string {
	sum := sha256.Sum256([]byte(identityGrantJWTHashSeed + tokenString))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyIdentityGrantJWT verifies a manager-issued identity grant JWT.
func VerifyIdentityGrantJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedGrant, error) {
	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if err := claims.requireProfile(TokenTypeIdentityGrant); err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingJWTID
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingSubject
	}
	if strings.TrimSpace(claims.Confirmation.KeyID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingConfirmationKey
	}

	values := identitypolicy.Values{
		Service:              claims.Service,
		Tenant:               claims.Tenant,
		Deployment:           claims.Deployment,
		Environment:          claims.Environment,
		Workload:             claims.Workload,
		Agent:                claims.Agent,
		AgentPublicKey:       claims.AgentPublicKey,
		ComputationID:        claims.ComputationID,
		TaskID:               claims.TaskID,
		ThreadID:             claims.ThreadID,
		DelegationID:         claims.DelegationID,
		IntentRef:            claims.IntentRef,
		CapabilityRef:        claims.CapabilityRef,
		OntologyID:           claims.OntologyID,
		Scopes:               withSpaceSeparatedValues(claims.Scopes, claims.Scope),
		Resources:            withSpaceSeparatedValues(claims.Resources, claims.Resource),
		AuthorizationDetails: claims.AuthorizationDetails,
	}
	if values.Agent == "" {
		values.Agent = claims.Subject
	}

	return identitypolicy.VerifiedGrant{
		Issuer:                 claims.Issuer,
		IssuerKey:              signerKey,
		Audience:               opts.ExpectedAudience,
		GrantHash:              IdentityGrantHash(tokenString),
		Values:                 values,
		ConfirmationKey:        claims.Confirmation.KeyID,
		AuthorizedEndpointKeys: claims.EndpointKeyIDs,
		IssuedAt:               claimTime(claims.IssuedAt),
		ExpiresAt:              claimTime(claims.ExpiresAt),
	}, nil
}

// VerifySessionBindingJWT verifies an agent-issued session-binding JWT.
func VerifySessionBindingJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedSessionBindingStatement, error) {
	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if err := claims.requireProfile(TokenTypeSessionBinding); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedSessionBindingStatement{}, ErrMissingJWTID
	}
	if err := claims.requireSessionBindingFields(); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}

	return identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: claims.GrantHash,
		Audience:  opts.ExpectedAudience,
		SignerKey: signerKey,
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:     claims.LeafKeySHA256,
			TLSExporterSHA256:       claims.TLSExporter,
			RequestContextSHA256:    claims.RequestContext,
			AttestationBinderSHA256: claims.AttestationBind,
			Nonce:                   claims.Nonce,
			IssuedAt:                claimTime(claims.IssuedAt),
			ExpiresAt:               claimTime(claims.ExpiresAt),
		},
	}, nil
}

// VerifySessionIdentityJWT verifies the Direct-Agent binding profile used by
// AttestedClientConfig.
func VerifySessionIdentityJWT(grantToken, bindingToken string, opts SessionIdentityJWTOptions) (SessionIdentityJWTResult, error) {
	if !opts.Policy.Enabled() {
		return SessionIdentityJWTResult{}, ErrMissingIdentityPolicy
	}
	if opts.ReplayCache == nil {
		return SessionIdentityJWTResult{}, ErrMissingReplayCache
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	grantOpts := opts.Grant
	grantOpts.Now = now
	grant, err := VerifyIdentityGrantJWT(grantToken, grantOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}

	bindingOpts := opts.SessionBinding
	bindingOpts.Now = now
	statement, err := VerifySessionBindingJWT(bindingToken, bindingOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if err := opts.Policy.ValidateAssertion(assertion, opts.ExpectedBinding, now); err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if err := identitypolicy.MarkSessionBindingUsed(opts.ReplayCache, statement); err != nil {
		return SessionIdentityJWTResult{}, err
	}

	return SessionIdentityJWTResult{
		Grant:     grant,
		Statement: statement,
		Assertion: assertion,
	}, nil
}

func parseBindingJWT(tokenString string, opts JWTVerifyOptions) (*bindingJWTClaims, string, error) {
	if err := rejectDuplicateJWTMembers(tokenString); err != nil {
		return nil, "", err
	}

	parserOpts, err := jwtParserOptions(opts)
	if err != nil {
		return nil, "", err
	}
	keyFunc, err := verificationKeyFunc(opts)
	if err != nil {
		return nil, "", err
	}

	var signerKey string
	claims := &bindingJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		keyID, err := tokenKeyID(token)
		if err != nil {
			return nil, err
		}
		signerKey = keyID
		return keyFunc(keyID)
	}, parserOpts...)
	if err != nil {
		return nil, "", fmt.Errorf("binding jwt: verify: %w", err)
	}
	if !token.Valid {
		return nil, "", errors.New("binding jwt: invalid token")
	}
	if listed(claims.ID, opts.RevokedJWTIDs) {
		return nil, "", ErrRevokedJWTID
	}
	return claims, signerKey, nil
}

func jwtParserOptions(opts JWTVerifyOptions) ([]jwt.ParserOption, error) {
	if opts.KeyFunc == nil && len(opts.LocalKeys) == 0 {
		return nil, ErrMissingKeyFunc
	}
	if opts.KeyFunc != nil && len(opts.LocalKeys) > 0 {
		return nil, ErrAmbiguousKeySource
	}
	if len(opts.ValidMethods) == 0 {
		return nil, ErrMissingValidMethods
	}
	for _, method := range opts.ValidMethods {
		method = strings.TrimSpace(method)
		if method == "" || strings.EqualFold(method, jwt.SigningMethodNone.Alg()) {
			return nil, ErrUnsafeSigningMethod
		}
	}
	if strings.TrimSpace(opts.ExpectedIssuer) == "" {
		return nil, ErrMissingExpectedIssuer
	}
	if strings.TrimSpace(opts.ExpectedAudience) == "" {
		return nil, ErrMissingExpectedAudience
	}

	out := []jwt.ParserOption{
		jwt.WithValidMethods(opts.ValidMethods),
		jwt.WithIssuer(opts.ExpectedIssuer),
		jwt.WithAudience(opts.ExpectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if !opts.Now.IsZero() {
		out = append(out, jwt.WithTimeFunc(func() time.Time {
			return opts.Now
		}))
	}
	return out, nil
}

func verificationKeyFunc(opts JWTVerifyOptions) (KeyFunc, error) {
	disabled := set(opts.DisabledKeyIDs)
	if opts.KeyFunc != nil {
		return func(keyID string) (interface{}, error) {
			keyID = strings.TrimSpace(keyID)
			if disabled[keyID] {
				return nil, ErrDisabledKeyID
			}
			return opts.KeyFunc(keyID)
		}, nil
	}

	keys := make(map[string]interface{}, len(opts.LocalKeys))
	for _, localKey := range opts.LocalKeys {
		keyID := strings.TrimSpace(localKey.KeyID)
		if keyID == "" {
			return nil, ErrMissingKeyID
		}
		if _, exists := keys[keyID]; exists {
			return nil, ErrDuplicateKeyID
		}
		if localKey.Key == nil {
			return nil, ErrMissingLocalKey
		}
		if localKey.Disabled {
			disabled[keyID] = true
		}
		keys[keyID] = localKey.Key
	}

	return func(keyID string) (interface{}, error) {
		keyID = strings.TrimSpace(keyID)
		if disabled[keyID] {
			return nil, ErrDisabledKeyID
		}
		key, ok := keys[keyID]
		if !ok {
			return nil, ErrUnknownKeyID
		}
		return key, nil
	}, nil
}

func tokenKeyID(token *jwt.Token) (string, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return "", ErrMissingKeyID
	}
	return strings.TrimSpace(keyID), nil
}

func (c bindingJWTClaims) requireProfile(expected string) error {
	if !profileValueMatches(c.ProfileType, expected) {
		return ErrInvalidTokenType
	}
	if !legacyProfileValueMatches(c.LegacyType, expected) {
		return ErrInvalidTokenType
	}
	if !profileVersionMatches(c.ProfileVersion) || !profileVersionMatches(c.LegacyVersion) {
		return ErrUnsupportedVersion
	}
	if strings.TrimSpace(c.ProfileType) == "" && strings.TrimSpace(c.LegacyType) == "" {
		return ErrInvalidTokenType
	}
	if strings.TrimSpace(c.ProfileVersion) == "" && strings.TrimSpace(c.LegacyVersion) == "" {
		return ErrUnsupportedVersion
	}
	return nil
}

func (c bindingJWTClaims) requireSessionBindingFields() error {
	if strings.TrimSpace(c.GrantHash) == "" {
		return ErrMissingGrantHash
	}
	required := []string{
		c.LeafKeySHA256,
		c.TLSExporter,
		c.RequestContext,
		c.Nonce,
	}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return ErrMissingBindingField
		}
	}
	return nil
}

func profileValueMatches(value, expected string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == expected
}

func legacyProfileValueMatches(value, expected string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if value == expected {
		return true
	}
	switch expected {
	case TokenTypeIdentityGrant:
		return value == LegacyTokenTypeIdentityGrant
	case TokenTypeSessionBinding:
		return value == LegacyTokenTypeSessionBinding
	default:
		return false
	}
}

func profileVersionMatches(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == ProfileVersion
}

func claimTime(value *jwt.NumericDate) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.Time
}

func withSpaceSeparatedValues(values []string, spaceSeparated string) []string {
	if strings.TrimSpace(spaceSeparated) == "" {
		return values
	}
	out := append([]string{}, values...)
	out = append(out, strings.Fields(spaceSeparated)...)
	return out
}

func listed(value string, values []string) bool {
	return set(values)[strings.TrimSpace(value)]
}

func set(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func rejectDuplicateJWTMembers(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	for _, part := range parts[:2] {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil
		}
		if err := rejectDuplicateJSONMembers(raw); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONMembers(raw []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("binding jwt: trailing json data")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONObjectMembers(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			member, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := member.(string)
			if !ok {
				return errors.New("binding jwt: non-string json object key")
			}
			if _, ok := seen[name]; ok {
				return ErrDuplicateJWTMember
			}
			seen[name] = struct{}{}
			if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token()
	return err
}
