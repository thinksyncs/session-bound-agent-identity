// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package identitypolicy validates deployment and agent identity policy inputs
// that sit above the basic aTLS channel-binding checks.
package identitypolicy

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrMissingExpected  = errors.New("identitypolicy: missing expected value")
	ErrMissingObserved  = errors.New("identitypolicy: missing observed value")
	ErrMismatch         = errors.New("identitypolicy: value mismatch")
	ErrInvalidMode      = errors.New("identitypolicy: invalid mode")
	ErrUnsafeValue      = errors.New("identitypolicy: unsafe value")
	ErrValueTooLong     = errors.New("identitypolicy: value too long")
	ErrTooManyValues    = errors.New("identitypolicy: too many values")
	ErrMissingBinding   = errors.New("identitypolicy: missing session binding")
	ErrExpiredAssertion = errors.New("identitypolicy: expired assertion")
	ErrFutureAssertion  = errors.New("identitypolicy: assertion issued in the future")
)

const (
	LayerL3 = "L3"
	LayerL4 = "L4"
	LayerL5 = "L5"
	LayerL6 = "L6"
)

// Mode selects how identity policy should be enforced.
type Mode string

const (
	ModeDefault  Mode = ""
	ModeDisabled Mode = "disabled"
	ModeRequired Mode = "required"
)

const (
	FieldAll                   = "*"
	FieldService               = "service"
	FieldTenant                = "tenant"
	FieldDeployment            = "deployment"
	FieldEnvironment           = "environment"
	FieldWorkload              = "workload"
	FieldAgent                 = "agent"
	FieldAgentPublicKey        = "agent_public_key"
	FieldComputationID         = "computation_id"
	FieldTaskID                = "task_id"
	FieldThreadID              = "thread_id"
	FieldDelegationID          = "delegation_id"
	FieldScopes                = "scopes"
	FieldResources             = "resources"
	FieldAuthorizationDetails  = "authorization_details"
	FieldLeafPublicKeyHash     = "leaf_public_key_sha256"
	FieldRequestContextHash    = "request_context_sha256"
	FieldAttestationBinderHash = "attestation_binder_sha256"
	FieldNonce                 = "nonce"
	FieldExpiresAt             = "expires_at"
	FieldIssuedAt              = "issued_at"
)

const (
	MaxValueLength = 1024
	MaxSetValues   = 128
)

// Requirements selects which identity-policy layers must be enforced.
type Requirements struct {
	L3 bool `json:"l3" yaml:"l3"`
	L4 bool `json:"l4" yaml:"l4"`
	L5 bool `json:"l5" yaml:"l5"`
	L6 bool `json:"l6" yaml:"l6"`
}

// Enabled reports whether at least one identity-policy layer is required.
func (r Requirements) Enabled() bool {
	return r.L3 || r.L4 || r.L5 || r.L6
}

// Values contains local expected values or observed peer values.
type Values struct {
	Service              string   `json:"service,omitempty" yaml:"service,omitempty"`
	Tenant               string   `json:"tenant,omitempty" yaml:"tenant,omitempty"`
	Deployment           string   `json:"deployment,omitempty" yaml:"deployment,omitempty"`
	Environment          string   `json:"environment,omitempty" yaml:"environment,omitempty"`
	Workload             string   `json:"workload,omitempty" yaml:"workload,omitempty"`
	Agent                string   `json:"agent,omitempty" yaml:"agent,omitempty"`
	AgentPublicKey       string   `json:"agent_public_key,omitempty" yaml:"agent_public_key,omitempty"`
	ComputationID        string   `json:"computation_id,omitempty" yaml:"computation_id,omitempty"`
	TaskID               string   `json:"task_id,omitempty" yaml:"task_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty" yaml:"thread_id,omitempty"`
	DelegationID         string   `json:"delegation_id,omitempty" yaml:"delegation_id,omitempty"`
	Scopes               []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Resources            []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty" yaml:"authorization_details,omitempty"`
}

// Binding ties an observed identity assertion to the accepted aTLS session.
type Binding struct {
	LeafPublicKeySHA256     string    `json:"leaf_public_key_sha256,omitempty" yaml:"leaf_public_key_sha256,omitempty"`
	RequestContextSHA256    string    `json:"request_context_sha256,omitempty" yaml:"request_context_sha256,omitempty"`
	AttestationBinderSHA256 string    `json:"attestation_binder_sha256,omitempty" yaml:"attestation_binder_sha256,omitempty"`
	Nonce                   string    `json:"nonce,omitempty" yaml:"nonce,omitempty"`
	IssuedAt                time.Time `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	ExpiresAt               time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// Assertion contains observed identity values plus their session binding.
type Assertion struct {
	Issuer  string  `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Values  Values  `json:"values" yaml:"values"`
	Binding Binding `json:"binding" yaml:"binding"`
}

// Policy separates local expected values from observed peer values.
type Policy struct {
	Mode     Mode         `json:"mode,omitempty" yaml:"mode,omitempty"`
	Require  Requirements `json:"require" yaml:"require"`
	Expected Values       `json:"expected" yaml:"expected"`
}

// Enabled reports whether this policy should be enforced.
func (p Policy) Enabled() bool {
	switch p.Mode {
	case ModeDisabled:
		return false
	case ModeRequired:
		return true
	case ModeDefault:
	default:
		return false
	}
	return p.Require.Enabled()
}

// ValidateMode checks whether this policy uses a supported production mode.
func (p Policy) ValidateMode() error {
	switch p.Mode {
	case ModeDefault, ModeDisabled, ModeRequired:
		return nil
	default:
		return ErrInvalidMode
	}
}

// Validate checks observed values against this policy.
func (p Policy) Validate(observed Values) error {
	return Validate(p, observed)
}

// ValidateAssertion checks a session-bound observed assertion against this policy.
func (p Policy) ValidateAssertion(assertion Assertion, expectedBinding Binding, now time.Time) error {
	return ValidateAssertion(p, assertion, expectedBinding, now)
}

// ValidationError reports the exact layer and field that failed validation.
type ValidationError struct {
	Layer string
	Field string
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Layer, e.Field, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// ValidationErrors reports all policy validation failures found in one pass.
type ValidationErrors []*ValidationError

func (e ValidationErrors) Error() string {
	validationErrs := e.nonNil()
	switch len(validationErrs) {
	case 0:
		return "identitypolicy: no validation errors"
	case 1:
		return validationErrs[0].Error()
	default:
		return fmt.Sprintf("%d identity policy validation errors", len(validationErrs))
	}
}

func (e ValidationErrors) Unwrap() []error {
	validationErrs := e.nonNil()
	errs := make([]error, len(validationErrs))
	for i, err := range validationErrs {
		errs[i] = err
	}
	return errs
}

// Has reports whether this aggregate contains a matching validation failure.
// Empty layer or field arguments act as wildcards. A nil target matches any
// error type for the selected layer and field.
func (e ValidationErrors) Has(layer, field string, target error) bool {
	for _, err := range e {
		if err == nil {
			continue
		}
		if layer != "" && err.Layer != layer {
			continue
		}
		if field != "" && err.Field != field {
			continue
		}
		if target != nil && !errors.Is(err, target) {
			continue
		}
		return true
	}
	return false
}

func (e ValidationErrors) ByLayer(layer string) ValidationErrors {
	var out ValidationErrors
	for _, err := range e {
		if err == nil {
			continue
		}
		if err.Layer == layer {
			out = append(out, err)
		}
	}
	return out
}

func (e ValidationErrors) ByField(field string) ValidationErrors {
	var out ValidationErrors
	for _, err := range e {
		if err == nil {
			continue
		}
		if err.Field == field {
			out = append(out, err)
		}
	}
	return out
}

func (e ValidationErrors) nonNil() ValidationErrors {
	out := make(ValidationErrors, 0, len(e))
	for _, err := range e {
		if err != nil {
			out = append(out, err)
		}
	}
	return out
}

// Validate checks observed values against local expected policy values.
func Validate(policy Policy, observed Values) error {
	var errs ValidationErrors
	if err := policy.ValidateMode(); err != nil {
		errs = append(errs, validationError("policy", "mode", err))
	}
	if policy.Mode == ModeRequired && !policy.Require.Enabled() {
		errs = append(errs, validationError("policy", FieldAll, ErrMissingExpected))
	}

	if policy.Require.L3 {
		if err := validateExactLayer(LayerL3, policy.Expected, observed, []field{
			{FieldService, func(v Values) string { return v.Service }},
			{FieldTenant, func(v Values) string { return v.Tenant }},
			{FieldDeployment, func(v Values) string { return v.Deployment }},
			{FieldEnvironment, func(v Values) string { return v.Environment }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L4 {
		if err := validateExactLayer(LayerL4, policy.Expected, observed, []field{
			{FieldWorkload, func(v Values) string { return v.Workload }},
			{FieldAgent, func(v Values) string { return v.Agent }},
			{FieldAgentPublicKey, func(v Values) string { return v.AgentPublicKey }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L5 {
		if err := validateExactLayer(LayerL5, policy.Expected, observed, []field{
			{FieldComputationID, func(v Values) string { return v.ComputationID }},
			{FieldTaskID, func(v Values) string { return v.TaskID }},
			{FieldThreadID, func(v Values) string { return v.ThreadID }},
			{FieldDelegationID, func(v Values) string { return v.DelegationID }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L6 {
		if err := validateL6(policy.Expected, observed); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateAssertion checks the observed values and their session binding.
func ValidateAssertion(policy Policy, assertion Assertion, expectedBinding Binding, now time.Time) error {
	var errs ValidationErrors
	if err := validateBinding(assertion.Binding, expectedBinding, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := Validate(policy, assertion.Values); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateBinding(observed, expected Binding, now time.Time) error {
	var errs ValidationErrors
	hasExpected := false
	for _, f := range []struct {
		name string
		want string
		got  string
	}{
		{FieldLeafPublicKeyHash, expected.LeafPublicKeySHA256, observed.LeafPublicKeySHA256},
		{FieldRequestContextHash, expected.RequestContextSHA256, observed.RequestContextSHA256},
		{FieldAttestationBinderHash, expected.AttestationBinderSHA256, observed.AttestationBinderSHA256},
		{FieldNonce, expected.Nonce, observed.Nonce},
	} {
		if isEmpty(f.want) {
			continue
		}
		hasExpected = true
		if isUnsafe(f.want) {
			errs = append(errs, validationError("binding", f.name, ErrUnsafeValue))
			continue
		}
		if isEmpty(f.got) {
			errs = append(errs, validationError("binding", f.name, ErrMissingBinding))
			continue
		}
		if isUnsafe(f.got) {
			errs = append(errs, validationError("binding", f.name, ErrUnsafeValue))
			continue
		}
		if f.got != f.want {
			errs = append(errs, validationError("binding", f.name, ErrMismatch))
		}
	}
	if !hasExpected {
		errs = append(errs, validationError("binding", FieldAll, ErrMissingExpected))
	}
	if observed.ExpiresAt.IsZero() {
		errs = append(errs, validationError("binding", FieldExpiresAt, ErrMissingBinding))
	} else if !now.IsZero() && now.After(observed.ExpiresAt) {
		errs = append(errs, validationError("binding", FieldExpiresAt, ErrExpiredAssertion))
	}
	if !observed.IssuedAt.IsZero() && !now.IsZero() && observed.IssuedAt.After(now) {
		errs = append(errs, validationError("binding", FieldIssuedAt, ErrFutureAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

type field struct {
	name string
	get  func(Values) string
}

func validateExactLayer(layer string, expected, observed Values, fields []field) error {
	var errs ValidationErrors
	hasExpected := false
	for _, f := range fields {
		want := f.get(expected)
		if isEmpty(want) {
			continue
		}
		hasExpected = true
		if err := validateValue(want); err != nil {
			errs = append(errs, validationError(layer, f.name, err))
			continue
		}
		got := f.get(observed)
		if isEmpty(got) {
			errs = append(errs, validationError(layer, f.name, ErrMissingObserved))
			continue
		}
		if err := validateValue(got); err != nil {
			errs = append(errs, validationError(layer, f.name, err))
			continue
		}
		if got != want {
			errs = append(errs, validationError(layer, f.name, ErrMismatch))
		}
	}
	if !hasExpected {
		return validationError(layer, FieldAll, ErrMissingExpected)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateL6(expected, observed Values) error {
	var errs ValidationErrors
	hasExpected := false
	if len(expected.Scopes) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL6, FieldScopes, expected.Scopes, observed.Scopes); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.Resources) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL6, FieldResources, expected.Resources, observed.Resources); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.AuthorizationDetails) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL6, FieldAuthorizationDetails, expected.AuthorizationDetails, observed.AuthorizationDetails); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if !hasExpected {
		return validationError(LayerL6, FieldAll, ErrMissingExpected)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func requireContainsAll(layer, fieldName string, expected, observed []string) error {
	if len(expected) > MaxSetValues || len(observed) > MaxSetValues {
		return validationError(layer, fieldName, ErrTooManyValues)
	}

	for _, value := range expected {
		if isEmpty(value) {
			return validationError(layer, fieldName, ErrMissingExpected)
		}
		if err := validateValue(value); err != nil {
			return validationError(layer, fieldName, err)
		}
	}

	seen := make(map[string]struct{}, len(observed))
	for _, value := range observed {
		if isEmpty(value) {
			continue
		}
		if err := validateValue(value); err != nil {
			return validationError(layer, fieldName, err)
		}
		seen[value] = struct{}{}
	}
	if len(seen) == 0 {
		return validationError(layer, fieldName, ErrMissingObserved)
	}
	for _, value := range expected {
		if _, ok := seen[value]; !ok {
			return validationError(layer, fieldName, ErrMismatch)
		}
	}
	return nil
}

func appendValidationErrors(errs ValidationErrors, err error) ValidationErrors {
	if err == nil {
		return errs
	}
	var validationErrors ValidationErrors
	if errors.As(err, &validationErrors) {
		return append(errs, validationErrors...)
	}
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return append(errs, validationErr)
	}
	return append(errs, validationError(FieldAll, FieldAll, err))
}

func validationError(layer, field string, err error) *ValidationError {
	return &ValidationError{
		Layer: layer,
		Field: field,
		Err:   err,
	}
}

func isEmpty(value string) bool {
	return strings.TrimSpace(value) == ""
}

func validateValue(value string) error {
	if len(value) > MaxValueLength {
		return ErrValueTooLong
	}
	if isUnsafe(value) {
		return ErrUnsafeValue
	}
	return nil
}

func isUnsafe(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			return true
		}
	}
	return false
}
