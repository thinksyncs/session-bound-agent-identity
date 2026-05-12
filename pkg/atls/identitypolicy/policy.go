// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package identitypolicy validates deployment and agent identity policy inputs
// that sit above the basic aTLS channel-binding checks.
package identitypolicy

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrMissingExpected = errors.New("identitypolicy: missing expected value")
	ErrMissingObserved = errors.New("identitypolicy: missing observed value")
	ErrMismatch        = errors.New("identitypolicy: value mismatch")
	ErrUnsafeValue     = errors.New("identitypolicy: unsafe value")
)

const (
	LayerL2B = "L2b"
	LayerL3  = "L3"
	LayerL4  = "L4"
	LayerL5  = "L5"
)

const (
	FieldAll                  = "*"
	FieldService              = "service"
	FieldTenant               = "tenant"
	FieldDeployment           = "deployment"
	FieldEnvironment          = "environment"
	FieldWorkload             = "workload"
	FieldAgent                = "agent"
	FieldAgentPublicKey       = "agent_public_key"
	FieldComputationID        = "computation_id"
	FieldTaskID               = "task_id"
	FieldThreadID             = "thread_id"
	FieldDelegationID         = "delegation_id"
	FieldScopes               = "scopes"
	FieldResources            = "resources"
	FieldAuthorizationDetails = "authorization_details"
)

// Requirements selects which identity-policy layers must be enforced.
type Requirements struct {
	L2B bool `json:"l2b" yaml:"l2b"`
	L3  bool `json:"l3" yaml:"l3"`
	L4  bool `json:"l4" yaml:"l4"`
	L5  bool `json:"l5" yaml:"l5"`
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

// Policy separates local expected values from observed peer values.
type Policy struct {
	Require  Requirements `json:"require" yaml:"require"`
	Expected Values       `json:"expected" yaml:"expected"`
}

// Validate checks observed values against this policy.
func (p Policy) Validate(observed Values) error {
	return Validate(p, observed)
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

	if policy.Require.L2B {
		if err := validateExactLayer(LayerL2B, policy.Expected, observed, []field{
			{FieldService, func(v Values) string { return v.Service }},
			{FieldTenant, func(v Values) string { return v.Tenant }},
			{FieldDeployment, func(v Values) string { return v.Deployment }},
			{FieldEnvironment, func(v Values) string { return v.Environment }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L3 {
		if err := validateExactLayer(LayerL3, policy.Expected, observed, []field{
			{FieldWorkload, func(v Values) string { return v.Workload }},
			{FieldAgent, func(v Values) string { return v.Agent }},
			{FieldAgentPublicKey, func(v Values) string { return v.AgentPublicKey }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L4 {
		if err := validateExactLayer(LayerL4, policy.Expected, observed, []field{
			{FieldComputationID, func(v Values) string { return v.ComputationID }},
			{FieldTaskID, func(v Values) string { return v.TaskID }},
			{FieldThreadID, func(v Values) string { return v.ThreadID }},
			{FieldDelegationID, func(v Values) string { return v.DelegationID }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L5 {
		if err := validateL5(policy.Expected, observed); err != nil {
			errs = appendValidationErrors(errs, err)
		}
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
		if isUnsafe(want) {
			errs = append(errs, validationError(layer, f.name, ErrUnsafeValue))
			continue
		}
		got := f.get(observed)
		if isEmpty(got) {
			errs = append(errs, validationError(layer, f.name, ErrMissingObserved))
			continue
		}
		if isUnsafe(got) {
			errs = append(errs, validationError(layer, f.name, ErrUnsafeValue))
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

func validateL5(expected, observed Values) error {
	var errs ValidationErrors
	hasExpected := false
	if len(expected.Scopes) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, FieldScopes, expected.Scopes, observed.Scopes); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.Resources) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, FieldResources, expected.Resources, observed.Resources); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.AuthorizationDetails) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, FieldAuthorizationDetails, expected.AuthorizationDetails, observed.AuthorizationDetails); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if !hasExpected {
		return validationError(LayerL5, FieldAll, ErrMissingExpected)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func requireContainsAll(layer, fieldName string, expected, observed []string) error {
	for _, value := range expected {
		if isEmpty(value) {
			return validationError(layer, fieldName, ErrMissingExpected)
		}
		if isUnsafe(value) {
			return validationError(layer, fieldName, ErrUnsafeValue)
		}
	}

	seen := make(map[string]struct{}, len(observed))
	for _, value := range observed {
		if isEmpty(value) {
			continue
		}
		if isUnsafe(value) {
			return validationError(layer, fieldName, ErrUnsafeValue)
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

func isUnsafe(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
