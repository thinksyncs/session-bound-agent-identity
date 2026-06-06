// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPolicyEnabled(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   bool
	}{
		{
			name: "disabled",
			want: false,
		},
		{
			name: "enabled",
			policy: Policy{
				Require: Requirements{L3: true},
			},
			want: true,
		},
		{
			name: "required mode",
			policy: Policy{
				Mode: ModeRequired,
			},
			want: true,
		},
		{
			name: "disabled mode overrides requirements",
			policy: Policy{
				Mode:    ModeDisabled,
				Require: Requirements{L3: true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.Enabled(); got != tt.want {
				t.Fatalf("Policy.Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRejectsRequiredModeWithoutRequirements(t *testing.T) {
	policy := Policy{Mode: ModeRequired}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsInvalidMode(t *testing.T) {
	policy := Policy{Mode: Mode("permissive")}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidMode)
	}
}

func TestValidateAcceptsMatchingRequiredLayers(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L3: true,
			L4: true,
			L5: true,
			L6: true,
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

func TestValidateAcceptsSingleExpectedValuePerRequiredLayer(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L3: true,
			L4: true,
			L5: true,
			L6: true,
		},
		Expected: Values{
			Service: "payments",
			Agent:   "agent-a",
			TaskID:  "task-1",
			Scopes:  []string{"read:orders"},
		},
	}

	observed := Values{
		Service:     "payments",
		Tenant:      "different-tenant",
		Deployment:  "different-deployment",
		Environment: "different-environment",
		Workload:    "different-workload",
		Agent:       "agent-a",
		TaskID:      "task-1",
		ThreadID:    "different-thread",
		Scopes:      []string{"read:orders", "write:audit"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsObservedSetSupersetWithDuplicatesAndBlanks(t *testing.T) {
	policy := Policy{
		Require: Requirements{L6: true},
		Expected: Values{
			Scopes:               []string{"read:orders", "read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	observed := Values{
		Scopes:               []string{" ", "read:orders", "read:orders", "write:audit"},
		Resources:            []string{"orders", "audit-log"},
		AuthorizationDetails: []string{"settle", "notify"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsPrintablePolicyValues(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L3: true,
			L6: true,
		},
		Expected: Values{
			Service:   "https://service.example.com/a?env=prod&tenant=a",
			Resources: []string{"urn:cocos:resource:orders#read"},
		},
	}

	observed := Values{
		Service:   "https://service.example.com/a?env=prod&tenant=a",
		Resources: []string{"urn:cocos:resource:orders#read", "urn:cocos:resource:audit#write"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsMaxLengthValue(t *testing.T) {
	value := strings.Repeat("a", MaxValueLength)
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: value},
	}

	if err := Validate(policy, Values{Agent: value}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingExpectedValue(t *testing.T) {
	policy := Policy{
		Require: Requirements{L3: true},
	}

	err := Validate(policy, Values{Service: "payments"})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsMissingObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
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
	if validationErr.Layer != LayerL4 || validationErr.Field != "agent" {
		t.Fatalf("Validate() error layer/field = %s/%s", validationErr.Layer, validationErr.Field)
	}
}

func TestValidateRejectsMismatchedObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{ComputationID: "cmp-1"},
	}

	err := Validate(policy, Values{ComputationID: "cmp-2"})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateRejectsMissingScope(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{"read:orders", "write:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders"}})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateReportsAllL6Failures(t *testing.T) {
	policy := Policy{
		Require: Requirements{L6: true},
		Expected: Values{
			Scopes:               []string{"read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	err := Validate(policy, Values{
		Scopes:    []string{" "},
		Resources: []string{"audit-log"},
	})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}

	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Validate() error = %T, want ValidationErrors", err)
	}
	if len(validationErrs) != 3 {
		t.Fatalf("Validate() error count = %d, want 3", len(validationErrs))
	}
	if !validationErrs.Has(LayerL6, FieldScopes, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L6 scopes missing observed value")
	}
	if !validationErrs.Has(LayerL6, FieldResources, ErrMismatch) {
		t.Fatalf("Validate() errors do not include L6 resources mismatch")
	}
	if !validationErrs.Has(LayerL6, FieldAuthorizationDetails, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L6 authorization details missing observed value")
	}
}

func TestValidateReportsAllLayerFailures(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L3: true,
			L4: true,
			L6: true,
		},
		Expected: Values{
			Service: "payments",
			Tenant:  "tenant-a",
			Agent:   "agent-a",
			Scopes:  []string{"read:orders"},
		},
	}

	err := policy.Validate(Values{
		Service: "billing",
		Scopes:  []string{"write:orders"},
	})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}

	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Validate() error = %T, want ValidationErrors", err)
	}
	if len(validationErrs) != 4 {
		t.Fatalf("Validate() error count = %d, want 4", len(validationErrs))
	}
	if !validationErrs.Has(LayerL3, FieldService, ErrMismatch) {
		t.Fatalf("Validate() errors do not include L3 service mismatch")
	}
	if !validationErrs.Has(LayerL4, FieldAgent, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L4 agent missing observed value")
	}
	if !validationErrs.Has(LayerL6, FieldScopes, nil) {
		t.Fatalf("Validate() errors do not include L6 scopes failure")
	}
}

func TestValidateRejectsBlankExpectedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{"read:orders", " "}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders"}})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsBlankOnlyExpectedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{" "}},
	}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
	if errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, did not want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsBlankObservedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{"read:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{" "}})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsBlankExpectedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: " "},
	}

	err := Validate(policy, Values{Agent: "agent-a"})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsBlankObservedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{Agent: " "})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsUnsafeExpectedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments\r\nx-forwarded-host: attacker"},
	}

	err := Validate(policy, Values{Service: "payments"})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestValidateRejectsHTMLDelimiters(t *testing.T) {
	value := `<script>alert("xss")</script>`
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: value},
	}

	err := Validate(policy, Values{Service: value})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestValidateRejectsUnsafeObservedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{Agent: "agent-a\nagent-b"})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestValidateRejectsTooLongExpectedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: strings.Repeat("a", MaxValueLength+1)},
	}

	err := Validate(policy, Values{Agent: "agent-a"})
	if !errors.Is(err, ErrValueTooLong) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrValueTooLong)
	}
}

func TestValidateRejectsTooLongObservedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{Agent: strings.Repeat("a", MaxValueLength+1)})
	if !errors.Is(err, ErrValueTooLong) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrValueTooLong)
	}
}

func TestValidateRejectsTooManyExpectedSetValues(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: repeatValues("scope", MaxSetValues+1)},
	}

	err := Validate(policy, Values{Scopes: repeatValues("scope", MaxSetValues+1)})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrTooManyValues)
	}
}

func TestValidateRejectsTooManyObservedSetValues(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{"scope-0"}},
	}

	err := Validate(policy, Values{Scopes: repeatValues("scope", MaxSetValues+1)})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrTooManyValues)
	}
}

func TestValidateRejectsInvalidUTF8ObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{TaskID: "task-1"},
	}

	err := Validate(policy, Values{TaskID: string([]byte{0xff})})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestValidateRejectsUnsafeSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L6: true},
		Expected: Values{Scopes: []string{"read:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders", "admin\r\nx-role: admin"}})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestValidateErrorsDoNotEchoRawObservedValues(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments"},
	}

	err := Validate(policy, Values{Service: `<script>alert("xss")</script>`})
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsafeValue)
	}
	if strings.Contains(err.Error(), "<script>") {
		t.Fatalf("Validate() error = %q, must not echo raw observed value", err.Error())
	}
}

func TestValidationErrorsHelpersSkipNilEntries(t *testing.T) {
	errs := ValidationErrors{
		nil,
		validationError(LayerL5, FieldTaskID, ErrMismatch),
	}

	if got := errs.Error(); got != "L5 task_id: identitypolicy: value mismatch" {
		t.Fatalf("ValidationErrors.Error() = %q", got)
	}
	if got := len(errs.Unwrap()); got != 1 {
		t.Fatalf("ValidationErrors.Unwrap() length = %d, want 1", got)
	}
	if !errs.Has(LayerL5, FieldTaskID, ErrMismatch) {
		t.Fatalf("ValidationErrors.Has() = false, want true")
	}
	if got := len(errs.ByLayer(LayerL5)); got != 1 {
		t.Fatalf("ValidationErrors.ByLayer() length = %d, want 1", got)
	}
	if got := len(errs.ByField(FieldTaskID)); got != 1 {
		t.Fatalf("ValidationErrors.ByField() length = %d, want 1", got)
	}
}

func TestAppendValidationErrorsWrapsUnexpectedError(t *testing.T) {
	unexpected := errors.New("unexpected")

	errs := appendValidationErrors(nil, unexpected)
	if len(errs) != 1 {
		t.Fatalf("appendValidationErrors() length = %d, want 1", len(errs))
	}
	if !errs.Has(FieldAll, FieldAll, unexpected) {
		t.Fatalf("appendValidationErrors() did not preserve unexpected error")
	}
	if !errors.Is(errs, unexpected) {
		t.Fatalf("appendValidationErrors() aggregate does not unwrap unexpected error")
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

func TestValidateAssertionAcceptsSessionBoundIdentity(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Require:  Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: Values{Service: "payments", Agent: "agent-a", TaskID: "task-1", Scopes: []string{"orders:read"}},
	}
	expectedBinding := Binding{
		LeafPublicKeySHA256:     "leaf-hash",
		RequestContextSHA256:    "context-hash",
		AttestationBinderSHA256: "binder-hash",
	}
	assertion := Assertion{
		Values: Values{
			Service: "payments",
			Agent:   "agent-a",
			TaskID:  "task-1",
			Scopes:  []string{"orders:read", "audit:write"},
		},
		Binding: Binding{
			LeafPublicKeySHA256:     "leaf-hash",
			RequestContextSHA256:    "context-hash",
			AttestationBinderSHA256: "binder-hash",
			IssuedAt:                now.Add(-time.Minute),
			ExpiresAt:               now.Add(time.Minute),
		},
	}

	if err := ValidateAssertion(policy, assertion, expectedBinding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}
}

func TestValidateAssertionRejectsBindingMismatch(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments"},
	}
	assertion := Assertion{
		Values: Values{Service: "payments"},
		Binding: Binding{
			LeafPublicKeySHA256:  "other-leaf",
			RequestContextSHA256: "context-hash",
			ExpiresAt:            now.Add(time.Minute),
		},
	}

	err := ValidateAssertion(policy, assertion, Binding{
		LeafPublicKeySHA256:  "leaf-hash",
		RequestContextSHA256: "context-hash",
	}, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("ValidateAssertion() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateAssertionRejectsMissingBindingExpiry(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments"},
	}
	assertion := Assertion{
		Values: Values{Service: "payments"},
		Binding: Binding{
			LeafPublicKeySHA256:  "leaf-hash",
			RequestContextSHA256: "context-hash",
		},
	}

	err := ValidateAssertion(policy, assertion, Binding{
		LeafPublicKeySHA256:  "leaf-hash",
		RequestContextSHA256: "context-hash",
	}, now)
	if !errors.Is(err, ErrMissingBinding) {
		t.Fatalf("ValidateAssertion() error = %v, want %v", err, ErrMissingBinding)
	}
}

func TestValidateAssertionRejectsExpiredAssertion(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments"},
	}
	assertion := Assertion{
		Values: Values{Service: "payments"},
		Binding: Binding{
			LeafPublicKeySHA256:  "leaf-hash",
			RequestContextSHA256: "context-hash",
			ExpiresAt:            now.Add(-time.Minute),
		},
	}

	err := ValidateAssertion(policy, assertion, Binding{
		LeafPublicKeySHA256:  "leaf-hash",
		RequestContextSHA256: "context-hash",
	}, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("ValidateAssertion() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestValidateAssertionRejectsFutureIssueTime(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Service: "payments"},
	}
	assertion := Assertion{
		Values: Values{Service: "payments"},
		Binding: Binding{
			LeafPublicKeySHA256:  "leaf-hash",
			RequestContextSHA256: "context-hash",
			IssuedAt:             now.Add(time.Minute),
			ExpiresAt:            now.Add(time.Hour),
		},
	}

	err := ValidateAssertion(policy, assertion, Binding{
		LeafPublicKeySHA256:  "leaf-hash",
		RequestContextSHA256: "context-hash",
	}, now)
	if !errors.Is(err, ErrFutureAssertion) {
		t.Fatalf("ValidateAssertion() error = %v, want %v", err, ErrFutureAssertion)
	}
}

func repeatValues(prefix string, n int) []string {
	values := make([]string, n)
	for i := range values {
		values[i] = prefix + "-" + strconv.Itoa(i)
	}
	return values
}
