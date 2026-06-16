// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	ErrUnsupportedCacheDirective = errors.New("agtp: unsupported response cache directive")
	ErrMissingCacheFreshness     = errors.New("agtp: missing response cache freshness")
	ErrUnsafeResponseCache       = errors.New("agtp: unsafe response cache policy")
	ErrMissingCachePartition     = errors.New("agtp: missing response cache partition")
)

const (
	ResponseCacheNoStore ResponseCacheDirective = "no-store"
	ResponseCachePublic  ResponseCacheDirective = "public"
	ResponseCachePrivate ResponseCacheDirective = "private"

	CacheVaryAgentID         = "Agent-ID"
	CacheVaryPrincipalID     = "Principal-ID"
	CacheVaryAuthorityScope  = "Authority-Scope"
	CacheVaryTenantID        = "Tenant-ID"
	CacheVaryDeploymentID    = "Deployment-ID"
	CacheVaryPolicyGrantHash = "Policy-Grant-Hash"
	CacheVarySessionID       = "Session-ID"
	CacheVaryTaskID          = "Task-ID"
)

// ResponseCacheDirective is the AGTP response-cache directive understood by
// the security profile. The names intentionally mirror RFC 9111 terminology.
type ResponseCacheDirective string

// ResponseCachePolicy describes endpoint response caching, not authorization
// or replay state.
type ResponseCachePolicy struct {
	Directive ResponseCacheDirective
	MaxAge    time.Duration
	Vary      []string
}

// ResponseCacheContext describes the security-sensitive inputs that can make a
// response unsafe to reuse across callers or sessions.
type ResponseCacheContext struct {
	SecurityState            bool
	CallerVaryFields         []string
	SessionBound             bool
	AllowSessionPrivateCache bool
}

// EffectiveResponseCacheDirective returns the directive after applying the
// profile default. Empty policy means no-store.
func EffectiveResponseCacheDirective(policy ResponseCachePolicy) ResponseCacheDirective {
	directive := ResponseCacheDirective(strings.ToLower(strings.TrimSpace(string(policy.Directive))))
	if directive == "" {
		return ResponseCacheNoStore
	}
	return directive
}

// ValidateResponseCachePolicy checks the RFC 9111-style AGTP response-cache
// profile from docs/SSOT.md. It never validates JWTs, grants, session bindings,
// or replay state; those remain separate acceptance checks.
func ValidateResponseCachePolicy(policy ResponseCachePolicy, ctx ResponseCacheContext) error {
	directive := EffectiveResponseCacheDirective(policy)
	switch directive {
	case ResponseCacheNoStore:
		return nil
	case ResponseCachePublic, ResponseCachePrivate:
	default:
		return ErrUnsupportedCacheDirective
	}

	if policy.MaxAge <= 0 {
		return ErrMissingCacheFreshness
	}
	if ctx.SecurityState {
		return ErrUnsafeResponseCache
	}

	vary := normalizeCacheVary(policy.Vary)
	callerVaryFields := normalizeCacheVary(ctx.CallerVaryFields)

	if directive == ResponseCachePublic {
		if len(callerVaryFields) > 0 || containsProtectedCacheVary(vary) {
			return ErrUnsafeResponseCache
		}
		return nil
	}

	if ctx.SessionBound {
		if !ctx.AllowSessionPrivateCache || !slices.Contains(vary, CacheVarySessionID) {
			return ErrMissingCachePartition
		}
	}
	if !containsAllCacheVary(vary, callerVaryFields) {
		return ErrMissingCachePartition
	}
	return nil
}

func normalizeCacheVary(fields []string) []string {
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = canonicalCacheVaryField(field)
		if field == "" {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		out = append(out, field)
	}
	slices.Sort(out)
	return out
}

func canonicalCacheVaryField(field string) string {
	field = strings.TrimSpace(field)
	for _, known := range []string{
		CacheVaryAgentID,
		CacheVaryPrincipalID,
		CacheVaryAuthorityScope,
		CacheVaryTenantID,
		CacheVaryDeploymentID,
		CacheVaryPolicyGrantHash,
		CacheVarySessionID,
		CacheVaryTaskID,
	} {
		if strings.EqualFold(field, known) {
			return known
		}
	}
	return field
}

func containsAllCacheVary(vary, required []string) bool {
	for _, field := range required {
		if !slices.Contains(vary, field) {
			return false
		}
	}
	return true
}

func containsProtectedCacheVary(vary []string) bool {
	for _, field := range []string{
		CacheVaryAgentID,
		CacheVaryPrincipalID,
		CacheVaryAuthorityScope,
		CacheVaryTenantID,
		CacheVaryDeploymentID,
		CacheVaryPolicyGrantHash,
		CacheVarySessionID,
		CacheVaryTaskID,
	} {
		if slices.Contains(vary, field) {
			return true
		}
	}
	return false
}
