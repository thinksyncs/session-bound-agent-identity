// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"errors"
	"testing"
	"time"
)

func TestValidateResponseCachePolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy ResponseCachePolicy
		ctx    ResponseCacheContext
		err    error
	}{
		{
			name: "default no-store allows security state",
			ctx:  ResponseCacheContext{SecurityState: true},
		},
		{
			name: "public allows caller invariant response",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePublic,
				MaxAge:    time.Minute,
			},
		},
		{
			name: "public rejects caller dependent response",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePublic,
				MaxAge:    time.Minute,
			},
			ctx: ResponseCacheContext{
				CallerVaryFields: []string{CacheVaryAgentID},
			},
			err: ErrUnsafeResponseCache,
		},
		{
			name: "public rejects protected vary field",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePublic,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVaryAuthorityScope},
			},
			err: ErrUnsafeResponseCache,
		},
		{
			name: "private rejects missing caller partition",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVaryAgentID},
			},
			ctx: ResponseCacheContext{
				CallerVaryFields: []string{CacheVaryAgentID, CacheVaryAuthorityScope},
			},
			err: ErrMissingCachePartition,
		},
		{
			name: "private accepts caller partition",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVaryAgentID, CacheVaryAuthorityScope},
			},
			ctx: ResponseCacheContext{
				CallerVaryFields: []string{CacheVaryAuthorityScope, CacheVaryAgentID},
			},
		},
		{
			name: "private accepts case insensitive caller partition",
			policy: ResponseCachePolicy{
				Directive: "PRIVATE",
				MaxAge:    time.Minute,
				Vary:      []string{"agent-id", "authority-scope"},
			},
			ctx: ResponseCacheContext{
				CallerVaryFields: []string{CacheVaryAuthorityScope, CacheVaryAgentID},
			},
		},
		{
			name: "public rejects case insensitive protected vary field",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePublic,
				MaxAge:    time.Minute,
				Vary:      []string{"agent-id"},
			},
			err: ErrUnsafeResponseCache,
		},
		{
			name: "private rejects session bound response without session local cache",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVarySessionID},
			},
			ctx: ResponseCacheContext{
				SessionBound: true,
			},
			err: ErrMissingCachePartition,
		},
		{
			name: "private accepts session local partition",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVarySessionID},
			},
			ctx: ResponseCacheContext{
				SessionBound:             true,
				AllowSessionPrivateCache: true,
			},
		},
		{
			name: "private rejects security state",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				MaxAge:    time.Minute,
				Vary:      []string{CacheVaryAgentID},
			},
			ctx: ResponseCacheContext{
				SecurityState: true,
			},
			err: ErrUnsafeResponseCache,
		},
		{
			name: "storable response requires freshness",
			policy: ResponseCachePolicy{
				Directive: ResponseCachePrivate,
				Vary:      []string{CacheVaryAgentID},
			},
			err: ErrMissingCacheFreshness,
		},
		{
			name: "unsupported directive rejects",
			policy: ResponseCachePolicy{
				Directive: "shared",
				MaxAge:    time.Minute,
			},
			err: ErrUnsupportedCacheDirective,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResponseCachePolicy(tt.policy, tt.ctx)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ValidateResponseCachePolicy() error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestEffectiveResponseCacheDirectiveDefaultsToNoStore(t *testing.T) {
	got := EffectiveResponseCacheDirective(ResponseCachePolicy{})
	if got != ResponseCacheNoStore {
		t.Fatalf("EffectiveResponseCacheDirective() = %q, want %q", got, ResponseCacheNoStore)
	}
}

func TestValidateResponseCachePolicyRedTeamRejectsCallerDependentPublicCache(t *testing.T) {
	policy := ResponseCachePolicy{
		Directive: ResponseCachePublic,
		MaxAge:    time.Minute,
	}
	ctx := ResponseCacheContext{
		CallerVaryFields: []string{CacheVaryAgentID, CacheVaryAuthorityScope},
	}
	if err := ValidateResponseCachePolicy(policy, ctx); !errors.Is(err, ErrUnsafeResponseCache) {
		t.Fatalf("ValidateResponseCachePolicy() error = %v, want %v", err, ErrUnsafeResponseCache)
	}

	cache := newResponseCachePolicyTestCache(policy)
	adminRequest := responseCachePolicyTestRequest{
		Method:         "QUERY",
		Path:           "/tools",
		InputHash:      "sha256:tools",
		AgentID:        "agent-admin",
		AuthorityScope: "tools:admin",
	}
	readOnlyRequest := responseCachePolicyTestRequest{
		Method:         "QUERY",
		Path:           "/tools",
		InputHash:      "sha256:tools",
		AgentID:        "agent-readonly",
		AuthorityScope: "tools:read",
	}
	cache.store(adminRequest, "delete-all")
	if got, ok := cache.lookup(readOnlyRequest); !ok || got != "delete-all" {
		t.Fatalf("red-team harness did not model shared-cache collision, got %q hit=%t", got, ok)
	}
}

func TestValidateResponseCachePolicyRedTeamPartitionsPrivateCache(t *testing.T) {
	policy := ResponseCachePolicy{
		Directive: ResponseCachePrivate,
		MaxAge:    time.Minute,
		Vary:      []string{CacheVaryAgentID, CacheVaryAuthorityScope},
	}
	ctx := ResponseCacheContext{
		CallerVaryFields: []string{CacheVaryAgentID, CacheVaryAuthorityScope},
	}
	if err := ValidateResponseCachePolicy(policy, ctx); err != nil {
		t.Fatalf("ValidateResponseCachePolicy() error = %v", err)
	}

	cache := newResponseCachePolicyTestCache(policy)
	adminRequest := responseCachePolicyTestRequest{
		Method:         "QUERY",
		Path:           "/tools",
		InputHash:      "sha256:tools",
		AgentID:        "agent-admin",
		AuthorityScope: "tools:admin",
	}
	readOnlyRequest := responseCachePolicyTestRequest{
		Method:         "QUERY",
		Path:           "/tools",
		InputHash:      "sha256:tools",
		AgentID:        "agent-readonly",
		AuthorityScope: "tools:read",
	}
	cache.store(adminRequest, "delete-all")
	if got, ok := cache.lookup(readOnlyRequest); ok {
		t.Fatalf("private cache leaked across caller partition, got %q", got)
	}
}

type responseCachePolicyTestRequest struct {
	Method         string
	Path           string
	InputHash      string
	AgentID        string
	AuthorityScope string
}

type responseCachePolicyTestCache struct {
	policy ResponseCachePolicy
	values map[string]string
}

func newResponseCachePolicyTestCache(policy ResponseCachePolicy) *responseCachePolicyTestCache {
	return &responseCachePolicyTestCache{
		policy: policy,
		values: make(map[string]string),
	}
}

func (c *responseCachePolicyTestCache) store(req responseCachePolicyTestRequest, value string) {
	c.values[c.key(req)] = value
}

func (c *responseCachePolicyTestCache) lookup(req responseCachePolicyTestRequest) (string, bool) {
	value, ok := c.values[c.key(req)]
	return value, ok
}

func (c *responseCachePolicyTestCache) key(req responseCachePolicyTestRequest) string {
	key := req.Method + "\x00" + req.Path + "\x00" + req.InputHash
	for _, field := range normalizeCacheVary(c.policy.Vary) {
		switch field {
		case CacheVaryAgentID:
			key += "\x00agent=" + req.AgentID
		case CacheVaryAuthorityScope:
			key += "\x00scope=" + req.AuthorityScope
		}
	}
	return key
}
