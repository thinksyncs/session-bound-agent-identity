# HTTP Cache Profile

This profile applies RFC 9111 cache vocabulary to endpoints that are used near
identity-binding decisions. It is separate from `docs/SSOT.md` because response
caching is broader than the core identity-binding mechanism.

## Boundary

Response caching and security-state caching are different things.

Response caching stores endpoint results for reuse. Replay caches store one-shot
freshness state. Verified Identity Grants, Session Binding Statements,
attestation evidence, authorization decisions, and prior verification results
are security state. They are not cacheable acceptance evidence for a later
session or request.

## Default

The default for profile-sensitive endpoints is `no-store`.

| Directive | Meaning |
| --- | --- |
| `no-store` | A cache MUST NOT store the response. This is required for identity tokens, Session Binding Statements, attestation evidence, capability grants, authorization decisions, and responses containing session-bound or caller-sensitive data. |
| `public` | A shared cache MAY store the response only when the response is invariant across Agent ID, principal, tenant, authority scope, policy grant, mTLS certificate identity, attestation result, session binding, task state, and other verifier-local policy inputs. |
| `private` | A shared cache MUST NOT store the response. An agent-local or principal-local cache MAY store it only inside the relevant identity or policy partition. |
| `max-age` | Response freshness lifetime. It does not extend token, grant, binding, revocation, attestation, or local policy lifetimes. |
| `vary` | Identity, policy, or request fields that partition a cached response when the response can differ by caller or authority context. |

`public` is a strong assertion. A public response must not depend on caller
identity, scope, principal, tenant, policy grant, mTLS certificate, attestation
result, session binding, task state, or any other verifier-local policy input.

Private cache hits do not bypass current security checks. A verifier still
authenticates the current Identity Grant, verifies the current Session Binding
Statement, checks replay state, and compares local policy before using a cached
response. Cache hit is a performance result, not an authorization result.

## Partitioning

When a response can vary by caller or authority context, the cache key or cache
partition must include the relevant inputs. Common partition inputs include:

- Agent ID;
- principal or subject;
- tenant or authority partition;
- authority scope;
- policy grant hash;
- mTLS certificate or certificate-derived identity;
- attestation result class;
- session context;
- task, route, resource, or capability reference.

If the implementation cannot prove that the response is public and invariant,
it should use `private` with explicit partitioning or `no-store`.
