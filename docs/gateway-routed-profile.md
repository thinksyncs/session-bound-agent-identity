# Gateway-Routed Profile

This document is a future profile sketch, not part of the v0.1 core
direct-Agent profile. In gateway-routed mode, the gateway terminates the TLS
session and performs the hardware-aware profile checks. The gateway is the live
TLS endpoint. Gateway session binding proves the gateway endpoint, not the
final Agent process.

The v0.1 runtime client path implements direct-Agent mode. A gateway-routed
deployment needs a separate route assertion before the relying party can treat
the final Agent as accepted.

## Route Assertion

A gateway route assertion is signed by a gateway route-signing key. That key
must be authorized by local verifier policy, a trusted gateway registry, or the
Manager-signed Identity Grant. It must not be inferred merely from the
client-to-gateway TLS endpoint key. The gateway route-signing key is a separate
key use from Manager signing keys and Agent confirmation keys.

The gateway route assertion states what the gateway observed and what it
guarantees. At minimum it contains:

- profile token type and version for a gateway route assertion;
- issuer or gateway ID;
- protected `kid` for the gateway route-signing key;
- relying-party audience;
- `jti`, `iat`, `exp`, and one-shot nonce;
- `grant_hash` for the exact verified Identity Grant;
- client-to-gateway session-binding hash or Session Binding Statement hash;
- gateway route ID and selected upstream endpoint;
- tenant, principal, authority scope, and policy partition identifiers when the
  gateway serves more than one authority context;
- final Agent ID, workload identity, and expected Agent confirmation key or key
  thumbprint;
- upstream authentication method, such as mTLS, SPIFFE/SPIRE workload identity,
  service-mesh identity, or an Agent holder-of-key proof;
- upstream peer identity observed by the gateway;
- request or task context hash when the route is task- or request-scoped.

mTLS, SPIFFE/SPIRE, service-mesh identity, and workload identity can be inputs
to the gateway's observation. They do not by themselves become relying-party
acceptance evidence unless the gateway signs the route assertion and the
verifier checks it against local policy. The gateway must map those inputs to
canonical Agent and workload identifiers before signing.

An Agent-side holder-of-key proof is required unless local policy explicitly
trusts the gateway as the delegation authority for the final Agent process. When
required, the gateway route assertion carries the Agent proof hash or key
thumbprint, and the verifier rejects the route if the proof is absent, expired,
replayed, signed by the wrong key, or not tied to the same `grant_hash`, route,
tenant partition, and request context.

## Replay and Partitioning

Gateway replay handling is separate from direct-Agent Session Binding Statement
replay handling. The replay cache key for gateway route assertions includes at
least:

```text
gateway_id || aud || tenant_partition || route_id || grant_hash || nonce
```

Multi-tenant gateways must partition route assertions, replay state, response
caches, and key caches by tenant or equivalent authority boundary. A route
assertion accepted for one tenant, principal, authority scope, route, Agent, or
task must not be reused for another.

## Failure Semantics

Failure semantics are fail-closed. The verifier rejects missing route
assertions, stale route assertions, unknown or disabled gateway route keys,
wrong tenant partitions, stale gateway registries, route-policy mismatches,
unavailable replay state, missing Agent holder-of-key proof when required, and
gateway assertions that only prove the gateway endpoint.

If the gateway route signing key or gateway policy authority is compromised,
this profile cannot recover the true final Agent identity. The deployment must
rely on gateway key revocation, route-policy rollback, audit, and isolation
controls.
