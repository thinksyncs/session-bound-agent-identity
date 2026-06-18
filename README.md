# Hardware-Aware TLS Identity Binding Profile

This repository defines a small security-hardening profile for binding a TLS
1.3 session to hardware-attestation evidence and application identity policy.

Hardware-aware TLS here means an application-profile acceptance gate over
ordinary TLS 1.3 plus post-handshake platform attestation and session binding.
It is not a TLS extension and it is not pre-TLS platform authentication.
The older shorthand `aTLS` appears only for existing
[Cocos](https://github.com/ultravioletrs/cocos) code paths, package names, or
historical terms.

The main specification and single source of truth is `docs/SSOT.md`. It defines the
layer names, semantic-reference rules, and verification order used by the rest
of the repository.

The profile makes relay, diversion, wrong-agent, replay, and
binding-parameter failures concrete. The layer split is one decomposition, not
the only possible taxonomy. AGTP / Agent2Agent is one reference target; see the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A). The
[nomoticai/agtp](https://github.com/nomoticai/agtp) repository was also used as
an implementation reference for AGTP-facing profile feedback. The same checks
can also be reused by other application protocols with similar identity-binding
needs.

## Why This Profile Exists

TLS gives the live encrypted channel. Post-handshake attestation can add
evidence about the platform behind that channel. Agent deployments still need
more: the peer must be the intended service, agent, task, and authority
boundary.

This profile splits those questions into L0-L7 layers. Each risk maps to the
first layer where a binding is missing, ambiguous, stale, or peer-controlled.
The result is a compact set of security-hardening rules and negative test
vectors, instead of a single broad claim that "the peer is authenticated."

## Specification Overview

Endpoint authenticity is treated as a layered binding problem. TLS 1.3
establishes the live channel. The hardware-aware TLS profile adds
post-handshake platform-attestation and session-binding checks. Application
policy then binds those facts to the intended deployment, agent, task, and
authorization decision.

| Layer | Binding question | Primary mechanism | Main owner |
| --- | --- | --- | --- |
| L0 | Same live TLS channel? | TLS 1.3 handshake, certificate validation, session keys | TLS |
| L1 | Same trusted platform or VM evidence? | remote-attestation evidence appraisal, CoRIM or local measurement policy | hardware-attestation verifier |
| L2 | Same evidence or authenticator bound to that TLS session? | Exported Authenticator, `tls_exporter_sha256`, request context, Session Binding Statement | hardware-aware TLS profile, then application profile |
| L3 | Same intended service, tenant, deployment, or environment? | Manager-signed Identity Grant, local expected deployment policy | application profile / local policy |
| L4 | Same intended workload, process, or agent? | agent identity, workload identity, confirmation key binding | application profile / local policy |
| L5 | Same task, thread, context, or delegation? | task id, context id, delegation token, replay cache | application profile / application state |
| L6 | Same authorization or capability? | scope, resource, authorization details, policy engine decision | application profile / authorization policy |
| L7 | Same current trust lifecycle state? | key rotation, revocation, registry freshness, version pinning, audit state | deployment / registry operations |

The current Go identity-policy API focuses on L3 through L6 checks after the
lower-layer hardware-aware TLS checks have accepted the session. L7 is an
operational profile requirement:
deployments must decide which registries, JWKS endpoints, revocation sources,
and replay-cache backends are authoritative.

### Reference-Value Normalization

Decision-sensitive values such as `intentRef`, `capabilityRef`, and
`ontologyId` must already be canonical before verification. Receivers compare
them deterministically and do not repair peer-provided aliases, display labels,
URI variants, or free-form text in the final acceptance path.

Canonical references also need a trusted registry namespace and version. The
same string from two registries, or from two registry versions, is not
automatically the same authority value.

## Risk Guide

The profile separates risks by the lowest layer where binding is missing,
ambiguous, stale, or controlled by the peer.

In this guide, "semantic diversion" is an umbrella term for cases where the
channel, session, token, or peer may be valid, but the action is bound to the
wrong semantic target, context, delegation, capability, or authority boundary.
The rows below split that family by the lowest layer where the missing binding
first appears.

| Risk | Short description | Main layers | Expected profile response |
| --- | --- | --- | --- |
| Relay / borrowed evidence | Evidence or a binding proof from one endpoint is accepted on another live session. | L0-L2 | Reject if the Session Binding Statement does not match the accepted TLS key, exporter context, or replay state. |
| Replay | A previously valid grant or binding statement is reused. | L2, L5, L7 | Require freshness, expiry, unique ids, and a replay cache. Fail closed if replay state is unavailable. |
| Service / tenant diversion | The peer is genuine, but not the intended service, tenant, deployment, or environment. | L3 | Compare Manager-signed grant values with local expected deployment policy. |
| Same-machine wrong-agent | The machine or VM is acceptable, but the workload, process, or agent is not. | L4 | Require agent or workload identity and confirmation-key binding. |
| Cross-task / context diversion | The peer is correct, but the response is tied to the wrong task, thread, context, or delegation. | L5 | Bind task or delegation identifiers and reject mismatches or replays. |
| Confused deputy / over-authorization | The peer is correct, but the requested action is not authorized. | L6 | Check scopes, resources, authorization details, and local policy decisions. |
| Binding-parameter confusion | The verifier treats peer-provided labels, contexts, keys, grants, or expected values as local policy. | L2-L6 | Keep observed values separate from expected values. Fail closed on unsupported labels, token types, versions, or algorithms. |
| Stale trust state | A key, grant, registry entry, or revocation state is outdated. | L7 | Require key rotation, revocation checks, registry freshness, and audit policy. |

## Focus

- hardware-aware TLS session binding for application-profile data
- Manager-signed identity grants
- Session Binding Statements tied to the accepted TLS session
- separate Manager signing keys and Agent confirmation keys
- local expected-value checks for deployment, agent, task, and capability
- negative test vectors for relay, diversion, wrong-agent, replay, downgrade,
  stale evidence, measurement mismatch, and binding-parameter confusion

## Evaluation Status

The v0.1 evaluation is useful but not sufficient proof of the full security
claim. It combines focused local checks, negative test vectors, unit-level
coverage, and dependency-free live-style harnesses. The remaining work is
tracked in `docs/live-red-team-report.md`, including real network relay,
hardware-generated borrowed attestation, multiplexed connection reuse,
resumption and 0-RTT behavior, gateway routing, fuzzing, and a small invariant
model.

## Non-Goals

- redefining AGTP core messages
- replacing AGTP transport choices
- replacing Cocos
- defining a complete OAuth or OIDC profile
- inventing new cryptography

## Repository Layout

- `docs/SSOT.md`: single normative source of truth for layer names,
  semantic-reference rules, and verification order
- `docs/architecture.md`: security-profile architecture and role split
- `docs/threat-model.md`: relay, diversion, wrong-agent, replay, and downgrade
  threat model
- `docs/hwtls-binding-profile.md`: hardware-aware TLS binding expectations
  for application profiles
- `docs/http-cache-profile.md`: non-normative HTTP response-cache profile for
  endpoints near identity-binding decisions
- `docs/gateway-routed-profile.md`: non-core gateway route-assertion sketch for
  future gateway-routed deployments
- `docs/agtp-security-profile-mapping.md`: profile validation state machine and
  error mapping
- `docs/agtp-security-profile-feedback.md`: high-priority AGTP security-profile
  feedback
- `docs/live-red-team-report.md`: current live-style red-team coverage and LRTT
  backlog
- `docs/static-diversion-policy.md`: static service / tenant diversion policy
- `interop/testvectors/`: positive and negative security-profile vectors
- `pkg/agtp/`: AGTP identity grant and session-binding helpers
- `pkg/agtp/diversionpolicy/`: static diversion-policy evaluator
- `pkg/atls/identitypolicy/`: local expected-value policy checks

## Test Vectors

The initial test-vector set is in `interop/testvectors/vectors.jsonl`.
Static diversion-policy examples are in
`interop/testvectors/diversion-policy-examples.jsonl`.

It covers:

- baseline acceptance
- relay or borrowed-evidence rejection
- service / tenant diversion rejection
- same-machine wrong-agent rejection
- replay rejection
- binding-parameter confusion rejection
- downgrade rejection
- stale-evidence rejection
- measurement-mismatch rejection
- policy-denied rejection

The vectors are profile-level vectors. They do not define AGTP core syntax.

## Implementation Provenance

This repository is forked from
[ultravioletrs/cocos.git](https://github.com/ultravioletrs/cocos.git). This
work uses Cocos hardware-attested TLS as related implementation experience and
as a source of concrete requirements. Cocos itself is not the scope of this
security profile.

## Reference Protocol Notes

AGTP is a natural reference target; see the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A) and
[nomoticai/agtp](https://github.com/nomoticai/agtp). This repository stays at
the security-profile and test-vector layer. AGTP, or any similar application
protocol, may carry identity and policy material, but it does not by itself
provide all of the semantic binding, canonical-reference, replay, and
local-policy checks needed here. This profile adds those checks as security
hardening and must not make peer-controlled metadata authoritative.

## Verification

For the current local implementation checks:

```sh
go test ./pkg/agtp ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Some client tests open local loopback listeners. In restricted sandboxes, those
tests may need to run outside the sandbox.

## License

This repository currently keeps the original Apache-2.0 license.
