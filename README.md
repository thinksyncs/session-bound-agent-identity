# AGTP aTLS Profile

This repository explores an aTLS-backed security profile for AGTP.

The goal is to make AGTP deployments easier to review for relay resistance,
diversion resistance, same-machine wrong-agent confusion, replay resistance, and
binding-parameter confusion.

This repository does not define the AGTP core protocol. It is intended as a
companion security profile, implementation-feedback workspace, and test-vector
set for existing AGTP work.

## Why This Profile Exists

aTLS is strong at lower-layer channel and attestation binding. AGTP is the
application protocol context in which agents exchange work. The gap is that
relay resistance, diversion resistance, wrong-agent resistance, replay
resistance, and authorization binding are often discussed as if they were one
property.

This profile makes those obligations explicit. It decomposes endpoint
authenticity into L0-L7 binding questions, maps each risk to the layer where the
first missing binding appears, and turns that mapping into negative test
vectors. That makes the profile easier to review than a single broad claim such
as "the peer is authenticated" or "the session is attested."

## Specification Overview

The profile treats endpoint authenticity as a layered binding problem. Each
layer asks a different "same-X" question. aTLS covers the lower transport and
attestation facts. AGTP carries or references the profile material needed to
bind those facts to the intended deployment, agent, task, and authorization
policy.

| Layer | Binding question | Primary mechanism | Main owner |
| --- | --- | --- | --- |
| L0 | Same live TLS channel? | TLS 1.3 handshake, certificate validation, session keys | aTLS / TLS |
| L1 | Same trusted platform or VM evidence? | remote-attestation evidence appraisal, CoRIM or local measurement policy | aTLS / attestation verifier |
| L2 | Same evidence or authenticator bound to that TLS session? | Exported Authenticator, TLS exporter binding, request context, Session Binding Statement | aTLS, then AGTP profile |
| L3 | Same intended service, tenant, deployment, or environment? | Manager-signed Identity Grant, local expected deployment policy | AGTP profile / local policy |
| L4 | Same intended workload, process, or agent? | agent identity, workload identity, confirmation key binding | AGTP profile / local policy |
| L5 | Same task, thread, context, or delegation? | task id, context id, delegation token, replay cache | AGTP profile / application state |
| L6 | Same authorization or capability? | scope, resource, authorization details, policy engine decision | AGTP profile / authorization policy |
| L7 | Same current trust lifecycle state? | key rotation, revocation, registry freshness, version pinning, audit state | deployment / registry operations |

The current Go identity-policy API focuses on L3 through L6 checks after aTLS
has accepted the lower-layer session. L7 is an operational profile requirement:
deployments must decide which registries, JWKS endpoints, revocation sources,
and replay-cache backends are authoritative.

## Risk Guide

The profile separates risks by the lowest layer where binding is missing,
ambiguous, stale, or controlled by the peer.

| Risk | Short description | Main layers | Expected profile response |
| --- | --- | --- | --- |
| Relay / borrowed evidence | Evidence or a binding proof from one endpoint is accepted on another live session. | L0-L2 | Reject if the Session Binding Statement does not match the accepted aTLS key, exporter context, or replay state. |
| Replay | A previously valid grant or binding statement is reused. | L2, L5, L7 | Require freshness, expiry, unique ids, and a replay cache. Fail closed if replay state is unavailable. |
| Diversion | The peer is genuine, but not the intended service, tenant, deployment, or environment. | L3 | Compare Manager-signed grant values with local expected deployment policy. |
| Same-machine wrong-agent | The machine or VM is acceptable, but the workload, process, or agent is not. | L4 | Require agent or workload identity and confirmation-key binding. |
| Cross-task confusion | The peer is correct, but the response is tied to the wrong task, thread, context, or delegation. | L5 | Bind task or delegation identifiers and reject mismatches or replays. |
| Confused deputy / over-authorization | The peer is correct, but the requested action is not authorized. | L6 | Check scopes, resources, authorization details, and local policy decisions. |
| Binding-parameter confusion | The verifier treats peer-provided labels, contexts, keys, grants, or expected values as local policy. | L2-L6 | Keep observed values separate from expected values. Fail closed on unsupported labels, token types, versions, or algorithms. |
| Stale trust state | A key, grant, registry entry, or revocation state is outdated. | L7 | Require key rotation, revocation checks, registry freshness, and audit policy. |

## Focus

- aTLS session binding for AGTP profile data
- Manager-signed identity grants
- Session Binding Statements tied to the accepted aTLS session
- local expected-value checks for deployment, agent, task, and capability
- negative test vectors for relay, diversion, wrong-agent, replay, downgrade,
  stale evidence, measurement mismatch, and binding-parameter confusion

## Non-Goals

- redefining AGTP core messages
- replacing AGTP transport choices
- replacing Cocos
- defining a complete OAuth or OIDC profile
- inventing new cryptography

## Repository Layout

- `docs/architecture.md`: security-profile architecture and role split
- `docs/threat-model.md`: relay, diversion, wrong-agent, replay, and downgrade
  threat model
- `docs/agtp-atls-binding-profile.md`: aTLS binding expectations for AGTP
- `docs/agtp-security-profile-mapping.md`: profile validation state machine and
  error mapping
- `docs/agtp-security-profile-feedback.md`: draft-feedback scope and boundaries
- `interop/testvectors/`: positive and negative security-profile vectors
- `pkg/agtp/`: AGTP identity grant and session-binding helpers
- `pkg/atls/identitypolicy/`: local expected-value policy checks

## Test Vectors

The initial test-vector set is in `interop/testvectors/vectors.jsonl`.

It covers:

- baseline acceptance
- relay or borrowed-evidence rejection
- diversion rejection
- same-machine wrong-agent rejection
- replay rejection
- binding-parameter confusion rejection
- downgrade rejection
- stale-evidence rejection
- measurement-mismatch rejection
- policy-denied rejection

The vectors are profile-level vectors. They do not define AGTP core syntax.

## Relationship to Cocos

This repository started from Cocos aTLS implementation experience. Cocos is
treated here as related implementation experience and as a source of concrete
security-profile requirements.

This repository does not replace Cocos and should not be read as a Cocos fork
continuation.

## Relationship to AGTP

AGTP core is treated as existing draft work. This repository explores security
checks and test vectors that can be proposed as implementation guidance or draft
feedback.

The central rule is simple: AGTP may carry identity and policy material, but it
must not make peer-controlled metadata authoritative.

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
