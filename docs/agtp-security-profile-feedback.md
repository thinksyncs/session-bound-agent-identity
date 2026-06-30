# AGTP Security-Profile Notes

This non-normative note lists AGTP-facing security-profile notes. The
normative source of truth for this repository is `docs/SSOT.md`.

The scope is limited to security-hardening behavior that changes what an
implementation must reject. Detailed protocol mechanics, generic token behavior,
and editorial preferences are outside this note unless they affect acceptance
or rejection.

AGTP core is treated as existing work in the
[Agent2Agent GitHub repository](https://github.com/a2aproject/A2A) and as one
reference target for this profile. This repository does not redefine AGTP core
protocol behavior or define an AGTP subset. The intended contribution is
narrower and optional:

- optional security-profile requirements for semantic binding,
  canonicalization, replay, and fail-closed local-policy checks in AGTP-like
  deployments;
- implementation feedback from the
  [Cocos](https://github.com/ultravioletrs/cocos) legacy session/attestation
  binding and identity-policy work;
- interop and negative test vectors for security-sensitive behavior.

## Selection Rule

Keep an item here only when it affects one of these acceptance failures:

- a binding from the wrong live TLS or attestation session is accepted;
- the right platform is accepted for the wrong service, tenant, agent, task, or
  authority boundary;
- replay, stale state, missing state, or required-mode downgrade is accepted;
- peer-selected metadata becomes verifier policy.

Omit items that are mainly:

- AGTP message syntax that belongs to the core AGTP draft;
- AGTP transport selection;
- agent discovery semantics;
- generic OAuth, OIDC, JWT, JWS, CWT, or COSE behavior;
- editorial naming or explanatory wording without a security test impact.

## Candidate Items

These items can be shared as candidate security-profile requirements and
test-vector requests.

| ID | Security question | Profile decision | Test-vector anchor |
| --- | --- | --- | --- |
| AGTP-FB-01 | How is AGTP-carried identity material bound to the accepted TLS and attestation session? | A Session Binding Statement must be verifiable against the accepted endpoint key, exporter context, attestation binder when present, and replay state. Mismatches fail closed. | `hwtls-id-profile-relay-001`; `TestAGTPObservedIdentityRedTeamRejectsAttestationBinderMismatch`; `TestAGTPObservedIdentityRedTeamRejectsMissingAttestationBinder` |
| AGTP-FB-02 | Which semantic target values are verifier-local policy, and which are only observed peer claims? | Service, tenant, deployment, agent or workload, task or delegation, scope, resource, and authorization values must be compared against local expected policy. Peer-provided values must not become expected values. | `hwtls-id-profile-diversion-001`; `hwtls-id-profile-wrong-agent-001`; `hwtls-id-profile-binding-confusion-001` |
| AGTP-FB-03 | Which freshness values are one-shot, and what happens when replay state is unavailable? | Required freshness checks must use fail-closed replay state. A repeated Session Binding Statement identifier, nonce, or task-binding value is rejected. | `hwtls-id-profile-replay-001` |
| AGTP-FB-04 | What happens in required mode when grant or binding material is missing, unsupported, substituted, or only partially verified? | Required mode fails closed. A Manager-signed Identity Grant authorizes upper-layer semantics; an Agent-signed Session Binding Statement binds that grant to the accepted session. Neither statement alone is sufficient. | `hwtls-id-profile-downgrade-001`; `TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution` |
| AGTP-FB-05 | Which endpoint responses are safe for shared caching, and which are caller-dependent? | AGTP response caching uses RFC 9111-style `public`, `private`, `no-store`, `max-age`, and `vary` semantics. `public` means caller-invariant across Agent ID, principal, scope, tenant, policy grant, certificate identity, and session context. Caller-dependent responses are `private` with adequate partitioning or `no-store`. Security inputs and prior verification results must not be cached as acceptance evidence. | `TestValidateResponseCachePolicyRedTeamRejectsCallerDependentPublicCache`; `TestValidateResponseCachePolicyRedTeamPartitionsPrivateCache` |

AGTP may carry identity and policy material, but it must not make
peer-controlled metadata authoritative.

Binding means receiver-verifiable linkage, not necessarily embedding a TLS
session identifier in the statement.
