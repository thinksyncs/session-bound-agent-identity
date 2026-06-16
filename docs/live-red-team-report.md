# Live Red-Team Completion Report

This report summarizes the completed live-style red-team work for the
hardware-aware TLS identity-binding profile. The normative profile source is
`docs/SSOT.md`.

## Status

Branch-scoped implementation and verification are complete as of 2026-06-13.
Additional local regressions were run on 2026-06-16 for attestation-binder
absence and Manager/Agent key-role separation.

- Implementation verification commit: `2ebd52694d88bef6d0a5e3fae2593ec9bfdf8647`
- GitHub Actions `Security Red Team` run #3 on that commit: success
- GitHub Actions `CI` run #3 on that commit: success

The completed branch covers the current direct-Agent AGTP/aTLS profile. A
gateway-routed profile remains separate design work because its trust model is
different: the gateway is the TLS endpoint and must authenticate the
gateway-to-Agent route before the intended Agent can be treated as accepted.

## Verification Evidence

GitHub Actions:

| Workflow | Run | Result | Notes |
| --- | --- | --- | --- |
| `Security Red Team` | `27466465706` | Success | Dedicated red-team workflow for AGTP/aTLS security packages |
| `CI` | `27466465697` | Success | `lint`, `Build`, all Go test matrix jobs, and coverage upload passed |

Local verification:

```sh
/opt/homebrew/bin/go test -v -race -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/clients ./pkg/atls/internal_transport
git diff --check
```

Both checks passed for the referenced implementation commit.

Focused local regression run on 2026-06-16:

```sh
env GOCACHE=/tmp/go-build-cocos go test -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/clients
```

All three packages passed.

## Implemented Coverage

| Test | Coverage | Result |
| --- | --- | --- |
| `TestAGTPObservedIdentityAcceptsManagerIssuedGrantE2E` | Manager-signed Identity Grant plus Agent-signed Session Binding Statement through the client hook. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRealTLSAttestationBinding` | Real TLS 1.3 exporter-derived attestation binder is accepted, while a binding borrowed from another TLS / attestation session is rejected. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityAcceptsHTTPJWKSAndRejectsRevocation` | HTTP-backed key lookup and revoked grant `jti` rejection. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsAttacks` | Peer-signed grant, service/tenant/deployment diversion, borrowed leaf-key binding, and borrowed request context. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsAgentThreats` | Agent/task/delegation/scope/resource/authorization red-team cases through the same client hook. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsReplay` | Reuse of the same valid Session Binding Statement against the same replay cache. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsReplayRace` | Concurrent reuse of the same valid Session Binding Statement through one shared replay cache. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsReplayRaceMultiProcess` | Multiple local worker processes race the same valid Session Binding Statement through one HTTP SETNX-style replay service. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsKeyAndRevocationFailures` | Stale JWKS, key rotation overlap, HTTP JWKS 500 and timeout, revocation-source outage, disabled Manager key, revoked grant `jti`, and disabled Agent binding key failures. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsAttestationBinderMismatch` | Session Binding Statement with only `attestation_binder_sha256` changed from the accepted attestation binder. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsMissingAttestationBinder` | Accepted lower-layer attestation binder requires `attestation_binder_sha256` in the Session Binding Statement. | Passed locally |
| `TestAGTPObservedIdentityRedTeamRejectsManagerKeyAsBindingKey` | Manager signing key cannot be reused as the Agent confirmation or Session Binding Statement key. | Passed locally |
| `TestAGTPObservedIdentityRedTeamRejectsGrantSubstitution` | Binding statement whose `grant_hash` targets a different Manager-signed Identity Grant. | Passed locally and in GitHub Actions |
| `TestAGTPObservedIdentityRedTeamRejectsVerifiedGrantCacheMisuse` | Previously accepted grant reused after the grant `jti` is revoked, with a fresh binding nonce. | Passed locally and in GitHub Actions |
| `TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution` | Single-envelope JWT/JWS rejects inner-grant substitution, outer `grant_hash` mismatch, skipped inner or outer signature verification, Agent-signed semantic claims, and missing inner grants. | Passed locally and in GitHub Actions |
| `TestVerifySessionIdentityCWTAcceptsManagerGrantAndLocalPolicy` | Manager-signed CWT/COSE Identity Grant plus Agent-signed CWT/COSE Session Binding Statement map to the same identity-policy model as JWT/JWS. | Passed locally and in GitHub Actions |
| `TestVerifySessionIdentityCWTRedTeamRejectsCOSEProfileAttacks` | CWT/COSE rejects forged grants, tampered grant signatures, wrong binding signers, grant substitution, stale bindings, local-policy mismatch, and unprotected `kid`. | Passed locally and in GitHub Actions |
| `TestValidateResponseCachePolicyRedTeamRejectsCallerDependentPublicCache` | Caller-dependent endpoint declared `public` is rejected; the harness shows the cross-Agent collision that a method/path/input-only shared cache would create. | Passed locally |
| `TestValidateResponseCachePolicyRedTeamPartitionsPrivateCache` | Caller-dependent endpoint declared `private` with `Agent-ID` and `Authority-Scope` partitioning does not leak an admin-scoped cached response to a read-only Agent. | Passed locally |

## LRTT Status

| ID | Status | Completion evidence | Boundary |
| --- | --- | --- | --- |
| LRTT01 | Completed for the dependency-free CI harness | `TestAGTPObservedIdentityRedTeamRealTLSAttestationBinding` covers real TLS 1.3 exporter binding, certificate material, accepted attestation payload, AGTP hook acceptance, and borrowed-session rejection | Hardware-generated confidential-VM evidence is not exercised in this local CI profile |
| LRTT02 | Completed | `TestVerifySessionIdentityCWTAcceptsManagerGrantAndLocalPolicy` and `TestVerifySessionIdentityCWTRedTeamRejectsCOSEProfileAttacks` | Runtime client configuration remains JWT/JWS-wired unless callers use the CWT verifier directly |
| LRTT03 | Completed | `TestAGTPObservedIdentityRedTeamRejectsReplayRaceMultiProcess` | Real multi-node Redis / Valkey deployment is outside the local harness |
| LRTT04 | Completed | `TestAGTPObservedIdentityRedTeamRejectsKeyAndRevocationFailures` | None for the modeled HTTP key and revocation failure modes |
| LRTT05 | Completed | `TestAGTPObservedIdentityRedTeamRejectsAttestationBinderMismatch` | None for binder mismatch comparison |
| LRTT06 | Completed | `TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution` | Runtime client configuration remains two-token JWT/JWS-wired unless callers use the envelope verifier directly |
| LRTT07 | Completed | `TestAGTPObservedIdentityRedTeamRejectsVerifiedGrantCacheMisuse` | None for the modeled verified-grant cache misuse path |
| LRTT08 | Out of scope for this completed direct-Agent branch | SSOT separates gateway mode from the direct-Agent trust model | Requires a gateway-routed profile before meaningful red-team tests can be implemented |
| LRTT09 | Completed locally | `TestValidateResponseCachePolicyRedTeamRejectsCallerDependentPublicCache`; `TestValidateResponseCachePolicyRedTeamPartitionsPrivateCache` | This is a dependency-free policy and cache-key harness, not a live AGTP daemon response-cache implementation |

## Completed Changes

- Consolidated the profile SSOT into `docs/SSOT.md`.
- Added the AGTP security-profile feedback list in
  `docs/agtp-security-profile-feedback.md`.
- Added JWT/JWS single-envelope verification and substitution red-team tests.
- Added CWT/COSE Identity Grant and Session Binding Statement verification with
  COSE profile red-team tests.
- Added local multi-process replay-race coverage through a shared SETNX-style
  replay service.
- Added key and revocation failure-mode coverage for stale JWKS, timeouts,
  HTTP 500, key rotation overlap, disabled keys, and revoked grant IDs.
- Added response-cache policy coverage for caller-dependent shared-cache
  leakage and private cache partitioning.
- Added the dedicated `.github/workflows/security-red-team.yaml` workflow.

## Residual Boundaries

These are not blockers for the completed branch; they are profile or deployment
boundaries that need separate work if the project chooses to support them.

- Hardware-generated confidential-VM attestation evidence is not produced inside
  GitHub Actions.
- CWT/COSE verification exists in `pkg/agtp`, but client configuration is still
  wired for the JWT/JWS runtime path.
- Replay race coverage uses a local HTTP SETNX-style service, not a real
  multi-node Redis or Valkey deployment.
- Gateway-routed deployments need a separate gateway trust profile and route
  assertion before LRTT08 can become executable.
