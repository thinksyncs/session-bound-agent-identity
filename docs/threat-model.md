# Hardware-Aware TLS Identity-Binding Threat Model

This threat model covers a hardware-aware TLS 1.3 identity-binding profile.
AGTP is one reference target, but the risks are not AGTP-specific. Terminology,
layers, verification order, and the normative threat-to-design-impact mapping
are defined in `docs/SSOT.md`. This file is explanatory and should be updated
after the SSOT when the two diverge.

Hardware-aware TLS is not pre-TLS platform authentication. It is ordinary TLS
1.3 plus post-handshake platform attestation bound to the accepted TLS session.
The key question is whether the application fails closed before treating that
TLS peer as an attested application peer.

## Assumptions

- TLS 1.3 and exported-authenticator validation are implemented by the lower
  layer.
- Platform evidence appraisal is handled by the lower attestation verifier.
- The Manager or policy-authority signing key is configured locally or through
  a trusted key source.
- Peer-provided metadata is never treated as local policy.
- Replay prevention is enforced by a caller-provided cache or equivalent
  one-shot state.

## Relay

Relay is a lower-layer binding failure. The attacker tries to make the client
accept evidence, an authenticator, or a proof that belongs to a different live
session or endpoint.

Profile requirement:

- bind profile objects to the accepted TLS session;
- reject mismatched binding values;
- reject reused binding identifiers or nonces.

## Diversion

Semantic diversion is an intended-subject failure family. The channel, session,
token, or peer may be valid, but the action is bound to the wrong semantic
target, context, delegation, capability, or authority boundary.

Service / tenant diversion is the L3 subset. The accepted peer may be genuine,
but it is not the intended service, tenant, deployment, or environment.

Profile requirement:

- carry deployment identity only in authenticated grants;
- compare observed deployment identity with local expected policy;
- fail closed on missing or mismatched required values.

Static policy requirement:

- distinguish client-visible and hidden diversion;
- require reason codes and stable audit fields;
- reject policy miss, denied diversion, unsupported policy versions, and hidden
  diversion without an explicit hidden-diversion rule.

## Same-Machine Wrong-Agent

Wrong-agent confusion occurs when the machine or VM is acceptable, but the
workload, process, or agent is not the intended one.

Profile requirement:

- bind the intended agent or workload identity in the Identity Grant;
- require a confirmation key authorized for that grant;
- keep Manager or policy-authority signing keys separate from Agent
  confirmation keys;
- compare the observed agent identity with local expected policy.

## Replay

Replay occurs when a previously valid grant or binding statement is reused
outside its intended session, task, or freshness window.

Profile requirement:

- require expiration and issued-at checks;
- require a unique grant id and binding id;
- use a replay cache or equivalent one-shot state;
- fail closed when replay state is unavailable.

## Binding-Parameter Confusion

Binding-parameter confusion occurs when a verifier uses peer-supplied values as
expected local values. Examples include labels, contexts, grant ids,
confirmation keys, expected agent ids, task ids, or authorization scopes.
Semantic reference aliases are also in scope: a peer must not choose the
verifier's expected `intentRef`, `capabilityRef`, or `ontologyId`.

Profile requirement:

- distinguish local expected values from observed values;
- reject unexpected labels, contexts, token types, versions, and signing
  methods;
- reject grants or binding statements that do not match local trust policy.
- apply the canonical semantic-reference rules in
  `docs/SSOT.md`.

## Downgrade and Policy Failure

The profile must fail closed when:

- profile material is required but absent;
- only one of the grant or binding statement is present;
- the replay cache is required but unavailable;
- the token type or profile version is unsupported;
- local expected values cannot be loaded.

## Privacy

The profile should avoid unnecessary disclosure of deployment or agent identity.
Where possible, implementations should use short-lived grants, scoped audience
values, and minimal audit fields.
