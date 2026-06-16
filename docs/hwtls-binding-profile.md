# Hardware-Aware TLS Binding Profile

Hardware-aware TLS binding expectations apply to application-profile material.
AGTP is one reference target, but the profile does not define AGTP core syntax
or introduce new cryptography.

Hardware-aware TLS means ordinary TLS 1.3 plus post-handshake platform
attestation bound to the accepted TLS session. It is not a replacement for the
TLS 1.3 handshake and is not pre-TLS platform authentication. The application
should withhold profile-level trust until the post-handshake attestation and
binding checks succeed.

## Binding Goal

The relying party should accept application-profile material only when it is
tied to the same accepted TLS session and to locally expected identity policy.

The profile separates two questions:

- L2 relay defense: is the profile material bound to this accepted TLS
  session?
- L3 and above: is the accepted session the intended deployment, agent, task, or
  authorized actor?

## Exporter Label and Context

Implementations should use locally expected exporter labels and contexts.

Rules:

- the verifier must not adopt a peer-supplied exporter label as the expected
  label;
- unsupported labels fail closed;
- context values must be fresh enough for the profile's replay window;
- context values used for task or grant binding must be compared with local
  expected state.

## Evidence and Authenticator Freshness

Profile deployments should define:

- evidence lifetime;
- grant lifetime;
- session-binding statement lifetime;
- maximum clock skew;
- replay-cache TTL.

Recommended starting point:

| Value | Starting policy |
| --- | --- |
| Identity Grant lifetime | short-lived, deployment-defined |
| Session Binding Statement lifetime | very short-lived, session-scoped |
| Replay cache TTL | at least the binding statement lifetime plus clock skew |
| Clock skew | explicit, small, and locally configured |

## Binding Statement Requirements

A Session Binding Statement should include:

- profile type;
- profile version;
- grant hash;
- accepted TLS endpoint key or key fingerprint;
- accepted exporter context or equivalent session-binding value;
- nonce or binding id;
- expiry;
- issuer or signer key id.

The signer must be the Agent confirmation key named by the verified Identity
Grant, or another key explicitly authorized by the verified grant or local
policy. Manager or policy-authority signing keys MUST NOT be accepted as
Session Binding Statement signer keys.

## Failure Semantics

The profile fails closed when:

- a required Identity Grant is absent;
- a required Session Binding Statement is absent;
- grant and binding statement do not match;
- the replay cache is unavailable;
- evidence or profile material is stale;
- local expected policy cannot be loaded;
- labels, contexts, token types, versions, or signing methods are unsupported.

## Privacy Limits

Binding values should not reveal more identity information than needed. The
profile uses scoped grants, short lifetimes, minimal audit fields, and
audience-restricted tokens.

## Protocol Boundary

Application protocols may carry or reference this profile material. They remain
responsible for their own message syntax, routing, and discovery semantics.
