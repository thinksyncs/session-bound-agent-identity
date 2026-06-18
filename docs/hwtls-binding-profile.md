# Hardware-Aware TLS Binding Profile

Hardware-aware TLS binding expectations apply to application-profile material.
AGTP is one reference target, but the profile does not define AGTP core syntax
or introduce new cryptography.

Hardware-aware TLS means an application-profile acceptance gate over ordinary
TLS 1.3 plus post-handshake platform attestation bound to the accepted TLS
session. It is not a TLS extension, a replacement for the TLS 1.3 handshake, or
pre-TLS platform authentication. The application should withhold profile-level
trust until the post-handshake attestation and binding checks succeed.

## Binding Goal

The relying party should accept application-profile material only when it is
tied to the same accepted TLS session and to locally expected identity policy.

The profile separates two questions:

- L2 relay defense: is the profile material bound to this accepted TLS
  session?
- L3 and above: is the accepted session the intended deployment, agent, task, or
  authorized actor?

## Exporter Label and Context

The direct-Agent profile uses:

- exporter label: `Attestation`;
- exporter context: the exact Exported Authenticator
  `certificate_request_context` bytes;
- exporter length: 32 bytes;
- binding input: accepted leaf certificate SubjectPublicKeyInfo plus exporter
  output;
- Session Binding Statement fields: `leaf_public_key_sha256`,
  `tls_exporter_sha256`, `request_context_sha256`, and
  `attestation_binder_sha256`.

`attestation_binder_sha256` is the compact statement reference to the accepted
attestation-channel binding. It connects the endpoint key, current TLS exporter
value, verifier-accepted request context, and fresh evidence or verifier results
that carry the same binding. It is not a standalone freshness proof; stale or
unbound evidence still fails.

`leaf_public_key_sha256` confirms the accepted endpoint key. It is not
session-unique by itself, because the same certificate key can be reused across
many TLS sessions. The primary binding is the exporter output under the
verifier-accepted context, together with the grant hash, audience, nonce, and
replay state.

`tls_exporter_sha256` is mandatory in the v0.1 direct-Agent profile. It is the
SHA-256 digest of the accepted TLS exporter output, not a peer-chosen value.

Rules:

- the verifier must not adopt a peer-supplied exporter label as the expected
  label;
- unsupported labels fail closed;
- context values must be canonical byte strings that separate authentication
  instances on the same TLS connection;
- each context must name the profile version, protocol id, relying-party
  audience, direction or role, exact grant hash, and a fresh verifier nonce or
  binding-attempt id;
- task, thread, delegation, capability, resource, method, path, or tenant
  values that affect local policy must be present in the context or compared
  from verifier-local state before acceptance;
- context values used for task, grant, delegation, or capability binding must be
  compared with local expected state;
- replay cache entries must include the grant hash, audience,
  TLS exporter hash, request-context hash, and nonce;
- HTTP/2 multiplexing, connection pooling, TLS resumption, and 0-RTT data must
  not reuse an old Session Binding Statement or attestation binder as acceptance
  evidence.

## Evidence and Authenticator Freshness

Profile deployments MUST define:

- evidence lifetime and freshness challenge handling;
- attestation-results lifetime;
- grant lifetime;
- session-binding statement lifetime;
- maximum clock skew;
- replay-cache TTL.

Measurement matching alone is not freshness. A correct but old hardware report
MUST be rejected unless it is bound to the current verifier challenge, TLS
exporter value, and application context. Attestation results are acceptable only
when a trusted verifier signs or references that same binding.

Recommended starting point:

| Value | Starting policy |
| --- | --- |
| Evidence challenge | fresh per authentication attempt |
| Evidence acceptance | current challenge and current attempt only |
| Attestation results lifetime | bounded and no longer than the Session Binding Statement lifetime |
| Identity Grant lifetime | short-lived, deployment-defined |
| Session Binding Statement lifetime | very short-lived, session-scoped |
| Replay cache TTL | at least the binding statement lifetime plus clock skew |
| Clock skew | explicit, small, and locally configured |

## Binding Statement Requirements

A Session Binding Statement should include:

- profile type;
- profile version;
- grant hash;
- accepted TLS endpoint key or key fingerprint as auxiliary endpoint
  confirmation;
- accepted exporter context hash or equivalent session-binding value;
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
