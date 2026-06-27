# AI2AI Security Profile Mapping

This document maps the session-bound identity profile in `docs/SSOT.md` onto
agent-to-agent protocols such as A2A and AGTP. It is not a replacement for the
SSOT. Its purpose is to keep discovery, authentication, message metadata, and
session-bound identity in separate trust domains.

This repository's implementation surface is Direct-Agent. Wallet and gateway
sections below are boundary guidance for optional presentation components and
separate gateway-routed profiles; they are not core verifier requirements here.

## Scope

The profile adds a receiver-verifiable binding between:

- a Manager-signed Identity Grant;
- an Agent-signed Session Binding Statement;
- the accepted TLS session and profile binding facts;
- the task, context, authority scope, and authorization policy expected by the
  receiver.

It does not redefine A2A or AGTP core messages. A protocol may carry or refer
to the profile material, but acceptance still follows the SSOT verification
algorithm: verify signatures, compare the binding to the accepted session,
check replay and freshness, then compare signed observed values with local
expected policy.

## A2A and AGTP Mapping

| Protocol concept | Profile treatment |
| --- | --- |
| Agent Card | Discovery data. A signed card can authenticate card provenance and freshness, but it does not prove that the current session is bound to the Agent named in the card. |
| `securitySchemes` | Authentication negotiation data. It tells a client how to authenticate or which credentials may be required. It is not a Session Binding Statement. |
| Extended Agent Card | Authenticated discovery or capability data. It can inform local policy configuration, but it is not accepted as peer-provided policy during a request. |
| Message metadata | Descriptive transport or application data unless it contains signed profile material that is verified under this profile. Location in metadata does not make a value authoritative. |
| `message.parts` | User or application payload. Values inside parts are never promoted to identity, task, tenant, capability, or authorization policy. |
| Task, context, or session identifiers | Inputs to local expected policy and to `request_context_sha256` when the receiver has canonicalized them from trusted state. |
| AGTP `relay_id`, `next_hop`, `target_agent`, `policy_id`, `session_id`, `task_id`, `context_id`, `audit_hash` | Natural inputs to a gateway-routed profile and Gateway Route Assertion. They must be signed, freshness-checked, replay-checked, and compared with local policy before acceptance. |

The rule is simple: discovery and authentication tell the receiver how to
reach or authenticate a peer. Session-bound identity decides whether this
specific accepted interaction is the intended Agent, task, context, and
authorization boundary.

## Discovery and Authentication Boundary

Agent Card signatures, `securitySchemes`, and extended cards belong to
discovery and authentication. They may establish that a card came from a
trusted publisher, that an endpoint supports a given authentication method, or
that a peer can complete a configured authentication flow.

They do not replace:

- Manager-signed authority over Agent identity and semantics;
- Agent confirmation-key control;
- Session Binding Statement verification;
- TLS exporter, request-context, nonce, and replay checks;
- local expected-policy comparison.

A receiver MAY use trusted discovery data to configure expected policy before a
request. During request acceptance, the receiver MUST NOT copy peer-provided
card fields, metadata fields, or message-part values into expected policy.

## Metadata Boundary

Peer-provided `metadata` and `message.parts` values are untrusted for policy
unless they are inside signed profile material and pass profile verification.
This includes labels such as service name, tenant, Agent name, task name,
capability, resource, scope, intent, ontology, policy ID, or route ID.

The receiver must keep two namespaces separate:

- observed values: values authenticated by a verified Identity Grant, Session
  Binding Statement, Gateway Route Assertion, or lower-layer attestation result;
- expected values: values loaded from local configuration, task state, Manager
  state, a trusted registry, or a policy engine.

Acceptance compares observed values with expected values. It does not create
expected values from the peer's message.

## Wallet Boundary

An Agent wallet is a key-custody and credential-presentation component. It is
not a trust root. A receiver does not accept a peer because a wallet label,
display name, card field, or wallet metadata says the peer is a given Agent.

If a wallet is used, the model is:

- the Manager or policy authority issues an Identity Grant;
- the wallet stores the grant and protects the Agent confirmation key;
- the wallet signs a Session Binding Statement over canonical session input;
- the receiver verifies the same grant, binding, replay, and local-policy
  rules defined by the SSOT.

A wallet-backed signer signs only canonical binding input, such as:

- profile version and token type;
- `aud`;
- `grant_hash`;
- `tls_exporter_sha256`;
- `request_context_sha256`;
- one-shot `nonce`;
- `iat` and `exp`;
- role or direction when local policy distinguishes initiator and responder;
- task, context, or delegation binding values after canonicalization;
- Gateway Route Assertion hash in gateway-routed mode.

The receiver, not the wallet, owns expected policy. Expected values come from
local configuration, task state, Manager state, a trusted registry, or a policy
engine. Wallet metadata, UI labels, card fields, message metadata, and
`message.parts` values are descriptive unless they are inside verified profile
material and then compared with local expected policy.

### Wallet Compared With JWT and CWT

JWT/JWS and CWT/COSE are signed-token encodings. A wallet is a component that
stores credentials and signs or presents them. The wallet can produce the
existing Session Binding Statement format; it does not change what the receiver
must verify.

| Aspect | JWT/JWS or CWT/COSE token | Agent wallet |
| --- | --- | --- |
| Role | Wire encoding for signed claims. | Key custody, credential storage, and signing runtime. |
| Holds | Identity Grant, Session Binding Statement, Gateway Route Assertion, or Security Binding Object bytes. | Agent confirmation key, grants, credentials, and signing policy. |
| Security basis | Signature verification, protected `kid`, algorithm policy, audience, expiry, replay state, and local policy. | Protection of the Agent key and controlled signing of canonical input. |
| Session binding | Claims carry `grant_hash`, `tls_exporter_sha256`, `request_context_sha256`, and `nonce`. | Wallet signs those same values with the Agent confirmation key. |
| Replay defense | Requires expiry, unique IDs, nonces, and receiver-side replay state. | Cannot replace receiver-side replay state. |
| Policy authority | None by itself; claims are observed values until compared with local expected policy. | None by itself; wallet metadata is not expected policy. |

The unsafe pattern is:

```text
wallet says "this is Agent A" -> accept
```

The safe pattern is:

```text
wallet signs canonical session binding input
receiver verifies Manager grant, Agent binding signature, replay state, and
local expected policy
```

### Wallet-Backed Signer Shape

A wallet-backed implementation should expose a narrow signing surface. The
wallet receives canonical binding input from the Agent runtime and returns a
signed Session Binding Statement. It does not compute verifier policy and it
does not decide acceptance.

Conceptually:

```text
SignSessionBinding(input):
  required input:
    profile_version
    aud
    grant_hash
    tls_exporter_sha256
    request_context_sha256
    nonce
    iat
    exp
  optional input:
    role
    task_id_hash
    context_id_hash
    delegation_hash
    gateway_route_assertion_sha256
  output:
    signed Session Binding Statement as JWT/JWS or CWT/COSE
```

The Agent runtime is responsible for constructing the canonical input from the
accepted session and trusted task state. A wallet MAY enforce local signing
policy, such as allowed audiences, maximum lifetime, non-exportable key use, or
user/operator consent. That policy only limits what the wallet will sign. It
does not become the receiver's expected policy.

The verifier path stays unchanged for local wallets, HSM-backed wallets, TPM or
Secure Enclave keys, and remote signers. In all cases, the receiver verifies
the signed Identity Grant, signed Session Binding Statement, replay state, and
local expected policy.

## Security Binding Object

The Security Binding Object is the recommended A2A/AGTP carrier for
session-bound identity material. It is a transport envelope, not a new trust
root. The verifier still validates the signed Identity Grant and signed Session
Binding Statement according to `docs/SSOT.md`.

When the protocol can carry extension objects, the object SHOULD be carried in
a dedicated profile field. If a deployment must carry it in message metadata,
the metadata location is only a carrier. The signed content and local policy
decide acceptance.

### JSON Object

The JSON form uses these exact field names:

| JSON field | Required | Meaning |
| --- | --- | --- |
| `sbo_type` | yes | Fixed string `ai2ai.security-binding`. |
| `sbo_version` | yes | Integer profile version, currently `1`. |
| `aud` | yes | Receiver or relying-party audience. |
| `jti` | yes | Unique object ID for diagnostics and optional envelope replay checks. |
| `iat` | yes | Object issued-at time. |
| `exp` | yes | Object expiry time. |
| `mode` | yes | `direct-agent` or `gateway-routed`. |
| `identity_grant_format` | yes | `jwt`, `cwt`, or `ref`. |
| `identity_grant` | conditional | Compact JWT, base64url CWT/COSE bytes, or absent when `identity_grant_ref` is used. |
| `identity_grant_ref` | conditional | Stable reference to the exact grant bytes when the grant is not embedded. |
| `identity_grant_sha256` | yes | SHA-256 hash of the exact signed Identity Grant bytes. |
| `session_binding_format` | yes | `jwt`, `cwt`, or `ref`. |
| `session_binding` | conditional | Compact JWT, base64url CWT/COSE bytes, or absent when `session_binding_ref` is used. |
| `session_binding_ref` | conditional | Stable reference to the exact Session Binding Statement bytes when it is not embedded. |
| `session_binding_sha256` | yes | SHA-256 hash of the exact signed Session Binding Statement bytes. |
| `request_context_sha256` | yes | Hash of the canonical request context used by the Session Binding Statement. |
| `tls_exporter_sha256` | yes | Hash of the profile TLS exporter value for the accepted session. |
| `nonce` | yes | One-shot freshness value for this binding object. |
| `gateway_route_assertion_format` | gateway-routed only | `jwt`, `cwt`, or `ref`. |
| `gateway_route_assertion` | gateway-routed conditional | Signed Gateway Route Assertion, or absent when a reference is used. |
| `gateway_route_assertion_ref` | gateway-routed conditional | Stable reference to the exact Gateway Route Assertion bytes. |
| `gateway_route_assertion_sha256` | gateway-routed only | SHA-256 hash of the exact signed Gateway Route Assertion bytes. |

If a `*_ref` field is used, the referenced bytes are part of the verification
input. A verifier MUST reject a reference that cannot be resolved fail-closed
before signature, hash, replay, and policy checks complete.

### JWT Claim Map

When the Security Binding Object is encoded as a JWT/JWS envelope, the claim
names are the JSON field names above. The protected header `typ` SHOULD be
`ai2ai+sbo+jwt`, and `alg` and `kid` MUST be verified using the same key
namespace rules as the SSOT.

The envelope signature is optional unless local policy requires it. It never
replaces the required Identity Grant signature or Session Binding Statement
signature.

### CWT/COSE Claim Map

When the Security Binding Object is encoded as CWT/COSE, the text claim names
are the JSON field names above encoded in canonical CBOR. A deployment MAY
assign private numeric labels for compactness, but the mapping from numeric
label to text claim name must be fixed by that deployment profile and covered
by test vectors.

The COSE `kid` used for envelope key lookup must be protected. Unprotected
`kid` is not accepted for key selection. As with JWT, a COSE envelope signature
does not replace the signed Identity Grant or the signed Session Binding
Statement.

## Gateway-Routed Mode

This repository does not implement gateway-routed runtime mode. The section is
boundary guidance for a separate binding profile.

Gateway-routed mode needs a Gateway Route Assertion in addition to the direct
Agent profile material. Gateway session binding proves the gateway endpoint. It
does not prove the final Agent process.

A Gateway Route Assertion binds:

- gateway identity;
- final Agent identity or workload identity;
- `route_id`;
- tenant or authority partition;
- `task_id` or `context_id`;
- `policy_id`;
- expiry and replay nonce;
- gateway-to-Agent holder-of-key proof, unless local policy explicitly trusts
  the gateway as the final delegation authority.

This is where AGTP-style `relay_id`, `next_hop`, `target_agent`, `session_id`,
`task_id`, `context_id`, and `audit_hash` fit naturally. They are route facts,
not receiver policy by themselves.

## Acceptance Summary

A receiver accepts only after all of the following are true:

1. Discovery and authentication policy for the endpoint has succeeded.
2. The Identity Grant is signed by a trusted Manager or policy authority.
3. The Session Binding Statement is signed by the Agent confirmation key
   authorized by the verified grant.
4. `identity_grant_sha256` and `session_binding_sha256` match the exact signed
   bytes verified by the receiver.
5. `request_context_sha256`, `tls_exporter_sha256`, and `nonce` match the
   accepted session and replay policy.
6. Gateway-routed mode has a verified Gateway Route Assertion and required
   holder-of-key proof.
7. Signed observed values match local expected policy for service, tenant,
   Agent, task, context, capability, resource, and authorization.

Anything else is descriptive data.
