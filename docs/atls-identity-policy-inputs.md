# aTLS Identity Policy Inputs

This note tracks identity inputs that are outside the basic TLS channel-binding
mechanism. It is a design note, not a production bug claim.

The current aTLS implementation can be reviewed in layers. The lower layers are
transport and attestation binding checks. The upper layers are deployment and
agent policy checks.

- L0: the accepted peer is on the expected live TLS channel.
- L1: the attested platform or VM measurement is appraised.
- L2: attestation or authenticator material is bound to the accepted TLS
  session.
- L3: the attested platform is checked against the intended service, tenant,
  deployment, or environment.
- L4: the accepted platform is checked against the intended workload, process,
  or agent.
- L5: the accepted request or response is checked against the intended task,
  thread, context, or delegation.
- L6: the accepted action is checked against the intended authorization or
  capability policy.

L0 through L2 can be tested directly with transport, attestation, and
implementation regressions. L3 through L6 need explicit policy inputs before the
verifier or application layer can
enforce them consistently.

This L0-L6 naming is used by both this note and the Go identity-policy API.

| Layer | Verification target | Main failure class |
| --- | --- | --- |
| L0 | Live TLS channel | MITM or session confusion |
| L1 | Attested platform validity | Fake, malformed, or untrusted platform evidence |
| L2 | Attestation-to-channel binding | Relay, replay, or borrowed evidence |
| L3 | Intended service, tenant, deployment, or environment | Diversion |
| L4 | Intended workload, process, or agent | Same-machine wrong-agent |
| L5 | Task, thread, context, or delegation binding | Cross-task or cross-thread confusion |
| L6 | Authorization or capability binding | Confused deputy or privilege escalation |

OIDC and OAuth are useful reference patterns for these upper layers. They are
not required by this note. The important idea is that the verifier should compare
peer claims against locally expected values, rather than treating peer-supplied
values as the policy.

## Scope

This note records the policy inputs needed before L3 through L6 can be
enforced consistently. The aTLS client transport exposes an optional
`atls.ClientConfig.IdentityPolicy` hook for callers that already have a trusted
source for the observed identity values.

Out of scope for this note:

- selecting a specific identity provider,
- standardizing a concrete wire-token format,
- changing the attestation evidence format,
- changing the aTLS wire protocol,
- and proving an end-to-end authorization model.

## Relationship to AGTP

AGTP can be treated as the application-profile layer that runs after aTLS has
established the lower-layer channel and attestation facts. In this split, aTLS
keeps responsibility for L0 through L2:

- L0: the live TLS channel is authenticated.
- L1: the attested platform or VM evidence is appraised.
- L2: the authenticator or attestation material is bound to the accepted TLS
  session.

AGTP can then carry or reference the upper-layer identity and policy material
needed for L3 through L6:

- L3: intended service, tenant, deployment, or environment.
- L4: intended workload, process, or agent.
- L5: intended task, thread, context, or delegation.
- L6: authorization or capability policy.

This keeps relay defense and diversion defense separate. Relay defense remains
an aTLS/session-binding question at L2. Diversion and wrong-agent prevention
need AGTP or another application profile to compare session-bound identity
claims with local expected policy at L3 and L4. Task and capability checks then
continue at L5 and L6.

AGTP should not make peer-provided metadata authoritative. Its role is to carry
authenticated policy inputs, such as an Identity Grant, and bind them to the
accepted aTLS session through a Session Binding Statement. The verifier still
compares those observed values against local expected values before treating the
peer as the intended deployment, agent, task, or authorized actor.

The initial implementation profile is:

```text
AGTP Identity Grant + aTLS + OAuth/OIDC-style semantics + JWT/JWS encoding
```

In this profile, OAuth and OIDC provide claim semantics and review vocabulary,
while JWT/JWS provides the concrete signed-token encoding. This does not make
AGTP a new OAuth or OIDC profile by itself. It only gives the aTLS relying party
a compact way to authenticate L3 through L6 identity and authorization inputs
before passing them to `identitypolicy`.

The JWT/JWS profile is intentionally fail closed. The verifier uses locally
configured issuer, audience, signing-method, and key-lookup policy. Tokens must
carry the AGTP token type, AGTP profile version, expiration time, issued-at
time, and JWT ID. The signing-method allow-list must not include `none`.
Identity values carried in an Agent-provided token are not authoritative unless
the token verifies under a locally trusted Manager or policy-authority key.

This profile keeps three key roles separate:

- TLS endpoint key: proves possession for the accepted TLS or exported
  authenticator endpoint.
- Agent binding key: signs the Session Binding Statement that binds a verified
  grant to the accepted aTLS session.
- Manager or policy-authority key: signs Identity Grants that authorize the
  intended deployment, agent, task, or capability values.

These keys may be related by deployment policy, but they must not be silently
treated as the same key. In particular, the Manager key is a token-signing or
policy-authority key, not a TLS endpoint key.

CWT/COSE can be added later as a compact binary encoding profile. The security
rules stay the same: the grant issuer must be trusted locally, the confirmation
key must be named by the verified grant, and the session-binding statement must
bind that exact grant to the accepted aTLS session.

### Key rotation and revocation

The JWT/JWS adapter verifies token signatures against caller-provided key
lookup policy. It does not define how Manager keys are rotated, how old keys are
retired, or how grants are revoked before `exp`.

Deployments that use this profile should define:

- a trusted issuer namespace for Manager or policy-authority keys,
- key identifiers and key-version rules,
- overlap windows for key rotation,
- a revocation source for grants, Manager keys, or Agent binding keys when
  early invalidation is required,
- maximum grant and session-binding lifetimes,
- and replay-cache retention that is at least as long as the accepted
  session-binding lifetime.

Until those deployment rules exist, short grant lifetimes and fail-closed local
key lookup are the conservative default. A token signed with an unknown,
retired, or locally disabled key should be rejected.

Revocation has three separate targets:

- grant revocation rejects a specific Identity Grant by `jti`;
- Manager-key revocation rejects grants signed by a disabled issuer key or
  `kid`;
- Agent binding-key revocation rejects Session Binding Statements signed by a
  compromised or retired confirmation key.

Unknown, revoked, or stale keys fail closed. A deployment that relies on JWKS or
another remote key set should define freshness, cache lifetime, and failure
handling for that key source.

### Initial production profile

The recommended initial production profile is intentionally small:

- Manager keys are configured locally by `kid`, algorithm, and public key.
- Identity Grants are short-lived.
- Optional local denylists cover revoked grant `jti` values and disabled
  Manager-key `kid` values.
- Unknown or disabled `kid` values fail closed.
- `MemoryReplayCache` is suitable only for tests and single-process deployments.
- Multi-instance deployments should use a shared replay cache, such as
  Redis-compatible `SET NX EX` semantics keyed by the session-binding nonce or
  binding statement ID.
- Production identity policy has two modes: disabled or required. Required mode
  fails closed when the policy, Identity Grant, Session Binding Statement,
  trusted Manager key, expected binding, or replay check is missing or invalid.

JWKS, DNS-AID, registry-based discovery, and centralized revocation APIs can be
added later. They should not replace the local trust decision unless freshness,
cache lifetime, revocation behavior, and fail-closed handling are specified.

In implementation terms, AGTP can be introduced as a post-aTLS handshake before
changing the aTLS wire protocol. The AGTP step would authenticate the grant,
verify the session binding statement against the accepted aTLS session, enforce
any replay policy, and then call the same `identitypolicy` validator used by the
current Go API.

## OIDC and OAuth-style mapping

OIDC and OAuth provide a useful vocabulary for local expected values:

| Layer | Policy question | OIDC / OAuth-style analogue |
| --- | --- | --- |
| L3 | Is this the intended service, tenant, deployment, or environment? | issuer, audience, tenant, hosted domain, deployment claim, environment claim |
| L4 | Is this the intended workload, process, or agent? | subject, client ID, workload identity, actor claim, confirmation key |
| L5 | Is this the intended task, thread, context, or delegation? | nonce, state, transaction ID, request object, delegation token |
| L6 | Is this action authorized for this peer and context? | scope, resource indicator, authorization details, policy decision, consent |

These names are analogies, not normative requirements. A CoCos deployment could
source the same expected values from configuration, a registry, CoRIM metadata,
an EAT claim, an agent manifest, or an application policy engine.

## Policy shape

The core rule is to keep expected values separate from observed values, and to
bind observed values to the accepted aTLS session.

- Expected values come from local policy, configuration, a trusted registry, or
  a policy engine.
- Observed values come from a session-bound identity assertion extracted from
  attestation evidence, CoRIM metadata, EAT claims, agent manifests,
  authenticated or locally derived request metadata, or authorization tokens.
- Verification compares observed values against expected values.
- Observed values must not become expected values without a trusted local policy
  decision.

A minimal policy object can be shaped as follows:

```yaml
identity_policy:
  require:
    l3: false
    l4: false
    l5: false
    l6: false

  expected:
    service: ""
    tenant: ""
    deployment: ""
    environment: ""
    workload: ""
    agent: ""
    agent_public_key: ""
    computation_id: ""
    task_id: ""
    thread_id: ""
    delegation_id: ""
    scopes: []
    resources: []
    authorization_details: []
```

After external identity material has been authenticated, the verified internal
`identitypolicy.Assertion` can be shaped as follows:

```yaml
identity_assertion:
  issuer: "manager-or-policy-engine"

  values:
    service: "payment-agent"
    tenant: "tenant-a"
    deployment: "prod"
    environment: "asia-northeast1"
    workload: "settlement-worker"
    agent: "agent-a"
    agent_public_key: "sha256:..."
    computation_id: "cmp-..."
    task_id: "task-..."
    thread_id: "thread-..."
    delegation_id: "delegation-..."
    scopes:
      - "orders:read"
    resources:
      - "orders"
    authorization_details:
      - "settlement"

  binding:
    leaf_public_key_sha256: "..."
    request_context_sha256: "..."
    attestation_binder_sha256: "..."
    nonce: "..."
    issued_at: "..."
    expires_at: "..."
```

This assertion is not a wire format. It is a local representation used after the
caller has authenticated the external identity material. `Assertion.Issuer` is
informational to `identitypolicy.ValidateAssertion`; it is trusted only if the
`ObservedIdentity` implementation has already verified the corresponding grant
issuer and trust anchor. The binding fields are what make the assertion a relay
defense rather than a plain metadata check.

An implementation can split this object across existing configuration, manager
state, agent metadata, or an external policy engine. The important part is the
source of authority, not the concrete serialization format.

## Issuer model

`identitypolicy.Assertion` is not a wire token. It is a verified internal
representation returned by `atls.ClientConfig.ObservedIdentity`. Any wire token,
manifest, EAT claim, CoRIM metadata, authorization token, or gateway statement
must be authenticated before the callback returns an assertion.

A production deployment should separate authority from session possession:

- Identity Grant: signed or otherwise authenticated by the Manager or another
  configured policy authority.
- Session Binding Statement: signed by the agent confirmation key named in the
  verified Identity Grant. The accepted endpoint key may be used only when the
  verified grant or local attestation policy explicitly binds that endpoint key
  to the same agent identity.

The Agent is not the authority for service, tenant, deployment, task, scope, or
resource values. An Agent-signed session binding is a holder-of-key proof, not
an authority statement.

### Identity Grant

The Identity Grant authorizes the intended upper-layer subject. The initial
wire profile uses JWT/JWS and OAuth/OIDC-style claim names where they fit. Other
encodings, such as CWT/COSE or a signed manifest, can be added later if they
preserve the same authority and session-binding rules.

An Identity Grant should include the deployment-specific equivalent of:

- AGTP token type (`agtp_type=agtp.identity-grant`),
- AGTP profile version (`agtp_version=1`),
- issuer (`iss`),
- subject (`sub`),
- audience (`aud`),
- unique grant ID (`jti`),
- service, tenant, deployment, or environment,
- workload or agent identity,
- agent public key or confirmation key (`cnf.kid` in the initial JWT/JWS
  profile),
- computation ID, task ID, thread ID, or delegation ID when known,
- scopes, resources, or authorization details when required,
- issuer key ID or key version when needed for key rotation,
- issued-at and expiration time (`iat`, `exp`),
- and a unique grant ID.

### Session Binding Statement

The Session Binding Statement does not authorize identity or capability values.
It only proves that the holder of the confirmation key named in the verified
grant bound that grant to the accepted aTLS session. A generic accepted endpoint
key is not sufficient unless the verified grant or local attestation policy
explicitly binds that key to the same agent identity.

A Session Binding Statement should include:

- AGTP token type (`agtp_type=agtp.session-binding`),
- AGTP profile version (`agtp_version=1`),
- unique binding statement ID (`jti`),
- `grant_hash`,
- `leaf_public_key_sha256`,
- `request_context_sha256`,
- `attestation_binder_sha256` when attestation is present,
- `aud` or relying-service ID,
- statement type, protocol name, and version,
- nonce or unique binding ID,
- `iat` or issued-at time,
- and expiration time.

The grant hash should be computed over an unambiguous byte string, for example:

```text
SHA-256("agtp.identity-grant.jwt.v1" || NUL || exact-signed-grant-bytes)
```

If a JSON-based format is used, the deployment must avoid ambiguous
canonicalization. Hashing the exact signed bytes, or using canonical CBOR/COSE,
is safer than hashing a re-serialized JSON object.

The reusable JWT/JWS adapter in `pkg/agtp` follows this rule. It verifies the
signed grant, computes the domain-separated hash over the exact compact JWT
bytes, and converts the result into `identitypolicy.VerifiedGrant`.

### Verification order

The overall verifier should perform the checks below. In the production aTLS
client wiring, the `ObservedIdentity` callback performs external authentication
and constructs the verified assertion, while
`identitypolicy.ValidateAssertion` compares the assertion with the accepted aTLS
session binding and local expected policy.

1. Verify the Identity Grant under a trusted Manager or policy-authority key.
2. Check grant issuer, audience, expiration, grant ID, and required scope or
   resource fields.
3. Verify that the Session Binding Statement signature key matches the
   grant confirmation key, or another endpoint key explicitly authorized by the
   verified grant or local attestation policy.
4. Verify that the statement grant hash matches the verified Identity Grant.
5. Verify that the statement audience matches the relying service or client.
6. Reject arbitrary accepted endpoint keys that are not explicitly bound by the
   verified grant or local attestation policy to the same agent identity, even when the underlying aTLS session is otherwise valid.
7. Compare the statement binding fields with the accepted aTLS session.
8. Enforce replay policy for grant IDs, binding IDs, or nonces when one-shot use
   is required.
9. Construct `identitypolicy.Assertion` only from the verified grant and binding
   statement.
10. Call `identitypolicy.ValidateAssertion` to compare the verified assertion
   with local expected policy.

`identitypolicy.ValidateAssertion` intentionally remains a comparator and
binding freshness checker. It does not parse or verify wire tokens, signatures,
grant formats, key rotation, revocation, or replay caches. Those checks belong
to the component that implements `ObservedIdentity`.

### Gateway mode

If the Agent terminates the accepted aTLS session directly, the Agent can sign
the Session Binding Statement over the accepted session binding values only when
the verified Identity Grant names that Agent key, or explicitly binds the
accepted endpoint key to the same agent identity.

If an ingress proxy or gateway terminates aTLS, the trust model is different:
the gateway is the live TLS endpoint. In that mode, policy must explicitly trust
the gateway and bind the gateway-to-agent route. The deployment can model this
with gateway ID, gateway public key, allowed route, and agent route fields in
the Identity Grant or in a separate gateway routing assertion. Without that
extra routing assertion, a gateway-terminated session binding does not by itself
prove that the intended Agent process handled the request.

A gateway routing assertion must not be treated as an Agent authority statement.
It only authenticates the gateway's routing decision. The relying party still
needs an Identity Grant for the intended Agent and, when required, an Agent-side
holder-of-key proof for the gateway-to-agent hop.

## Production wiring

The production aTLS client hook is:

- `atls.ClientConfig.IdentityPolicy` for local expected values.
- `atls.ClientConfig.ObservedIdentity` for a session-bound observed identity
  assertion extracted from a trusted source.

The hook runs after exported-authenticator and attestation validation, but
before the accepted aTLS connection is returned to the caller.

The expected values are owned by local policy. In practice, that means manager
configuration, operator configuration, a trusted registry, or an authorization
policy engine. Peer-provided values must not become expected values.

The observed assertion is extracted by the caller-supplied `ObservedIdentity`
callback. That callback should read from trusted evidence, CoRIM metadata, EAT
claims, agent manifests, authenticated or locally derived request metadata, or
authorization tokens. If an identity policy is enabled without an
observed-identity callback, the client fails closed.

The aTLS client computes the expected session binding from the accepted
exported authenticator: the leaf public key, the certificate request context,
and the attestation binder when attestation is present. The observed assertion
must carry matching binding values and a non-expired `expires_at` value before
its identity fields are compared with local policy.

This gives the profile two distinct defenses:

- relay defense: the observed identity assertion must be tied to this accepted
  aTLS session at L2, not borrowed from another endpoint or connection.
- diversion defense: the session-bound observed identity must match locally
  expected deployment identity at L3. Workload, task, and authorization checks
  continue at L4 through L6.

## L3: intended service, tenant, or deployment

The verifier needs a local source of expected identity values. Examples include:

- service identity,
- tenant identity,
- deployment or environment identity,
- region or location, if relevant,
- CoRIM or evidence fields that represent these values,
- and the local policy source for the expected values.

The key question is whether a valid platform measurement is also tied to the
intended service or deployment subject.

## L4: intended workload, process, or agent

Machine-level attestation may not be enough when several workloads or agents run
on the same platform. The verifier or application layer may need expected values
such as:

- workload ID,
- agent ID,
- process or binary hash,
- config or policy hash,
- agent public key,
- and routing target or ingress identity.

The key question is whether the accepted peer is the intended workload or agent,
not only a workload on a valid attested machine.

## L5: intended task, thread, context, or delegation

An accepted peer can still be used in the wrong application context. The
application layer may need expected values such as:

- computation ID,
- task ID,
- thread or conversation ID,
- request context,
- delegation token,
- callback or ingress binding,
- and locally tracked one-shot state.

The key question is whether the accepted response is tied to the task or
delegation that the relying party intended.

## L6: authorization or capability policy

Identity alone does not decide whether an action is allowed. The policy layer
may need expected values such as:

- OAuth scope or authorization detail,
- capability token,
- resource indicator,
- user consent record,
- policy-engine decision,
- and tool or data-access policy.

The key question is whether the accepted peer is authorized for the requested
action in the current context.

## Possible CoCos input sources

The table below lists candidate input sources. It is intentionally descriptive;
it does not claim that all inputs already exist or are enforced today.

| Layer | Candidate local expected value | Possible CoCos source |
| --- | --- | --- |
| L3 | Expected service, tenant, deployment, or environment | manager configuration, deployment registry, CoRIM metadata, EAT claim, operator policy |
| L4 | Expected workload, process, or agent | agent manifest, workload ID, binary or config hash, agent public key, ingress routing policy |
| L5 | Expected task, thread, context, or delegation | computation ID, request context, session state, delegation token, callback binding |
| L6 | Expected authorization or capability | OAuth/OIDC-style policy, capability token, policy engine, user consent, tool policy |

## Validation algorithm

For each layer that is required by policy:

1. Load the local expected value for that layer.
2. Reject if the expected value is missing or ambiguous.
3. Extract the observed session-bound identity assertion from the trusted source.
4. Reject if the assertion is not bound to the accepted aTLS session.
5. Reject if the assertion is expired or missing freshness metadata.
6. Extract the observed value from the assertion for that layer.
7. Reject if the observed value is missing.
8. Compare the observed value with the expected value.
9. Reject on mismatch.
10. Continue to the next required layer.

For set-like values such as scopes or resources, the observed set must satisfy
the local policy. A peer-provided scope list is not enough by itself.

## Fail-closed principle

For L3 through L6, the safe default should be fail closed when an expected local
value is required but unavailable, ambiguous, or only peer supplied.

Concrete policy rules should follow this shape:

- The expected value comes from local configuration, a trusted registry, an
  attestation policy, or a policy engine.
- The received claim is compared against that local expected value.
- Missing expected values do not silently relax the check.
- Peer-provided values are never promoted into expected values without a trusted
  policy decision.
- A mismatch is a hard failure for flows that require that layer.

## Error handling

Validation failures should preserve the layer, field, and error class. Callers
can then distinguish local policy configuration errors from missing peer claims
or mismatched values.

For example:

- missing local expected value: configuration or policy setup problem
- missing observed value: peer evidence, metadata, or token did not carry the
  required claim
- mismatch: peer supplied a claim, but it did not match local policy

Aggregated validation errors should remain inspectable by layer and field so
callers can fail closed while still reporting actionable diagnostics.

The validator also rejects unsafe identity-policy values, including invalid
UTF-8, control characters such as CRLF, and HTML delimiter characters. It also
limits individual values to 1024 bytes and set-like fields to 128 values. This
protects log, header, and diagnostic paths from accepting values that could be
reused for injection or resource-exhaustion attacks. Validation errors
intentionally report only layer, field, and error class; they do not echo raw
peer values. Any HTTP or HTML presentation layer must still use normal output
escaping and CSRF protections at that layer.

## Minimal implementation path

A small implementation can be staged without changing the aTLS wire protocol:

1. Define a local policy input structure for L3 through L6 expected values.
2. Define extraction points for observed values.
3. Add fail-closed validators for exact-match string fields.
4. Add set-containment validation for scopes, resources, or authorization
   details.
5. Wire the validators at the application or manager layer before treating an
   accepted aTLS peer as the intended deployment, agent, task, or authorized
   actor.

The aTLS verifier can remain focused on L0 through L2. L3 through L6 enforcement
can live at the layer that has access to deployment policy, agent metadata,
computation state, and authorization decisions.

## Implementation status

The reusable validator lives in `pkg/atls/identitypolicy`. It implements the
expected-versus-observed comparison model and session-bound assertion validation
described above. The aTLS client transport calls it when
`atls.ClientConfig.IdentityPolicy` is enabled.

The same package also provides a helper for the post-authentication step:
`identitypolicy.NewAssertionFromSessionBinding` builds an internal `Assertion`
from an already-authenticated Identity Grant and an already-verified Session
Binding Statement. It does not parse wire tokens or verify signatures; it only
checks that the statement is tied to the grant, audience, allowed confirmation
key, and minimum session-binding fields before the assertion is compared with
the accepted aTLS session. `identitypolicy.SessionBindingOptions` can also
attach a replay cache for one-shot binding nonces.

The aTLS client config supports both integration styles. Callers can provide a
custom `ObservedIdentity` callback, or they can pass a verified Identity Grant,
a verified Session Binding Statement, and an optional replay cache directly on
`atls.ClientConfig`. In both cases, the transport validates the resulting
assertion against the accepted aTLS session before returning the connection. For
the direct grant/statement path, replay-cache marking happens only after the
session-binding and local policy comparison succeed.

`pkg/agtp` provides the first concrete wire-token adapter for that direct path.
It verifies AGTP Identity Grants and Session Binding Statements encoded as
JWT/JWS, using locally configured issuer, audience, signing methods, and key
lookup policy. The adapter does not choose the trusted Manager keys, rotate
keys, perform revocation, or define deployment policy. Those remain caller
responsibilities.

The initial JWT/JWS adapter treats the grant `cnf.kid` value as the authorized
session-binding signer key. The Session Binding Statement signer is taken from
the protected JWS `kid` header and is later checked by `identitypolicy` against
the verified grant. Thumbprint-based confirmation, such as `cnf.jkt`, can be
added later once the deployment defines how key thumbprints map to local
verification keys.

The adapter also rejects tokens with the wrong AGTP token type, unsupported
profile version, missing JWT ID, missing grant confirmation key, missing
session-binding grant hash, missing required session-binding fields, or an
unsafe signing-method allow-list. It does not perform key rotation,
revocation, or replay-cache storage; those remain deployment responsibilities.

For callers that want one fail-closed acceptance gate, `pkg/agtp` also exposes
`VerifySessionIdentityJWT`. That helper verifies the Manager-signed Identity
Grant, verifies the Session Binding Statement, checks that the binding signer is
authorized by the verified grant, compares the resulting assertion with local
expected `identitypolicy.Policy` values and the accepted aTLS session binding,
and only then marks the binding nonce in the replay cache. This prevents a peer
from making OAuth/OIDC-style claims authoritative by self-signing or simply
presenting them as metadata.

Callers are expected to:

- build a local `Policy` from trusted deployment or authorization inputs,
- extract or provide a verified observed identity assertion from the appropriate
  CoCos layer,
- call `identitypolicy.ValidateAssertion`, provide the assertion through
  `atls.ClientConfig.ObservedIdentity`, or configure the verified grant and
  session-binding fields on `atls.ClientConfig`,
- and treat validation errors as fail-closed for layers required by policy.

`identitypolicy.Validate` reports all layer and field failures found in one
pass. Callers can inspect `ValidationErrors` for per-field diagnostics, while
still using `errors.Is` with the package sentinel errors.

## Suggested next step

Decide which Manager or policy-authority keys are trusted for Identity Grants,
which confirmation keys may sign Session Binding Statements, and which replay
cache or nonce policy is required for task-level one-shot use. The source can be
manager configuration, agent metadata, computation state, or an authorization
policy engine, but it must not be raw peer-controlled metadata.
