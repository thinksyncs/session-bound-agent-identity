# aTLS Identity Policy Inputs

This note tracks identity inputs that are outside the basic TLS channel-binding
mechanism. It is a design note, not a production bug claim.

The current aTLS implementation can be reviewed in layers. The lower layers are
transport and attestation binding checks. The upper layers are deployment and
agent policy checks.

- L1: attestation or authenticator material is bound to the accepted TLS
  session.
- L2a: the attested platform or VM measurement is appraised.
- L2b: the attested platform is checked against the intended service, tenant,
  deployment, or environment.
- L3: the accepted platform is checked against the intended workload, process,
  or agent.
- L4: the accepted request or response is checked against the intended task,
  thread, context, or delegation.
- L5: the accepted action is checked against the intended authorization or
  capability policy.

L1 and L2a can be tested directly with implementation regressions. L2b through
L5 need explicit policy inputs before the verifier or application layer can
enforce them consistently.

OIDC and OAuth are useful reference patterns for these upper layers. They are
not required by this note. The important idea is that the verifier should compare
peer claims against locally expected values, rather than treating peer-supplied
values as the policy.

## Scope

This note records the policy inputs needed before L2b through L5 can be
enforced consistently. The aTLS client transport exposes an optional
`atls.ClientConfig.IdentityPolicy` hook for callers that already have a trusted
source for the observed identity values.

Out of scope for this note:

- selecting a specific identity provider,
- defining a new token format,
- changing the attestation evidence format,
- changing the aTLS wire protocol,
- and proving an end-to-end authorization model.

## OIDC and OAuth-style mapping

OIDC and OAuth provide a useful vocabulary for local expected values:

| Layer | Policy question | OIDC / OAuth-style analogue |
| --- | --- | --- |
| L2b | Is this the intended service, tenant, deployment, or environment? | issuer, audience, tenant, hosted domain, deployment claim, environment claim |
| L3 | Is this the intended workload, process, or agent? | subject, client ID, workload identity, actor claim, confirmation key |
| L4 | Is this the intended task, thread, context, or delegation? | nonce, state, transaction ID, request object, delegation token |
| L5 | Is this action authorized for this peer and context? | scope, resource indicator, authorization details, policy decision, consent |

These names are analogies, not normative requirements. A CoCos deployment could
source the same expected values from configuration, a registry, CoRIM metadata,
an EAT claim, an agent manifest, or an application policy engine.

## Policy shape

The core rule is to keep expected values separate from observed values, and to
bind observed values to the accepted aTLS session.

- Expected values come from local policy, configuration, a trusted registry, or
  a policy engine.
- Observed values come from a session-bound identity assertion extracted from
  attestation evidence, CoRIM metadata, EAT claims, agent manifests, request
  metadata, or authorization tokens.
- Verification compares observed values against expected values.
- Observed values must not become expected values without a trusted local policy
  decision.

A minimal policy object can be shaped as follows:

```yaml
identity_policy:
  require:
    l2b: false
    l3: false
    l4: false
    l5: false

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

A session-bound identity assertion can be shaped as follows:

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

The assertion format is local to this package. The binding fields are what make
the assertion a relay defense rather than a plain metadata check.

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
- Session Binding Statement: signed by the accepted endpoint key, or by an agent
  confirmation key named in the verified Identity Grant.

The Agent is not the authority for service, tenant, deployment, task, scope, or
resource values. An Agent-signed session binding is a holder-of-key proof, not
an authority statement.

### Identity Grant

The Identity Grant authorizes the intended upper-layer subject. It can use a
JWT/JWS, CWT/COSE, signed manifest, or another deployment-specific format. The
format is outside this package; the required property is that the verifier can
authenticate the issuer and extract trusted identity values.

An Identity Grant should include the deployment-specific equivalent of:

- issuer,
- subject,
- audience,
- service, tenant, deployment, or environment,
- workload or agent identity,
- agent public key or confirmation key,
- computation ID, task ID, thread ID, or delegation ID when known,
- scopes, resources, or authorization details when required,
- issued-at and expiration time,
- and a unique grant ID.

### Session Binding Statement

The Session Binding Statement does not authorize identity or capability values.
It only proves that the holder of the grant confirmation key bound the verified
grant to the accepted aTLS session.

A Session Binding Statement should include:

- grant hash,
- leaf public-key hash,
- certificate request context hash,
- attestation-binder hash when attestation is present,
- audience or relying-service ID,
- protocol name and version,
- nonce or unique binding ID,
- issued-at time,
- and expiration time.

The grant hash should be computed over an unambiguous byte string, for example:

```text
SHA-256("cocos.identity-grant.v1" || exact-signed-grant-bytes)
```

If a JSON-based format is used, the deployment must avoid ambiguous
canonicalization. Hashing the exact signed bytes, or using canonical CBOR/COSE,
is safer than hashing a re-serialized JSON object.

### Verification order

The `ObservedIdentity` callback should perform the external authentication work
in this order:

1. Verify the Identity Grant under a trusted Manager or policy-authority key.
2. Check grant issuer, audience, expiration, grant ID, and required scope or
   resource fields.
3. Verify that the Session Binding Statement signature key matches the accepted endpoint key, or the grant
   confirmation key.
4. Verify that the statement grant hash matches the verified Identity Grant.
5. Verify that the statement audience matches the relying service or client.
6. Compare the statement binding fields with the accepted aTLS session.
7. Enforce replay policy for grant IDs, binding IDs, or nonces when one-shot use
   is required.
8. Construct `identitypolicy.Assertion` only from the verified grant and binding
   statement.
9. Call `identitypolicy.ValidateAssertion` to compare the verified assertion
   with local expected policy.

`identitypolicy.ValidateAssertion` intentionally remains a comparator and
binding freshness checker. It does not parse or verify wire tokens, signatures,
grant formats, key rotation, revocation, or replay caches. Those checks belong
to the component that implements `ObservedIdentity`.

### Gateway mode

If the Agent terminates the accepted aTLS session directly, the Agent can sign
the Session Binding Statement over the accepted session binding values.

If an ingress proxy or gateway terminates aTLS, the trust model is different:
the gateway is the live TLS endpoint. In that mode, policy must explicitly trust
the gateway and bind the gateway-to-agent route. The deployment can model this
with gateway ID, gateway public key, allowed route, and agent route fields in
the Identity Grant or in a separate gateway routing assertion. Without that
extra routing assertion, a gateway-terminated session binding does not by itself
prove that the intended Agent process handled the request.

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
claims, agent manifests, request metadata, or authorization tokens. If an
identity policy is enabled without an observed-identity callback, the client
fails closed.

The aTLS client computes the expected session binding from the accepted
exported authenticator: the leaf public key, the certificate request context,
and the attestation binder when attestation is present. The observed assertion
must carry matching binding values and a non-expired `expires_at` value before
its identity fields are compared with local policy.

This gives the profile two distinct defenses:

- relay defense: the observed identity assertion must be tied to this accepted
  aTLS session, not borrowed from another endpoint or connection.
- diversion defense: the session-bound observed identity must match locally
  expected service, tenant, deployment, workload, task, and authorization
  policy.

## L2b: intended service, tenant, or deployment

The verifier needs a local source of expected identity values. Examples include:

- service identity,
- tenant identity,
- deployment or environment identity,
- region or location, if relevant,
- CoRIM or evidence fields that represent these values,
- and the local policy source for the expected values.

The key question is whether a valid platform measurement is also tied to the
intended service or deployment subject.

## L3: intended workload, process, or agent

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

## L4: intended task, thread, context, or delegation

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

## L5: authorization or capability policy

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
| L2b | Expected service, tenant, deployment, or environment | manager configuration, deployment registry, CoRIM metadata, EAT claim, operator policy |
| L3 | Expected workload, process, or agent | agent manifest, workload ID, binary or config hash, agent public key, ingress routing policy |
| L4 | Expected task, thread, context, or delegation | computation ID, request context, session state, delegation token, callback binding |
| L5 | Expected authorization or capability | OAuth/OIDC-style policy, capability token, policy engine, user consent, tool policy |

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

For L2b through L5, the safe default should be fail closed when an expected local
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

1. Define a local policy input structure for L2b through L5 expected values.
2. Define extraction points for observed values.
3. Add fail-closed validators for exact-match string fields.
4. Add set-containment validation for scopes, resources, or authorization
   details.
5. Wire the validators at the application or manager layer before treating an
   accepted aTLS peer as the intended deployment, agent, task, or authorized
   actor.

The aTLS verifier can remain focused on L1 and L2a. L2b through L5 enforcement
can live at the layer that has access to deployment policy, agent metadata,
computation state, and authorization decisions.

## Implementation status

The reusable validator lives in `pkg/atls/identitypolicy`. It implements the
expected-versus-observed comparison model and session-bound assertion validation
described above. The aTLS client transport calls it when
`atls.ClientConfig.IdentityPolicy` is enabled.

Callers are expected to:

- build a local `Policy` from trusted deployment or authorization inputs,
- extract an observed `Assertion` from the appropriate CoCos layer,
- call `identitypolicy.ValidateAssertion`, or provide the assertion through
  `atls.ClientConfig.ObservedIdentity`,
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
