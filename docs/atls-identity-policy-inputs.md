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

The core rule is to keep expected values separate from observed values.

- Expected values come from local policy, configuration, a trusted registry, or
  a policy engine.
- Observed values come from attestation evidence, CoRIM metadata, EAT claims,
  agent manifests, request metadata, or authorization tokens.
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

An implementation can split this object across existing configuration, manager
state, agent metadata, or an external policy engine. The important part is the
source of authority, not the concrete serialization format.

## Production wiring

The production aTLS client hook is:

- `atls.ClientConfig.IdentityPolicy` for local expected values.
- `atls.ClientConfig.ObservedIdentity` for observed values extracted from a
  trusted source.

The hook runs after exported-authenticator and attestation validation, but
before the accepted aTLS connection is returned to the caller.

The expected values are owned by local policy. In practice, that means manager
configuration, operator configuration, a trusted registry, or an authorization
policy engine. Peer-provided values must not become expected values.

The observed values are extracted by the caller-supplied `ObservedIdentity`
callback. That callback should read from trusted evidence, CoRIM metadata, EAT
claims, agent manifests, request metadata, or authorization tokens. If an
identity policy is enabled without an observed-identity callback, the client
fails closed.

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
3. Extract the observed value from the trusted source for that layer.
4. Reject if the observed value is missing.
5. Compare the observed value with the expected value.
6. Reject on mismatch.
7. Continue to the next required layer.

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
expected-versus-observed comparison model described above, but it is not wired
into the aTLS verifier by default.

Callers are expected to:

- build a local `Policy` from trusted deployment or authorization inputs,
- extract observed `Values` from the appropriate CoCos layer,
- call `identitypolicy.Validate`,
- and treat validation errors as fail-closed for layers required by policy.

`identitypolicy.Validate` reports all layer and field failures found in one
pass. Callers can inspect `ValidationErrors` for per-field diagnostics, while
still using `errors.Is` with the package sentinel errors.

## Suggested next step

Decide which L2b through L5 inputs each CoCos deployment expects to enforce.
Then wire `identitypolicy.Validate` at the layer that owns those inputs, such as
manager configuration, agent metadata, computation state, or an authorization
policy engine.
