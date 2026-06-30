# Agents Secure Binding

## Status

Draft status: repository security-hardening draft.

Current source of truth: `docs/SSOT.md`, Draft v0.5-review2.

Standards status: this is not an IETF consensus document and does not define a
new TLS handshake, TLS extension, attestation evidence format, identity
provider, or application protocol.

Evaluation boundary: the v0.4 evaluation is useful implementation evidence for
the checked fail-closed verifier behavior. It is not a formal proof and should
not be cited as validation of TLS, attestation formats, or all deployments. The
latest recorded remote implementation checkpoint is commit
`4c3e4fc57cca52a6423394fe2292d620f957c962`: GitHub Actions `CI` run
`28181903677` and `Security Red Team` run `28181903553` both completed
successfully on 2026-06-25 UTC.

## What This Is / Is Not

Agents Secure Binding implements one experimental Direct-Agent binding profile
based on the core acceptance rules. It is not the draft itself, and it does not
claim to implement every binding profile.

A verifier accepts an Agent only when a verified authority grant,
holder-of-key proof, accepted TLS or exported-authenticator session, freshness
and replay state, any required attestation result, and verifier-local policy
all describe the same intended interaction.

This repository contains profile text, implementation helpers, tests, vectors,
and derived notes for that acceptance rule.

The Direct-Agent runtime implementation is centered on `pkg/clients`,
`pkg/atls`, and `pkg/atls/identitypolicy`. The `pkg/atls` name is a legacy
implementation package name from the inherited codebase; it does not mean this
repository defines attested TLS or a TLS extension. The legacy-named `pkg/agtp`
package is retained as an experimental reference-adapter surface for JWT/JWS,
CWT/COSE, and gateway-route policy experiments; it is not the core verifier
dependency.

This profile is not:

- a TLS extension;
- an attestation evidence format;
- an identity provider;
- a holder-side presentation format;
- a registry, control plane, gateway, or application protocol;
- a replacement for AGTP, A2A, Cocos, TLS, OAuth/OIDC, or remote attestation
  standards;
- new cryptography.

Application protocols can carry the profile material, but they do not by
themselves supply the verifier-side acceptance rule.

Wallets are optional presentation or signing components, not trust roots or
sources of expected policy. Gateway-routed mode is out of scope for this
Direct-Agent implementation surface.

Review boundary:

- TLS 1.3, certificate-path validation, exporter computation, and key-schedule
  security are delegated to the deployment TLS stack. This repository consumes
  an already accepted TLS connection.
- Attestation evidence formats and appraisal policy are delegated to the
  concrete binding profile or deployment appraisal profile. This repository
  checks the accepted binder value when that profile supplies one.
- The red-team evidence supports the tested fail-closed verifier behavior. It
  is not a formal proof and does not validate every deployment topology.
- Legacy package names such as `pkg/atls` and `pkg/agtp` are implementation
  compatibility names. They do not define the protocol trust model.

## Start Here

- `docs/SSOT.md`: normative repository source for profile behavior, dimensions,
  verification order, and compatibility notes.
- `docs/threat-model.md`: explanatory relay, replay, diversion, wrong-Agent,
  gateway-route, downgrade, and privacy threat model.
- `docs/live-red-team-report.md`: current live-style red-team evidence and
  evaluation boundaries.
- `PUBLICATION_TODO.md`: publication blockers, inherited runtime risk
  classification, module identity choice, and CI/red-team checkpoint status.

## Profile Overview

The core invariant is simple: a verifier must not return a
profile-authenticated Agent identity unless the verified grant, proof, accepted
session, freshness state, replay state, any required attestation result, and
local policy identify the same intended interaction.

This profile uses D0 through D6 as acceptance dimensions. These labels are for
policy separation and diagnostics. They are not OSI layers, wire-format layers,
or a trust hierarchy.

| Dimension | Verification target | Main failure class |
| --- | --- | --- |
| D0 | Live TLS or exported-authenticator session | MITM or session confusion |
| D1 | Attested platform validity, when required | Fake, malformed, stale, or untrusted evidence |
| D2 | Attestation or authenticator-to-session binding | Relay, replay, or borrowed evidence |
| D3 | Service, tenant, deployment, or environment | Wrong service or tenant; context diversion |
| D4 | Workload, process, or Agent | Same-host wrong-Agent confusion |
| D5 | Task, thread, context, or delegation | Wrong task or delegation; context diversion |
| D6 | Authorization or capability policy | Confused deputy or privilege escalation |

D0 through D2 are authentication and binding dimensions. D3 through D6 are
verifier-local policy dimensions. Peer-provided metadata can be observed input;
it is not expected policy.

A concrete binding profile must still define its profile identifier, protocol
identifier, TLS exporter label, canonical audience form, `grant_hash` bytes,
session-proof encoding, request-context construction, nonce and replay rules,
attestation requirement, D3 through D6 expected-value source, and diagnostic
error classes.

Decision-sensitive values such as `intent_ref`, `capability_ref`, and
`ontology_id` must already be canonical before acceptance. Receivers compare
them deterministically and do not repair peer-provided aliases, display labels,
URI variants, natural-language phrases, or model interpretations in the final
acceptance path.

## Evaluation Status

Covered in the current v0.4 evidence:

- focused local checks and unit-level coverage;
- positive and negative profile vectors;
- relay, replay, wrong-context, wrong-Agent, downgrade, stale-evidence,
  measurement-mismatch, and binding-parameter confusion checks;
- dependency-free live-style harnesses for local TLS exporter binding, HTTP/2
  and gRPC connection reuse, TLS resumption replay rejection, QUIC/TLS
  early-data pre-binding rejection, malformed token corpora, bounded fuzz smoke
  for compact JWT/JWS parsing, and deterministic acceptance invariants;
- route-assertion policy tests and a local HTTP route-assertion harness for the
  documented gateway boundary, with no runtime gateway mode.

For accepted TLS sessions, the AGTP observed-identity path derives
`tls_exporter_sha256` from the accepted `tls.ConnectionState`. Fixed exporter
bytes are used only in synthetic unit fixtures.

Not yet validated as a broad deployment security claim:

- end-to-end application 0-RTT payload behavior beyond the dependency-free
  QUIC/TLS early-data harness;
- broader gRPC deployment pooling beyond the local reuse harness;
- runtime gateway wiring beyond the route-assertion HTTP harness;
- longer fuzz/property campaigns beyond the bounded token-parser smoke target
  and the current 60-second local fuzz pass;
- hardware-backed confidential-VM attestation replay coverage.

See `docs/live-red-team-report.md` for the evidence matrix and
`PUBLICATION_TODO.md` for release blockers.

## Implementation Provenance

This repository contains derived runtime, attestation, legacy `pkg/atls`,
manager, agent, HAL, proxy, OCI, and helper code from
[ultravioletrs/cocos](https://github.com/ultravioletrs/cocos), plus
profile-specific documentation, tests, vectors, and security-profile helpers
for Agents Secure Binding.

Cocos remains implementation provenance and experience. It is not the normative
scope of this security profile.

The repository keeps the Apache-2.0 license and retained upstream notices. See
`ATTRIBUTION.md`.

Repository identity note: the public repository name and Go module path are
both `github.com/thinksyncs/agents-secure-binding`.

## Verification Commands

Local implementation checks:

```sh
go test ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Reference-adapter checks:

```sh
go test ./pkg/agtp ./pkg/agtp/gatewayroute
```

Focused Direct-Agent red-team check:

```sh
GOTOOLCHAIN=go1.26.0+auto go test -v -race -count=1 \
  ./pkg/atls/identitypolicy \
  ./pkg/clients
```

Product security gate:

```sh
make product-security-gate
```

Some client and red-team tests open local loopback listeners. Restricted
sandboxes may need a less constrained local environment for those tests.

## Security Reporting

Report suspected vulnerabilities through GitHub private vulnerability reporting
for this repository. Do not open a public issue with exploit details. See
`SECURITY.md`.

## Authorship and Review

This repository is maintained by ToppyMicroServices OÜ. Published
specifications, tests, and releases are reviewed and accepted by the
maintainer.

## License

This repository currently keeps the original Apache-2.0 license and retained
upstream notices. See `ATTRIBUTION.md`.
