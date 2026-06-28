# Publication TODO

Release blockers and evidence limits for the public draft.

## Repository Identity

Resolved for public v0.5: the repository name, Go module path, imports,
protobuf `go_package` options, examples, and local documentation use
`github.com/thinksyncs/agents-secure-binding`.

## Recorded CI and Red-Team Status

Latest recorded remote implementation checkpoint:

| Commit | Workflow | Run | Result | Date |
| --- | --- | --- | --- | --- |
| `4c3e4fc57cca52a6423394fe2292d620f957c962` | `CI` | `28181903677` | Success | 2026-06-25 UTC |
| `4c3e4fc57cca52a6423394fe2292d620f957c962` | `Security Red Team` | `28181903553` | Success | 2026-06-25 UTC |

This checkpoint is not a full security proof. New commits need their own CI and
red-team run before a public release.

## Inherited Runtime Risk Classification

These items come from inherited Cocos runtime code paths. Profile text does not
resolve them.

| Area | Evidence | Classification | Required disposition |
| --- | --- | --- | --- |
| OCI image handling | `pkg/oci/skopeo.go` no longer passes `--insecure-policy`, `--src-tls-verify=false`, `--dest-tls-verify=false`, or `--tls-verify=false`. | Addressed for the current runtime helper. | Keep skopeo policy and TLS verification enabled by default; do not add an insecure development mode without explicit tests and documentation. |
| Egress proxy policy | `pkg/egress/proxy.go` now defaults to loopback-only destinations and supports an explicit host, host:port, IP, or CIDR allowlist for CONNECT, HTTP, and HTTP/2 paths. | Addressed for the current proxy helper. | Configure `EGRESS_PROXY_ALLOWLIST` or `--allowlist` for non-loopback deployments; store unavailability is not part of this local proxy. |
| SEV-SNP HostData and kernel hashes | Go QEMU launch paths and `hal/cloud/qemu.sh` now reject invalid HostData before launch. `kernel-hashes=on` still has no profile-level appraisal contract. | Partly addressed; P0 before relying on HostData or kernel hashes as verifier policy. | Define the expected HostData source, hash construction, appraisal rule, and fail-closed behavior when missing or mismatched. |
| Zip extraction | `internal/zip.go` validates archive entry paths before extraction. | Addressed for the current in-memory zip helper. | Continue rejecting absolute paths, `..` traversal, unsafe symlinks, unsupported file types, and paths escaping the extraction root. |

## Evaluation Boundaries

The v0.4 red-team evidence is useful but limited. Before stronger public
claims, add or explicitly defer:

- real 0-RTT early-data transport coverage;
- gRPC connection-pooling coverage;
- full gateway-routed network harness;
- randomized fuzz/property generation for token and invariant paths;
- hardware-backed confidential-VM attestation replay coverage.
