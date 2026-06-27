# Publication TODO

Release blockers and evidence limits for the public draft.

## Repository Identity

The public repository name is `agents-secure-binding`. The current Go module
path is still `github.com/thinksyncs/hardware-aware-tls-identity-binding`.

Before public v0.5, choose one:

- rename `go.mod`, imports, protobuf `go_package` options, examples, and docs
  to `github.com/thinksyncs/agents-secure-binding`;
- keep the existing module path and publish a compatibility note explaining why
  the module path remains stable.

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
| OCI image handling | `pkg/oci/skopeo.go` passes `--insecure-policy`, `--src-tls-verify=false`, `--dest-tls-verify=false`, and `--tls-verify=false`. | P0 before production runtime image pull, decrypt, inspect, or archive conversion use. | Default to verified policy and TLS verification; allow insecure mode only behind an explicit local development setting with tests. |
| Egress proxy policy | `pkg/egress/proxy.go` has allowlist TODOs in CONNECT, HTTP, and HTTP/2 paths. | P0 before exposing the proxy outside a trusted test network. | Add a fail-closed allowlist policy, audit fields, and negative tests for denied CONNECT and HTTP/2 destinations. |
| SEV-SNP HostData and kernel hashes | `hal/cloud/qemu.sh` accepts `SEV_SNP_HOST_DATA` and optional `kernel-hashes=on` without a profile-level appraisal contract. | P0 before relying on HostData or kernel hashes as verifier policy. | Define the expected HostData source, hash construction, appraisal rule, and fail-closed behavior when missing or mismatched. |
| Zip extraction | `internal/zip.go` joins `targetDir` with archive entry names during extraction. | P0 before accepting untrusted archives. | Reject absolute paths, `..` traversal, unsafe symlinks, and paths escaping the extraction root; add regression tests. |

## Evaluation Boundaries

The v0.4 red-team evidence is useful but limited. Before stronger public
claims, add or explicitly defer:

- real 0-RTT early-data transport coverage;
- gRPC connection-pooling coverage;
- full gateway-routed network harness;
- randomized fuzz/property generation for token and invariant paths;
- hardware-backed confidential-VM attestation replay coverage.
