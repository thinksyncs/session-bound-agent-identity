# Contributing

Thanks for considering a contribution. This repository is focused on the
hardware-aware TLS identity-binding profile, its Go implementation helpers, and
the accompanying security test vectors.

## Issues

Open an issue when behavior is unclear, a security boundary is missing, or a
test vector does not match the profile. Include:

- the affected file, package, or vector;
- the expected behavior;
- the observed behavior;
- the smallest reproduction or failing test, when available.

## Pull Requests

Keep pull requests focused. A good pull request changes one behavior, document
section, or test surface at a time.

Use concise Conventional Commit messages:

```text
<type>(optional scope): <summary>
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`,
`build`, and `perf`.

Before opening a pull request, run the relevant checks. For profile and identity
changes, start with:

```sh
go test ./pkg/agtp ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Some client tests open local loopback listeners. Restricted sandboxes may need a
less constrained local environment for those tests.

## Documentation

`docs/SSOT.md` is the source of truth for the security profile. Keep derived
notes, reports, and test-vector descriptions aligned with it.
