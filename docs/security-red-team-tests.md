# Security Red-Team Test Notes

This note records the live-style red-team regressions added for the AGTP
identity hook used by aTLS clients.

## Scope

The tests exercise the production-facing client hook:

- `AttestedClientConfig.AGTPObservedIdentity()`
- `agtp.VerifySessionIdentityJWT`
- `identitypolicy.ValidateAssertion`
- `identitypolicy.MemoryReplayCache`

This is different from testing the lower-level validator functions directly.
The goal is to confirm that attacker-shaped inputs are rejected through the
same callback that a client configuration wires into aTLS.

## Tests

The red-team coverage lives in `pkg/clients/clients_test.go`.

### `TestAGTPObservedIdentityAcceptsManagerIssuedGrantE2E`

This test uses small in-process issuer helpers to model the intended flow:

- a Manager issues an Identity Grant;
- an Agent issues a Session Binding Statement for that exact grant;
- the client verifies both through `AGTPObservedIdentity()`;
- the resulting assertion is compared with the accepted aTLS binding.

This keeps the test close to the production client hook without requiring a
network Manager service.

### `TestAGTPObservedIdentityAcceptsHTTPJWKSAndRejectsRevocation`

This test uses `httptest` to model external key and revocation sources:

- `/jwks` returns Manager and Agent verification keys;
- `/revocations` returns revoked grant `jti` values;
- the client uses a `KeyFunc` backed by the HTTP key source;
- the client rejects a grant when the HTTP revocation source lists its `jti`.

This is not a Redis, JWKS, or registry product implementation. It is a
dependency-free integration test showing how the existing verification hooks
fail closed when caller-supplied HTTP key and revocation sources are wired in.

### `TestAGTPObservedIdentityRedTeamRejectsAttacks`

This test builds Manager-signed Identity Grants and Agent-signed Session
Binding Statements, then mutates them into attacker-shaped cases.

It checks:

- a peer-signed grant cannot impersonate the Manager;
- a diverted service identity cannot satisfy local client policy;
- diverted tenant or deployment identity cannot satisfy local client policy;
- a borrowed binding for a different accepted leaf key is rejected.
- a borrowed binding for a different request context is rejected.

These cases cover the main intended failure classes for the AGTP identity hook:

- unauthorized issuer or signing key;
- diversion against local expected service, tenant, and deployment identity;
- relay or borrowed-evidence attempts against the accepted aTLS leaf key and
  request context.

### `TestAGTPObservedIdentityRedTeamRejectsAgentThreats`

This test exercises agent-specific semantic threats through the same live client
hook. It binds a valid Manager grant and Agent session-binding statement to
service, workload, task, delegation, scope, resource, and authorization policy,
then mutates one boundary at a time.

It checks:

- impersonation by a peer-signed grant;
- prompt-injection-shaped unsafe task context;
- tool misuse through the wrong tool scope;
- data exfiltration through the wrong resource target;
- capability escalation through a stronger-than-authorized scope;
- policy bypass through required mode without concrete checks;
- confused-deputy behavior through the wrong delegation id;
- a newly spawned agent key attempting to inherit a parent grant;
- audit evasion through missing grant or binding ids.

These cases treat identical machine, account, or session context as insufficient
unless the semantic agent, task, delegation, capability, and audit bindings also
match local policy.

### `TestAGTPObservedIdentityRedTeamRejectsReplay`

This test calls the same observed-identity callback twice with the same valid
Session Binding Statement and replay cache.

It checks:

- first use is accepted;
- second use is rejected with `identitypolicy.ErrReplayDetected`.

## Expected Result

All red-team cases should fail closed before the client treats the observed
identity as accepted. Successful execution means the attacker-shaped input was
rejected, not accepted.

## Command

Run the focused client red-team tests with:

```sh
env GOCACHE=/tmp/go-build-cocos go test -count=1 ./pkg/clients
```

For the broader security regression set, run:

```sh
env GOCACHE=/tmp/go-build-cocos go test -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/atls/ea ./pkg/atls/eaattestation ./pkg/atls/internal_transport ./pkg/atls ./pkg/clients ./pkg/clients/grpc ./pkg/clients/http
```
