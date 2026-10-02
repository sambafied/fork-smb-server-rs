# smb-server

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

The `rustsmb` server binary: CLI argument parsing, the async accept loop,
SMB1/SMB2 request dispatch, session/tree/handle state, and observability
(tracing + Prometheus metrics). This is where every other crate in the
workspace comes together — `smb-server-proto`/`smb-server-proto-smb1`/`smb-server-proto-smb2`
for wire codecs, `smb-server-transport` for framing, `smb-server-vfs`/`smb-server-backend-posix`
for storage, `smb-server-auth` for authentication, and `smb-server-handle-store` for
durable handles.

Runs fully async on `io_uring` via a `tokio_uring` current-thread runtime —
see the top-level [README](../../README.md) for the full concurrency model
and feature set.

## Optional durable shadow share policy

The current startup source adds an optional `--shadow-policy-root PATH` to
`rustsmb`. It requires `--shadow-config`; PATH must be an existing absolute
server-owned directory, and a symlink root is rejected. For example, a trusted
server configuration can add `--shadow-config /srv/samba/shadows.json
--shadow-policy-root /srv/samba/policies` to its existing account, share and
listener arguments. Accounts continue to arrive through private stdin.

Each shadow share uses one durable organisation/share policy authority shared
by all its mapped users. Their startup policy values, organisation, share and
base version must agree; conflicting values fail startup. Private user storage
namespaces remain separate. First startup persists the common initial policy;
restart loads existing policy and revision history, preserving administrative
edits rather than replacing them with startup defaults. Omit the policy-root
option to retain static shadow policies.

The startup source and native fixture are committed at `b2ecb8e` but have not
yet been compiled or qualified by the new Linux CI run. Regression tests have been added for conflicting defaults/scope,
persistent edits and the required shadow configuration. The native Linux
fixture selects this option and checks a single shared document unchanged
across restart; its CI execution is planned. The prior Core Store and adapter
source at `df650c1` had all four checks green, which does not qualify these
startup changes.

Product policy API/CLI/UI wiring and integrated live-change acceptance remain
incomplete. The catalogue primitive does not authorize callers and limits its
administrative audit outbox to 1,024 changes without a drain path. See
[POLICY.md](../sambafied-shadow/POLICY.md) for enforcement and qualification
boundaries.
