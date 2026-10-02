# Sambafied CI scope

The `Sambafied CI` workflow runs on Ubuntu for pushes to, and pull requests
targeting, `sambafied/**` branches.

## Covered

- `cargo check --locked -p smb-server`, which checks the server package and its
  resolved dependencies against the committed lockfile using Rust 1.98.1.
- Existing portable unit suites for `smb-server-auth`, `smb-server-proto`,
  `smb-server-vfs`, `sambafied-shadow`, and `smb-server-backend-shadow`.

## Self-contained shadow core

The engine includes the generic `sambafied-shadow` core as source in this
repository.  It was initially mirrored from the product at
`f93a0fa03dd7d60e805c0aa05dfe3e4769aafa5e`; the source is currently identical
to that version.  Engine crates use the in-repository source and have no
private Git dependency for this core.

## Not covered

- io_uring runtime behavior or tests that need kernel capabilities beyond the
  standard GitHub-hosted Linux runner.
- Running SMB server acceptance, interoperability, client, network, filesystem,
  performance, or production-readiness testing.
- Any claim that a successful workflow validates a deployed SMB service.

This is an early, narrow source-level signal. Its covered checks should not be
treated as runtime or SMB acceptance evidence.
