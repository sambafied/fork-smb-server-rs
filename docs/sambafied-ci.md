# Sambafied CI scope

The `Sambafied CI` workflow runs on Ubuntu for pushes to, and pull requests
targeting, `sambafied/**` branches.

## Covered

- `cargo check --locked -p smb-server`, which checks the server package and its
  resolved dependencies against the committed lockfile using Rust 1.98.1.
- Existing portable unit suites for `smb-server-auth`, `smb-server-proto`, and
  `smb-server-vfs`.

## Not covered

- io_uring runtime behavior or tests that need kernel capabilities beyond the
  standard GitHub-hosted Linux runner.
- Running SMB server acceptance, interoperability, client, network, filesystem,
  performance, or production-readiness testing.
- Any claim that a successful workflow validates a deployed SMB service.

This is an early, narrow source-level signal. Its covered checks should not be
treated as runtime or SMB acceptance evidence.
