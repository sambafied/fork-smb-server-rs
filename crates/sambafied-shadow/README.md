# `sambafied-shadow`

Status: **ACTIVE — partial core-storage prototype.**

`sambafied-shadow` is an internal Rust crate that exercises durable, private
overlay storage over a pinned immutable base. It is intentionally a storage
prototype, not the finished overlay product and not a public API commitment.

## What is implemented in this crate

- private whole-file blobs with content hashes and durable metadata;
- merged namespace state, including whiteouts and opaque directories;
- pinned-base reads, copy-up, private rename and base immutability checks;
- snapshots, reset, rollback, trash restore/purge, and verified backup/restore;
- generation switching, recovery history, retention references, capacity
  budgets, maintenance quiescence, and restart-oriented recovery tests.

The current storage tests are deliberately foundation evidence. They establish
behaviour for the crate's local storage model; they do not establish live SMB
engine behaviour or a management-plane contract.

## Not implemented by this crate

The prototype is not wired into the SMB engine, management API, CLI, or UI. It
does not provide management previews, job resources, mutation idempotency,
Windows 8.3 names, ACLs, extended attributes, alternate data streams, the
retention automation service, crash/fault qualification, or the full
API/CLI/UI parity suite.

## Contract and evidence

[`docs/overlay-milestone-contract.md`](../../docs/overlay-milestone-contract.md)
is the normative delivery contract. This README is descriptive only and does
not amend that contract. Current bounded evidence and the remaining delivery
gaps are recorded in
[`docs/overlay-core-evidence.md`](../../docs/overlay-core-evidence.md).

Run the focused foundation suite from the repository root with:

```text
cargo test -p sambafied-shadow --locked
```
