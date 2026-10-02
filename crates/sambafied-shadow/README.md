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

## Internal backup management jobs

The internal state format is schema 5. It records queued, running, succeeded,
and failed receipts for capture, restore, delete-backup and export work. A capture
uses its job ID as the backup ID, so a restart can reconcile an already
published external backup with the same receipt instead of creating a second
backup.

Backup destinations come only from a server-owned catalog. A request selects a
validated destination ID; it never supplies a filesystem path. Previews are
pure: they validate the revision-bound source, destination, budgets, and
expected impact without writing blobs, manifests, receipts, or history. An API
layer must still authorize a request, bind the preview to its actor/resource and
expiry, and recheck those conditions at submission and execution.

External backup manifests have v1 and v2 reader compatibility. Job-backed
captures write v2. Restore validates either v1 or v2 against the configured
identity, base digest, destination, expiry, content hashes, and size before it
changes the local view. Delete writes a durable deletion tombstone (and makes a
v1 manifest v2 before tombstoning) so a backup cannot reappear after loss of
the local upper-store index. The tombstone deliberately retains its backup
directory: its physical bytes and destination entry count remain charged until
separate reclamation is implemented.

An external manifest can be published before the local successful receipt is
durable; publication across those folders is therefore not atomic. Such an
orphaned published backup remains discoverable and is reconciled only through
the same job ID. If a restarted running capture or deletion is retried after
authorization is denied, configuration or source binding changes, or the source
has expired, the uncertainty remains resumable rather than becoming a terminal
failed receipt. This storage layer does not promise that it will automatically
retry or complete that work.

The six existing management actions — snapshot, reset, rollback, restore-trash,
purge-trash, and delete-snapshot — are exposed through the product management
surfaces and have an SMB shadow backend in `smb-server-backend-shadow`;
Linux-native CI exercises that integration. The storage tests in this crate
remain focused foundation evidence: they do not qualify the new backup job
actions as a product management-plane contract.

## Internal durable export artifacts

`Action::Export` captures deterministic upper-layer tar archives and records
schema-5 artifact receipts. Its stable artifact ID is the job UUID. Execution
checks current authorization before capture and again before publication;
publication can precede the durable local success receipt, so retry reconciles
an existing verified archive with that same ID.

Capture requires explicit server-owned `Policy.artifacts`; `None` disables
artifact capture. Its TTL, count and byte limits are independent of snapshot
TTL. Complete archives count against both the artifact byte limit and retained
bytes. Registered receipts and physical orphans remain charged, including
expired archives, until physical reclamation. Automatic expiry pruning and
artifact deletion are not implemented.

`Store::artifact(id, actor)` returns an actor-scoped receipt, not authorization.
`Store::open_artifact(id, actor, authorize)` verifies size and SHA-256 and
returns a rewound file descriptor, invoking current authorization before
verification and again before return. Product API, CLI and UI integration
remain pending. The raw `Store::export_archive` and `export_preflight` methods
create no durable jobs or receipts and do not write `State`.

See [the artifact candidate contract](../../docs/sambafied-export-artifacts.md)
and [the raw archive contract](../../docs/sambafied-export-archives.md).

## Not implemented by this crate

The new capture, restore, delete-backup and export job actions are internal storage
work only. They are not yet exposed or qualified as product management API,
CLI, or UI actions, and their storage primitives are not a public API contract.
This crate does not provide public job resources, Windows 8.3 names, ACLs,
extended attributes, alternate data streams, the retention automation service,
broader process-kill/end-to-end fault qualification, or the full API/CLI/UI parity suite. Nothing here
claims a deployment or release.

## Contract and evidence

[`docs/overlay-milestone-contract.md`](https://github.com/sambafied/sambafied/blob/main/docs/overlay-milestone-contract.md)
is the normative delivery contract. This README is descriptive only and does
not amend that contract. Current runtime qualification evidence and the
remaining delivery gaps are recorded in
[`docs/overlay-runtime-qualification.md`](https://github.com/sambafied/sambafied/blob/main/docs/overlay-runtime-qualification.md).

Run the focused foundation suite from the repository root with:

```text
cargo test -p sambafied-shadow --locked
```

Current candidate source checks: 62 core tests (49 existing plus 13 export tests) pass
on Windows and Linux, six
shadow backend tests pass on Linux, and strict core Clippy passes on both.
These checks do not establish a CI result for these changes or end-to-end
acceptance.

PR #10 merged the archive foundation at `955b46b0db53aa000b326853cb52edc7ba2095db`,
after all four CI checks passed on `3c7ff64`. That merged foundation evidence does not
qualify the subsequent durable artifact candidate.

The additional durable regressions prove that a completed tar remains charged against
retained capacity and can block a snapshot; quiescent schema-4-to-5 migration leaves the
old artifact policy disabled; and a planned running retry rejects a changed TTL before
publication, then resumes exactly once with the original binding.

Source filesystem-fault tests verify private publication before a failed local
success receipt, restart and retry reconciliation, authorization revocation, and
changed-TTL rejection. These checks do not establish broader process-kill or
end-to-end fault qualification.
