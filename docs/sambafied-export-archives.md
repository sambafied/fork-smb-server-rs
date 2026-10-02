# Sambafied shadow export archives

`Store::export_archive(expected_revision, private_writer)` is a foundational
storage primitive for producing a consistent, portable archive of one private
shadow view. It is deliberately not a public export feature or an artifact
resource. It creates no snapshot, history event, receipt, job, backup, or
durable publication record.

The primitive accepts an expected revision and a writer that the caller has
already made private. It returns an `ExportSummary` only after the complete
archive has been written successfully. The summary contains the archive byte
count, the lowercase SHA-256 of the complete tar stream, and the archived
generation and revision.

## Archive contract

The output is a deterministic, uncompressed USTAR tar. It contains exactly:

- `manifest.json`, encoded as JSON for manifest schema `1` with the shadow
  identity, pinned `base_digest`, generation, revision, and complete logical
  `view`;
- `blobs/<sha256>.blob` for each distinct digest referenced by a non-directory
  upper entry.

Blob members contain only private upper-layer content. Repeated upper files
with the same digest are represented by one blob member, and members are
ordered deterministically by their digest. The manifest is written first.
Tar headers are regular-file entries with fixed metadata, and there is no
compression, making repeated exports of an unchanged view byte-for-byte
identical.

The archive is a dependency on the pinned base, not a standalone game or share
image. `base_digest` identifies the required base, but base bytes are not copied
into the tar. The logical view preserves whiteouts (including directory
whiteouts) so a consumer can reconstruct the private overlay semantics against
that exact base. It does not include host storage paths, internal namespace
paths, the configured base path, or another principal's private blobs.

`State` is not extended or otherwise changed by this primitive. The archive
manifest is a separate, schema-1 representation of the selected revision and
view; it does not revise the existing durable-state schema, which remains at
schema `4`.

## Consistency, validation, and writer safety

Export takes the exclusive maintenance gate and the serial state gate, then
requires `expected_revision` to equal the current revision. An active SMB
handle or maintenance operation therefore yields a retryable busy result, and a
changed revision is rejected before archive construction.

Before touching the supplied writer, export validates normalized logical paths,
entry names, object IDs, file and directory invariants, whiteout markers, and
all referenced content metadata. It builds the deduplicated blob list, checks
the exact tar budget, and reads every referenced blob once to verify both its
declared size and SHA-256 digest. Any stale revision, quota violation, corrupt
metadata, missing blob, size mismatch, or digest mismatch fails without
writing archive bytes.

The staging budget is exact. It includes each member's 512-byte tar header,
payload rounding, and the final two zero blocks. The calculated archive size
must fit `policy.temporary_bytes` before writing begins. The writer counts the
actual bytes and hashes every successful write, refuses to exceed that budget,
and verifies that the final tar size equals the precomputed value.

The blobs are read and hash-checked again while they are copied into the tar.
This second check detects changes between preflight and copy. A writer error,
tar failure, size discrepancy, or second-pass validation failure returns an
error and no `ExportSummary`. Short successful writes are supported: the writer
retries until each requested buffer is completely written, while accounting for
and hashing each successful write.

The primitive cannot undo bytes already sent to a writer. Its contract is that
the caller must use an isolated private staging writer and discard it on every
error. A partial writer is never an artifact and must never be published. Only
a successful return, followed by caller-controlled publication of the complete
staged bytes, may make an archive visible.

## Management-layer responsibilities

This primitive has no authorizing caller argument and makes no authorization
decision. The management layer must authorize the actor, resource, operation,
and requested revision before it calls export; it must also recheck those
conditions at admission and immediately before it publishes. A successful
primitive call is evidence of archive construction, not an authorization token
or an entitlement to download data.

The management layer is responsible for durable artifact and job records, plan
binding, idempotency, admission quotas, expiry, publication state, retention,
and an authorized download API. It must stage privately, publish only after
success, and make later retrieval subject to current authorization. It must not
treat the archive's deterministic digest as a substitute for any of those
controls.

The durable artifact policy remains unspecified and pending: artifact TTL,
artifact count limits, and retained-byte accounting require an explicit
server-owned policy. Future implementation must define that policy rather than
silently reuse the snapshot TTL.

Public API, CLI download, UI export flow, background runtime behavior, crash
and fault qualification, and product-level artifact lifecycle remain pending.
They require their own contracts and evidence; none are supplied by this
storage primitive.

## Evidence and limits

The current source candidate is covered by the focused Windows development
suite: 55 tests total, comprising 49 existing tests and 6 export tests. The
export tests demonstrate deterministic output, deduplicated private upper
content, manifest preservation of whiteouts, exclusion of base and another
principal's bytes, unchanged storage, pre-write rejection of busy/stale/quota/
corrupt inputs, private-writer failure without a storage-side publication, and
partial successful writer calls that still produce a complete verified tar
stream. The strict core Clippy pass also passes.

The same 55 tests (6 export and 49 existing) and strict core Clippy pass in a
bounded Linux source check
using the pinned Rust 1.98.1 Bookworm container and the project seccomp profile.

This is source-level candidate evidence only. It does not claim Linux CI
coverage, a completed CI run, runtime acceptance, an exported artifact service,
or release qualification.

## Pure export preflight

`Store::export_preflight(expected_revision)` validates the same logical metadata,
blob hashes, file sizes, quiescence, revision and staging budget as archive
capture. It returns exact uncompressed tar bytes, generation and revision without
writing an archive or changing storage. The result is preparation evidence, not
an artifact ID, authorization decision, durable receipt or confirmation plan.
Execution must revalidate; a preflight does not reserve capacity.

The internal prepared capture separates content validation from archive writing,
so durable management execution can hold its existing locks, check retained
capacity and renewed authorization before creating a private staging file.
The public job/artifact lifecycle and API, CLI and UI integration remain pending.
The sixth export regression verifies exact size agreement, unchanged storage,
and stale, busy, corrupt and over-budget rejection during preflight.
