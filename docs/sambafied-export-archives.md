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
view. Durable `State` is now schema `5` for the separate job-backed artifact
lifecycle; calling this raw primitive does not write that state.

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

The current management candidate implements internal `Action::Export` jobs,
schema-5 artifact receipts, revision and request binding, idempotency, admission
quotas, expiry checks and publication state. A product download API remains
pending. It must stage privately, publish only after
success, and make later retrieval subject to current authorization. It must not
treat the archive's deterministic digest as a substitute for any of those
controls.

Job-backed capture requires explicit server-owned `Policy.artifacts`. `None`
disables artifact capture. `ArtifactPolicy` defines its own TTL, count limit and
byte limit, independently of snapshot TTL. Complete tar bytes count against
both its byte limit and the store retained-byte budget; registered receipts
and physical orphans remain charged until physical reclamation. Expiry does
not free capacity. See [the artifact candidate contract](sambafied-export-artifacts.md)
for bounds and retry accounting.

`Store::artifact(id, actor)` provides an actor-scoped receipt.
`Store::open_artifact(id, actor, authorize)` returns a verified, rewound file
descriptor only after current authorization is checked before archive
verification and again before return. Ownership alone grants no authorization.
Automatic expiry pruning and artifact deletion are not implemented.

Public API, CLI download, UI export flow, background runtime behavior, crash
and broader process-kill/end-to-end fault qualification, and product-level
artifact lifecycle remain pending.
They require their own contracts and evidence; none are supplied by this
storage primitive.

## Evidence and limits

The current source candidate has 62 passing core tests (49 existing plus 13 export
tests) on Windows and Linux,
six passing shadow backend tests on Linux, and strict core Clippy passes on
both platforms. The archive regressions cover deterministic output, private
upper-content deduplication, whiteouts, isolation, unchanged storage,
pre-write validation, writer failures, partial writes and pure preflight.

These are source-level candidate checks. They do not establish a CI result for
these changes, end-to-end acceptance, product API/CLI/UI integration, runtime
acceptance, deployment or release qualification.

PR #10 merged the archive foundation at `955b46b0db53aa000b326853cb52edc7ba2095db`,
after all four CI checks passed on `3c7ff64`. That merged foundation evidence does not
qualify the subsequent durable artifact candidate.

The additional durable regressions prove that a completed tar remains charged against
retained capacity and can block a snapshot; quiescent schema-4-to-5 migration leaves the
old artifact policy disabled; and a planned running retry rejects a changed TTL before
publication, then resumes exactly once with the original binding.

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
The internal durable job/artifact lifecycle is implemented in the current
source candidate; public API, CLI and UI integration remain pending.
The sixth export regression verifies exact size agreement, unchanged storage,
and stale, busy, corrupt and over-budget rejection during preflight.

Source filesystem-fault tests verify private publication before a failed local
success receipt, restart and retry reconciliation, authorization revocation, and
changed-TTL rejection. These checks do not establish broader process-kill or
end-to-end fault qualification.
