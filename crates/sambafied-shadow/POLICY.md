# Share policy catalogue: FOUNDATION ONLY

`SharePolicyCatalog` is a durable organisation/share policy authority primitive.
This is foundation work only: there is no SMB store, API, CLI or UI runtime
wiring yet. It does not establish live enforcement or complete the live-policy
milestone.

## Scope and persistence

Trusted server configuration selects the catalogue root, organisation and share.
The root must be an existing absolute directory, and a symlink root is rejected.
The catalogue canonicalises that root and hashes the organisation/share pair to
select its policy document and lock file. Clients must never select this host
path or assert the authoritative organisation/share scope.

Opening a new catalogue validates and persists the initial policy at revision
zero. Reopening loads and validates the existing document; startup defaults do
not overwrite durable policy. Unknown document fields, unsupported schema,
scope mismatch, invalid policy and inconsistent revision/audit chains fail
closed.

The catalogue stores policy and administrative changes only. It does not mutate
upper data, rewrite existing retained-object expiry times, or retroactively
change existing TTLs. Applying policy to future storage operations remains a
runtime integration responsibility.

## Leases, replacement and preview binding

`read()` returns a consistent policy document with a shared cross-process read
lease. Runtime adapters must retain that lease and the policy snapshot for the
entire operation. Reading at startup or dropping the lease before the operation
finishes does not provide this guarantee.

`replace(expected_revision, actor, policy)` validates the replacement and takes
a nonblocking exclusive lease. An active reader produces `Error::Busy`; a stale
expected revision produces `Error::Revision`. Neither publishes a change.
Successful replacement increments the monotonic revision and atomically
publishes the policy and its administrative audit event in the same document.
The event records the actor, commit time, revision and previous/new policy
digests. Publication failure preserves the prior policy and audit document.

`PolicyRead::fingerprint()` binds the organisation, share, revision and policy
values. Changing policy from A to B and back to A produces a different
fingerprint because the revision advances, preventing ABA reuse of a preview
binding. Runtime action paths still need to consume and verify this binding.

## Authorization and bounded audit outbox

The primitive does not authorize callers. Each runtime caller must independently
authorize policy reads, administrative changes and storage/action operations,
and supply a server-verified actor rather than a client ownership assertion.
Valid actor syntax is not authorization.

The durable audit outbox holds at most 1,024 administrative changes. Once full,
replacement fails closed with `Error::Quota`; no automatic drain, truncation or
acknowledgement path exists. An operational export/acknowledgement design is
still required before sustained administration can rely on this catalogue.

## Verification boundary

Parent-run Windows verification reported five new catalogue tests passing and
one ignored subprocess fixture helper. The existing 63 core tests passed, for
68 passing core tests in total, and strict Clippy passed. Catalogue coverage
includes durable reopen, scope separation, revision/fingerprint ABA behavior,
read-lease contention, stale replacement, corrupt document rejection, Windows
publication failure preservation, and a cross-process reader-kill test showing
that process death releases the gate without changing the policy revision.

The read-only destination publication-fault test is Windows-specific. Unix
publication-fault behavior is not qualified by it: Unix rename can replace a
read-only inode. These checks qualify the foundation primitive, not runtime
enforcement, end-to-end authorization or milestone acceptance.

## Remaining runtime work

The next implementation must retain full-operation leases and consistent policy
snapshots across every storage and action path, and bind previews/actions to the
monotonic policy revision. It must provide authorized share policy GET/PUT with
ETag concurrency control, matching CLI/UI behavior, and integrated quota,
retention and grants scenarios. Any unsupported policy fields or scheduler
behavior require their own implementation and qualification; this foundation
does not promise their acceptance or execution.
