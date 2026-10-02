# Share policy catalogue: CORE STORE ENFORCEMENT ONLY

`SharePolicyCatalog` is a durable organisation/share policy authority primitive.
Core Store operations can now use that authority through
`Store::open_with_policy_catalog`. The SMB adapter can opt in through `ShadowVfs::new_with_policy_catalog`;
server startup configuration and product API, CLI and UI wiring remain incomplete. This work does not establish end-to-end
live enforcement or complete the live-policy milestone.

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
closed. A Store rejects a catalogue for another organisation/share before
creating its upper namespace.

The catalogue stores policy and administrative changes only. Replacement does
not mutate upper data, rewrite existing retained-object expiry times, or
retroactively change existing TTLs. Core Store operations use current policy
for future operations. Lowering write limits preserves reads of existing data:
reads are bounded by pinned entry sizes, and changed pinned content still fails
with `Error::Corrupt`. The configured base scanning ceiling remains relevant
when opening a Store; a lower catalogue write limit does not hide pinned base
files.

## Leases, replacement and preview binding

`read()` returns a consistent policy document with a shared cross-process read
lease. Runtime adapters must retain that lease and the policy snapshot for the
entire operation. Reading at startup or dropping the lease before the operation
finishes does not provide this guarantee.

For catalogue-backed Stores, serial storage and action operations acquire a
policy lease before the state lock and use one immutable current-policy Store
snapshot with shared pinned base indexes. Existing Store instances and open
handles therefore use updated limits on their next operation. The operation
retains its policy lease through validation and publication; raw archive export
retains it through the final archive write. `inspect_with_policy()` returns the
state, effective policy and optional policy revision from the same operation.
`Store::open` remains the static-policy opening path.

`replace(expected_revision, actor, policy)` validates the replacement and takes
a nonblocking exclusive lease. An active reader produces `Error::Busy`; a stale
expected revision produces `Error::Revision`. Neither publishes a change.
Successful replacement increments the monotonic revision and atomically
publishes the policy and its administrative audit event in the same document.
The event records the actor, commit time, revision and previous/new policy
digests. Publication failure preserves the prior policy and audit document.

`PolicyRead::fingerprint()` binds the organisation, share, revision and policy
values. Changing policy from A to B and back to A produces a different
fingerprint because the revision advances. Catalogue-backed Store action
fingerprints also include the policy revision: stale previews are rejected,
and queued actions bound to an older policy fail without applying their action,
even after an A-to-B-to-A change with no Store generation change.

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

The historical foundation receipt at `a8d1d9c` reported parent-run Windows
verification of five new catalogue tests and the existing 63 core tests: 68
passing core tests, one ignored subprocess fixture helper and strict Clippy
passing. Catalogue coverage included durable reopen, scope separation,
revision/fingerprint ABA behavior, read-lease contention, stale replacement,
corrupt document rejection, Windows publication failure preservation, and a
cross-process reader-kill test showing that process death releases the gate
without changing the policy revision. This receipt qualifies the foundation
source only.

For the current Core Store enforcement changes, the parent reports Windows
verification of 72 passing core tests (63 existing and nine new), two ignored
subprocess fixture helpers and strict Clippy passing. Added Store tests cover
updated limits on already-open handles while preserving existing data and
state, policy ABA invalidation of previews and queued actions, wrong-catalogue
rejection before namespace creation, and policy-lease retention through every
archive writer call. The pinned-base corruption regression continues to require
`Error::Corrupt` and passes in the current suite. These checks qualify Core
Store enforcement only, not SMB integration or end-to-end authorization.

The prior portable Linux CI run at `a8d1d9c` failed the independent-reader lease
release test with `Error::Busy` after the lease was dropped. Commit `9c0702c`
adds explicit lease unlocking. The parent verified all four PR #13 checks green
at `9c0702c5c20f7ca55f79daa28a66e246753a0b88`, including portable Linux and native
SMB checks on push and PR. This qualifies that committed lease correction, not
the current uncommitted Store enforcement changes. Inherited fork descriptors
remain a possible explanation for the prior failure, not a verified cause.

The read-only destination publication-fault test is Windows-specific. Unix
publication-fault behavior is not qualified by it: Unix rename can replace a
read-only inode. None of these receipts constitutes milestone acceptance.

## Remaining runtime work

Wire the catalogue-backed Store into trusted SMB backend configuration and
provide authorized share policy GET/PUT with ETag concurrency control and
matching CLI/UI behavior. Qualify integrated quota, retention and grants
scenarios and qualify the current Store enforcement changes on Linux. Any
unsupported policy fields or
scheduler behavior require their own implementation and qualification; Core
Store enforcement does not promise their acceptance or execution.

The parent also verified seven Windows SMB adapter storage tests, including an
already-open protocol handle observing reduced write limits while retaining reads,
updated disk free space, Bob isolation and unchanged base content. This is adapter
coverage, not network or server-startup qualification.
