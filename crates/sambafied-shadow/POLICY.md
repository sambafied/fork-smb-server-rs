# Share policy catalogue: Core Store and SMB adapter enforcement

`SharePolicyCatalog` is a durable organisation/share policy authority primitive.
Core Store operations can now use that authority through
`Store::open_with_policy_catalog`. The SMB adapter can opt in through `ShadowVfs::new_with_policy_catalog`;
optional server startup configuration is described below. Product policy API, CLI
and UI wiring remain incomplete. This work does not establish end-to-end
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

## Optional SMB server startup authority

The current startup source adds `--shadow-policy-root PATH`, which requires
`--shadow-config`. PATH must be an existing absolute server-owned directory;
the catalogue rejects a symlink root. This trusted host path is not selected
by SMB clients.

For each configured shadow share, every mapped user must supply identical
startup policy values and the same organisation, share and base version.
Conflicting defaults or scope fail startup rather than selecting one user's
policy. All mapped users of that share receive the same catalogue authority,
while their private storage namespaces remain separate. A new catalogue
persists the common initial policy; reopening preserves durable edits and
revision history instead of overwriting them with startup defaults.

Omitting `--shadow-policy-root` keeps the existing static configuration path
through `ShadowVfs::new` and `Store::open`.

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

The parent verified all four PR #13 checks green for committed Core Store and
SMB adapter source at `df650c1`, including portable Linux and native SMB checks
on push and PR. Windows verification included 72 passing core tests, two
ignored subprocess fixture helpers, strict Clippy and seven SMB adapter storage
tests. Coverage includes current limits on already-open handles, preserved
reads and state, policy ABA invalidation, wrong-catalogue rejection, policy
leases through archive writes, disk free space, Bob isolation and unchanged
base content. These receipts qualify that committed source, not the subsequent
startup changes.

The optional startup source and native fixture are committed at `b2ecb8e`
but have not yet been compiled or qualified by the new Linux CI run. Added regression tests cover conflicting startup defaults/scope
before catalogue publication, preservation of a committed policy edit on
reopen, and the CLI requirement for explicit shadow configuration. The native
Linux fixture now selects a shared policy root and checks one policy document
and unchanged document bytes across a server restart; execution in CI is
planned. This fixture does not itself exercise an administrative policy edit
or establish live network policy-change acceptance.

The earlier portable Linux failure at `a8d1d9c` returned `Error::Busy` after an
independent-reader lease was dropped. Commit `9c0702c` added explicit lease
unlocking and its four checks passed. Inherited fork descriptors remain a
possible explanation for the prior failure, not a verified cause.

The read-only destination publication-fault test is Windows-specific. Unix
publication-fault behavior is not qualified by it: Unix rename can replace a
read-only inode. None of these receipts constitutes milestone acceptance.

## Remaining runtime work

Compile and qualify the optional trusted SMB startup wiring, then provide
authorized share policy GET/PUT with ETag concurrency control and matching
product CLI/UI behavior. Qualify integrated quota, retention and grants
scenarios. Unsupported policy fields or scheduler behavior require their own
implementation and qualification; Core Store enforcement does not promise
their acceptance or execution. The primitive still supplies no caller
authorization and has a bounded audit outbox without a drain path.
