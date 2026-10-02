# Sambafied management receipts

Management receipts are durable, internal core-job primitives. They are not a
public management API and do not by themselves provide a CLI, UI, backup jobs
or exports. Retention and receipt pruning are also pending.

## Supported operations

Each receipt names exactly one of these six operations:

1. `snapshot`
2. `reset`
3. `rollback` of a snapshot
4. `restore-trash` of a trash entry
5. `purge-trash` of a trash entry
6. `delete-snapshot` of a snapshot

## Action previews

`preview_action` is an internal, pure preflight for those same six actions. It
obtains the exclusive maintenance gate and is blocked while another maintenance
operation holds it. It also serializes with state access, requires the caller's
expected revision, validates the action, and evaluates the operation against a
staged clone of the current state. A busy gate, stale revision, malformed
identifier, retention protection, quota failure, or any other operation
precondition prevents a preview from being returned.

The returned `ActionImpact` binds the evidence to the current revision,
generation, base version, and a fingerprint of the state and policy. It reports
the logical post-action usage and counts: active and retained bytes, snapshot
and trash counts, and the number of affected entries. `affected_entries` is
calculated against the merged namespace, including base and upper-layer paths,
so it represents the logical visible change rather than only a copied-up file.
For `reset` and `rollback`, `recovery_retention_seconds` reports the configured
recovery window. It is not a generalized retention forecast. For `purge-trash`
and `delete-snapshot`, `physical_reclamation_deferred` says that later physical
reclamation may still be required; the preview does not promise reclaimed disk
space.

Previewing writes no blob, manifest, receipt, history event, or job. This also
holds for a base-only trash restore: preview validates the copy-up and budget
path without materializing the file's blob. It changes neither the stored state
nor the namespace visible to SMB clients.

A preview is evidence, not authorization, a durable plan, or a public API
contract. Before requesting a preview, an API caller must authorize the action
and bind its result to the actor, resource, normalized input, expiry, and its
own plan identifier. The fingerprint is not an authorization decision and must
not be treated as a durable plan token. Submission and execution must acquire
their own gates and recheck every authorization and state precondition; a
successful preview does not reserve the namespace or guarantee execution.

The impact is a logical storage estimate. It does not guarantee physical free
space, concrete blob or object keys, encryption state, ACLs, aliases, or other
filesystem-facing details.

The receipt test suite currently has 12 receipt cases, including four preview
regressions: all six actions leave storage unchanged while reset reports its
recovery window; base-only restore does not materialize a blob; preview rejects
busy, stale-revision, protected-source, and restore-conflict cases without
writes; and fingerprint changes with its source state while reset still checks
the recovery quota.

On success, the operation's data change, its resulting receipt, and all history
events created by that operation are atomically published together. The receipt
records the resulting revision and generation, plus any snapshot or recovery
snapshot produced by the operation. A receipt is initially `queued`, becomes
`running` while work is staged, and is terminal as `succeeded` or `failed`.
Running receipts persist and may be resumed after restart.

## Submission, ownership, and execution

Idempotency is scoped to the actor and namespace. A retry with the same actor,
idempotency key, expected revision, and action returns the existing receipt,
including when a previous execution has already advanced the data revision. A
changed action or expected revision with that actor/key pair is an idempotency
error. Receipt lookups and execution are actor-scoped.

`submit_job` trusts its actor input as already authorized. Its caller **must**
enforce OIDC and Cedar authorization and validate destructive previews before
submitting. Execution rechecks authorization before staging and again before
activation. Execution of a terminal receipt also invokes that callback. The
`job` lookup checks actor ownership only; callers must separately authorize
every lookup against current policy.

A busy lease is retryable: the receipt remains queued or running for a later
attempt and no mutation is forced. Terminal `failed` receipts are not retried
automatically. Failures carry a stable error code, while a success already
published is preserved even if a later directory-sync report fails.

The receipt store has a hard cap of 1,024 receipts. Until retention/pruning is
implemented, reaching that cap rejects new submissions.

## State-schema compatibility

Opening schema 1 state automatically migrates it to schema 2, but migration
requires quiescence: an active maintenance lease causes opening to fail busy
without rewriting the state. Schema 2 stores the receipt collection. An old
engine must reject schema 2; there is no downgrade path. Unknown state fields
are rejected rather than ignored.
