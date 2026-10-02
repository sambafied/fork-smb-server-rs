# Sambafied management receipts

Management receipts are durable, internal core-job primitives. They are not a
public management API and do not by themselves provide a CLI, UI, previews,
backup jobs or exports. Retention and receipt pruning are also pending.

## Supported operations

Each receipt names exactly one of these six operations:

1. `snapshot`
2. `reset`
3. `rollback` of a snapshot
4. `restore-trash` of a trash entry
5. `purge-trash` of a trash entry
6. `delete-snapshot` of a snapshot

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
