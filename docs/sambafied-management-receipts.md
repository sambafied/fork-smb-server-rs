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

`preview_action` is an internal, pure preflight for those same six actions.
`preview_planned_action` is the corresponding preflight for a planned job. Both
obtain the exclusive maintenance gate and are blocked while another maintenance
operation holds it. They also serialize with state access, require the caller's
expected revision, validate the action, and evaluate it against a staged clone
of the current state. A busy gate, stale revision, malformed identifier,
retention protection, quota failure, or any other operation precondition
prevents a preview from being returned.

The returned `ActionImpact` binds the evidence to the current revision,
generation, base version, and a fingerprint of the state and policy. It reports
the logical post-action usage and counts: active and retained bytes, snapshot
and trash counts, and the number of affected entries. `affected_entries` is
calculated against the merged namespace, including base and upper-layer paths,
so it represents the logical visible change rather than only a copied-up file.
For `reset` and `rollback`, `recovery_retention_seconds` reports the configured
recovery window. A planned `restore-trash` reports that window too: its
execution first creates a protected recovery snapshot and changes generation
before restoring the entry. It is not a generalized retention forecast. For
`purge-trash` and `delete-snapshot`, `physical_reclamation_deferred` says that
later physical reclamation may still be required; the preview does not promise
reclaimed disk space.

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

Receipt regressions establish that all six actions leave storage unchanged
during preview while reset reports its recovery window; base-only restore does
not materialize a blob; preview rejects busy, stale-revision, protected-source,
and restore-conflict cases without writes; and the fingerprint changes with its
source state while reset still checks the recovery quota.

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

`RequestBinding` is private confirmation metadata for a planned submission. It
contains a canonical UUID `plan_id` and a lowercase hexadecimal source
fingerprint; it is neither authorization nor an API token. A caller obtains the
fingerprint through `preview_planned_action`, then passes that binding to
`submit_planned_job`. Admission repeats the fingerprint calculation under the
serial lock, over the source state and current policy, before persisting the
job. A changed source, policy, or journal therefore rejects the request rather
than admitting a stale plan, even when the data revision has not changed. For
an idempotent retry, the binding must also be exact.

When a planned job is dequeued, its source-and-policy fingerprint is checked
again before it becomes running. The check excludes that job's own persisted
record, so persistence, restart recovery, and a durable `running` transition do
not invalidate the job by themselves. Any other relevant state or policy change
fails the job before activation. A planned `restore-trash` takes its protected
recovery snapshot and switches generation as part of its staged execution; its
planned preview describes those consequences without changing storage.

`planned_submission` can locate an already accepted exact request using its
actor, idempotency key, expected revision, action, and `plan_id`. This lookup is
for recovery from loss or expiry of the API's ephemeral plan, not an
authorization bypass: the API must reauthorize the actor's scope and action
before making it. With that authorization, an exact accepted retry returns the
existing job and cannot create a second one; a different plan binding or other
request detail is an idempotency error.

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
implemented, reaching that cap rejects new submissions. Public API submission,
including parity between planned and ordinary submission flows, remains pending.

## State-schema compatibility

Opening schema 1 or schema 2 state automatically migrates it to schema 3, but
migration requires quiescence: an active maintenance lease causes opening to
fail busy without rewriting the state. Schema 3 stores planned request bindings
with receipts. Older engines must reject schema 3; there is no downgrade path.
Unknown state fields are rejected rather than ignored.
