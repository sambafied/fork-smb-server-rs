# Sambafied export artifacts: candidate contract

This document describes the current source candidate contract for durable export artifacts; this document does not establish acceptance, runtime qualification, or completed API, CLI, or UI support.

## Explicit server-owned policy

New job-backed export captures require an explicit, server-owned `Policy.artifacts` configuration. `None` disables new artifact capture; the raw archive primitive remains available. Artifact TTL is independent of snapshot TTL. Actor ownership does not grant or override artifact policy.

An `ArtifactPolicy` must satisfy all of these bounds:

| Field | Required bound |
| --- | --- |
| `ttl_seconds` | `1..=315360000` |
| `count_limit` | `1..=1024` |
| `byte_limit` | Positive and no greater than `retained_bytes` |

The complete tar archive's bytes are charged against both the artifact `byte_limit` and `retained_bytes`. `temporary_bytes` governs staging; it is not a substitute for either final archive budget.

Accounting includes registered receipts and physically present archives, including unregistered orphans, using the greater recorded or physical size for each ID. Expiration does not free bytes or archive count before physical reclamation. An exact retry counts the archive matching its stable job ID once; other physical archives remain charged.

## Durable publication and authorization

The internal `Action::Export` action is represented by a durable job and a manifest artifact receipt using schema 5. The artifact's stable ID is the job UUID, so an exact retry retains the same identity.

The current actor and authorization must be checked before capture and again before publication. A previous authorization decision or actor ownership is not sufficient to authorize publication.

`Store::artifact(id, actor)` returns an actor-scoped registered receipt belonging to a succeeded job; it is not an authorization grant. `Store::open_artifact(id, actor, authorize)` checks expiry and calls the current authorization callback before verifying the archive, then checks expiry and calls the callback again before returning the verified file descriptor. Verification checks file type, size and complete SHA-256 and rewinds the descriptor. The callback must enforce current API policy. Actor ownership does not grant artifact policy or replace the current authorization check. An expired download returns `Retention`.

## Archive scope and unfinished qualification

The archive contains the upper layer only. It is not a standalone game archive.

Automatic expiry pruning, artifact deletion and physical reclamation are not implemented. Expired or unregistered physical archives remain subject to accounting until physical reclamation occurs.

API, CLI, and UI integration remain pending, as do broader process-kill and
end-to-end fault qualification. Acceptance requires evidence for the implemented contract, including durable receipt behavior, exact retries, authorization checks, physical archive accounting, and failures around capture and publication.

## Source evidence and limits

The current candidate has 62 passing core tests (49 existing plus 13 export tests) on
Windows and Linux, six passing shadow backend tests on Linux, and strict core Clippy
passes on both platforms. These are source checks, not end-to-end acceptance, a CI
result for these changes, deployment or release qualification.

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
