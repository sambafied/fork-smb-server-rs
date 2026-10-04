//! Exact-batch, externally acknowledged history archival. Never job eviction.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryCheckpoint {
    pub source_revision: u64,
    pub committed_revision: u64,
    pub actor: String,
    pub acknowledged_at: u64,
    pub batch_digest: String,
    pub event_count: usize,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryAuditBatch {
    pub schema: u32,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub revision: u64,
    pub checkpoint: Option<HistoryCheckpoint>,
    pub events: Vec<Event>,
}
impl HistoryAuditBatch {
    pub fn fingerprint(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryAcknowledgement {
    pub checkpoint: HistoryCheckpoint,
    pub replayed: bool,
}

fn batch(state: &State) -> HistoryAuditBatch {
    HistoryAuditBatch {
        schema: 1,
        identity: state.identity.clone(),
        base_digest: state.base_digest.clone(),
        generation: state.generation.clone(),
        revision: state.revision,
        checkpoint: state.history_checkpoint.clone(),
        events: state.history.clone(),
    }
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_actor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub(crate) fn validate_history_checkpoint(state: &State) -> Result<()> {
    let Some(checkpoint) = &state.history_checkpoint else {
        return if state.schema == 8 {
            Err(Error::Corrupt)
        } else {
            Ok(())
        };
    };
    if !matches!(state.schema, 8..=9)
        || checkpoint.source_revision.checked_add(1) != Some(checkpoint.committed_revision)
        || checkpoint.committed_revision > state.revision
        || !valid_actor(&checkpoint.actor)
        || !valid_digest(&checkpoint.batch_digest)
        || checkpoint
            .previous_checkpoint_digest
            .as_ref()
            .is_some_and(|v| !valid_digest(v))
        || checkpoint.event_count == 0
        || checkpoint.first_sequence == 0
        || checkpoint.first_sequence > checkpoint.last_sequence
        || checkpoint.last_sequence > checkpoint.source_revision
    {
        return Err(Error::Corrupt);
    }
    let mut previous = checkpoint.committed_revision;
    for event in &state.history {
        if event.sequence <= previous
            || event.sequence != event.revision
            || event.sequence > state.revision
        {
            return Err(Error::Corrupt);
        }
        previous = event.sequence;
    }
    Ok(())
}

impl Store {
    pub fn history_audit_batch(&self) -> Result<HistoryAuditBatch> {
        let _lease = self.lease()?;
        let operation = self.serial()?;
        Ok(batch(&operation.store.load()?))
    }

    /// The caller attests that the exact exported batch is durably archived.
    /// A checkpoint records this trust boundary; no external durability is inferred.
    pub fn acknowledge_history(
        &self,
        expected_digest: &str,
        through_revision: u64,
        actor: &str,
    ) -> Result<HistoryAcknowledgement> {
        if !valid_digest(expected_digest) || !valid_actor(actor) {
            return Err(Error::Path);
        }
        let _maintenance = self.maintenance()?;
        let operation = self.serial()?;
        let current = &operation.store;
        let mut state = current.load()?;
        if let Some(checkpoint) = &state.history_checkpoint
            && checkpoint.batch_digest == expected_digest
            && checkpoint.source_revision == through_revision
        {
            if checkpoint.actor != actor {
                return Err(Error::Idempotency);
            }
            return Ok(HistoryAcknowledgement {
                checkpoint: checkpoint.clone(),
                replayed: true,
            });
        }
        if state.revision != through_revision || batch(&state).fingerprint()? != expected_digest {
            return Err(Error::Revision);
        }
        if state
            .jobs
            .values()
            .any(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
        {
            return Err(Error::Busy);
        }
        let first = state.history.first().ok_or(Error::Path)?;
        let last = state.history.last().ok_or(Error::Path)?;
        let committed_revision = state.revision.checked_add(1).ok_or(Error::Quota)?;
        let checkpoint = HistoryCheckpoint {
            source_revision: state.revision,
            committed_revision,
            actor: actor.into(),
            acknowledged_at: now(),
            batch_digest: expected_digest.into(),
            event_count: state.history.len(),
            first_sequence: first.sequence,
            last_sequence: last.sequence,
            previous_checkpoint_digest: state
                .history_checkpoint
                .as_ref()
                .map(|value| serde_json::to_vec(value).map(|bytes| digest(&bytes)))
                .transpose()?,
        };
        // Trash display provenance used to depend on the pending delete event.
        // Retain known provenance before removing the acknowledged source events.
        for trash in state.trash.values_mut() {
            if trash.generation.is_none() {
                trash.generation = state
                    .history
                    .iter()
                    .find(|event| {
                        event.operation == "delete"
                            && event.object_id.as_deref() == Some(trash.id.as_str())
                    })
                    .map(|event| event.generation.clone());
            }
        }
        state.schema = state.schema.max(8);
        state.revision = committed_revision;
        state.history.clear();
        state.history_checkpoint = Some(checkpoint.clone());
        validate_history_checkpoint(&state)?;
        current.save(&state)?;
        Ok(HistoryAcknowledgement {
            checkpoint,
            replayed: false,
        })
    }
}
