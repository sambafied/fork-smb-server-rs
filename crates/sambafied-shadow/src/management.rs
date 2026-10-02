//! Durable management receipts share the data manifest's atomic publication.
//! Callers must authorize requests and validate destructive previews before
//! submission. These storage primitives are not a public management API.
use super::*;

const JOB_LIMIT: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Snapshot,
    Reset,
    Rollback { snapshot_id: String },
    RestoreTrash { trash_id: String },
    PurgeTrash { trash_id: String },
    DeleteSnapshot { snapshot_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    pub revision: u64,
    pub generation: String,
    pub snapshot_id: Option<String>,
    pub recovery_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub actor: String,
    /// Hash only; raw caller keys are never written to disk.
    pub key_digest: String,
    pub expected_revision: u64,
    pub action: Action,
    pub status: JobStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub result: Option<JobResult>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Submission {
    pub job: Job,
    pub replayed: bool,
}

/// Pure preflight evidence, not authorization or a promise of execution.
/// The API must bind this to its actor/resource/expiry and recheck on submission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionImpact {
    pub revision: u64,
    pub generation: String,
    pub base_version: String,
    pub fingerprint: String,
    pub action: Action,
    pub affected_entries: usize,
    pub active_bytes_after: u64,
    pub retained_bytes_after: u64,
    pub snapshots_after: usize,
    pub trash_after: usize,
    pub recovery_retention_seconds: Option<u64>,
    pub physical_reclamation_deferred: bool,
}

impl Action {
    fn validate(&self) -> Result<()> {
        let source = match self {
            Self::Snapshot | Self::Reset => return Ok(()),
            Self::Rollback { snapshot_id } | Self::DeleteSnapshot { snapshot_id } => snapshot_id,
            Self::RestoreTrash { trash_id } | Self::PurgeTrash { trash_id } => trash_id,
        };
        if Uuid::parse_str(source).is_err() {
            return Err(Error::Path);
        }
        Ok(())
    }
}

impl Store {
    /// Validate the exact operation against a quiescent, revision-bound state.
    /// No blob, receipt, history or manifest is written. Busy is a blocker;
    /// execution must acquire its own gate and validate all preconditions again.
    pub fn preview_action(
        &self,
        expected: u64,
        actor: &str,
        action: Action,
    ) -> Result<ActionImpact> {
        if actor.is_empty() || actor.len() > 256 {
            return Err(Error::Path);
        }
        action.validate()?;
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let original = self.load()?;
        self.revision(&original, expected)?;
        let fingerprint = digest(&serde_json::to_vec(&(&original, &self.config.policy))?);
        let mut staged = original.clone();
        match &action {
            Action::Snapshot => {
                self.snapshot_locked(&mut staged, actor)?;
            }
            Action::Reset => {
                self.reset_locked(&mut staged, actor)?;
            }
            Action::Rollback { snapshot_id } => {
                self.rollback_locked(&mut staged, snapshot_id, actor)?;
            }
            Action::RestoreTrash { trash_id } => {
                self.restore_trash_prepared(&mut staged, trash_id, actor, false)?;
            }
            Action::PurgeTrash { trash_id } => {
                self.purge_trash_locked(&mut staged, trash_id, actor)?;
            }
            Action::DeleteSnapshot { snapshot_id } => {
                self.delete_snapshot_locked(&mut staged, snapshot_id, actor)?;
            }
        }
        self.check_budget(&staged)?;
        let paths: BTreeSet<_> = self
            .base
            .keys()
            .chain(original.view.upper.keys())
            .chain(staged.view.upper.keys())
            .collect();
        let affected_entries = paths
            .iter()
            .filter(|path| self.lookup(&original.view, path) != self.lookup(&staged.view, path))
            .count();
        let active_bytes_after = staged.view.upper.values().map(|e| e.size).sum();
        let retained_bytes_after = staged
            .snapshots
            .values()
            .flat_map(|s| s.view.upper.values())
            .map(|e| e.size)
            .chain(
                staged
                    .trash
                    .values()
                    .filter(|t| t.from_upper)
                    .map(|t| t.entry.size),
            )
            .sum();
        Ok(ActionImpact {
            revision: original.revision,
            generation: original.generation,
            base_version: original.identity.base_version,
            fingerprint,
            recovery_retention_seconds: matches!(action, Action::Reset | Action::Rollback { .. })
                .then_some(self.config.policy.recovery_protection_seconds),
            physical_reclamation_deferred: matches!(
                action,
                Action::PurgeTrash { .. } | Action::DeleteSnapshot { .. }
            ),
            action,
            affected_entries,
            active_bytes_after,
            retained_bytes_after,
            snapshots_after: staged.snapshots.len(),
            trash_after: staged.trash.len(),
        })
    }
    /// Submit only after API authorization and preview validation. Matching
    /// retries return the same receipt even after its data revision advanced.
    pub fn submit_job(
        &self,
        expected: u64,
        actor: &str,
        key: &str,
        action: Action,
    ) -> Result<Submission> {
        if actor.is_empty() || actor.len() > 256 || key.is_empty() || key.len() > 256 {
            return Err(Error::Path);
        }
        action.validate()?;
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        let key_digest = digest(key.as_bytes());
        if let Some(job) = state
            .jobs
            .values()
            .find(|j| j.actor == actor && j.key_digest == key_digest)
        {
            if job.expected_revision != expected || job.action != action {
                return Err(Error::Idempotency);
            }
            return Ok(Submission {
                job: job.clone(),
                replayed: true,
            });
        }
        self.revision(&state, expected)?;
        if state.jobs.len() >= JOB_LIMIT {
            return Err(Error::Quota);
        }
        let at = now();
        let job = Job {
            id: id(),
            actor: actor.into(),
            key_digest,
            expected_revision: expected,
            action,
            status: JobStatus::Queued,
            created_at: at,
            updated_at: at,
            result: None,
            error_code: None,
        };
        state.jobs.insert(job.id.clone(), job.clone());
        self.save(&state)?;
        Ok(Submission {
            job,
            replayed: false,
        })
    }

    /// Actor scoping is mandatory even when a job id is known. Administrative
    /// lookup requires the caller to explicitly authorize that actor's scope.
    pub fn job(&self, job_id: &str, actor: &str) -> Result<Job> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        self.load()?
            .jobs
            .get(job_id)
            .filter(|j| j.actor == actor)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Recheck current authorization before staging and before activation.
    /// The callback must not reenter storage or wait on asynchronous work.
    /// Busy jobs remain queued/running for a later retry; no handle is forced
    /// closed. Success and its data/history are published in the same write.
    pub fn execute_job<F>(&self, job_id: &str, actor: &str, mut authorize: F) -> Result<Job>
    where
        F: FnMut(&Job) -> Result<()>,
    {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut original = self.load()?;
        let mut job = original
            .jobs
            .get(job_id)
            .filter(|j| j.actor == actor)
            .cloned()
            .ok_or(Error::NotFound)?;
        // Even terminal results require fresh authorization.
        let allowed = authorize(&job);
        if matches!(job.status, JobStatus::Succeeded | JobStatus::Failed) {
            allowed?;
            return Ok(job);
        }
        let operation = (|| {
            allowed?;
            self.revision(&original, job.expected_revision)?;
            job.status = JobStatus::Running;
            job.updated_at = now();
            original.jobs.insert(job.id.clone(), job.clone());
            self.save(&original)?;
            let mut staged = original.clone();
            let history_start = staged.history.len();
            let mut result = JobResult {
                revision: staged.revision,
                generation: staged.generation.clone(),
                snapshot_id: None,
                recovery_snapshot_id: None,
            };
            match &job.action {
                Action::Snapshot => {
                    result.snapshot_id = Some(self.snapshot_locked(&mut staged, actor)?)
                }
                Action::Reset => {
                    result.recovery_snapshot_id = Some(self.reset_locked(&mut staged, actor)?)
                }
                Action::Rollback { snapshot_id } => {
                    result.recovery_snapshot_id =
                        Some(self.rollback_locked(&mut staged, snapshot_id, actor)?)
                }
                Action::RestoreTrash { trash_id } => {
                    self.restore_trash_locked(&mut staged, trash_id, actor)?
                }
                Action::PurgeTrash { trash_id } => {
                    self.purge_trash_locked(&mut staged, trash_id, actor)?
                }
                Action::DeleteSnapshot { snapshot_id } => {
                    self.delete_snapshot_locked(&mut staged, snapshot_id, actor)?
                }
            }
            authorize(&job)?;
            result.revision = staged.revision;
            result.generation = staged.generation.clone();
            for event in &mut staged.history[history_start..] {
                event.job_id = Some(job.id.clone());
            }
            let mut completed = job.clone();
            completed.status = JobStatus::Succeeded;
            completed.updated_at = now();
            completed.result = Some(result);
            staged.jobs.insert(completed.id.clone(), completed.clone());
            self.save(&staged)?;
            Ok(completed)
        })();
        match operation {
            Ok(completed) => Ok(completed),
            Err(error) => {
                // A publication may succeed before directory sync reports an
                // I/O failure. Never overwrite an already committed success.
                let current = self.load()?;
                if let Some(committed) = current
                    .jobs
                    .get(job_id)
                    .filter(|j| j.status == JobStatus::Succeeded)
                {
                    return Ok(committed.clone());
                }
                job.status = JobStatus::Failed;
                job.updated_at = now();
                job.error_code = Some(error_code(&error).into());
                original.jobs.insert(job.id.clone(), job.clone());
                self.save(&original)?;
                Ok(job)
            }
        }
    }
}

fn error_code(error: &Error) -> &'static str {
    match error {
        Error::Denied => "denied",
        Error::Revision => "revision-changed",
        Error::NotFound => "not-found",
        Error::Exists => "conflict",
        Error::Quota => "quota",
        Error::Retention => "retention",
        Error::Corrupt | Error::Json(_) => "corrupt",
        Error::Busy => "busy",
        Error::Io(_) => "storage-unavailable",
        _ => "invalid-operation",
    }
}
