//! Durable management receipts share the data manifest's atomic publication.
//! Callers must authorize requests and validate destructive previews before
//! submission. These storage primitives are not a public management API.
use super::*;

const JOB_LIMIT: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    ExpireRetained {
        expired_before: u64,
    },
    Snapshot,
    Export,
    Reset,
    Rollback {
        snapshot_id: String,
    },
    RestoreTrash {
        trash_id: String,
    },
    PurgeTrash {
        trash_id: String,
    },
    DeleteSnapshot {
        snapshot_id: String,
    },
    Backup {
        destination_id: String,
    },
    RestoreBackup {
        destination_id: String,
        backup_id: String,
    },
    DeleteBackup {
        destination_id: String,
        backup_id: String,
    },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionJobResult>,
    pub revision: u64,
    pub generation: String,
    pub snapshot_id: Option<String>,
    pub recovery_snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_binding: Option<RequestBinding>,
}

/// Private confirmation metadata, not authorization or an API token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    pub plan_id: String,
    pub source_fingerprint: String,
}
impl RequestBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        if Uuid::parse_str(&self.plan_id)
            .map_err(|_| Error::Path)?
            .to_string()
            != self.plan_id
            || self.source_fingerprint.len() != 64
            || !self
                .source_fingerprint
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::Path);
        }
        Ok(())
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<ExpiryPreview>,
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
    pub backups_after: usize,
    pub recovery_retention_seconds: Option<u64>,
    pub physical_reclamation_deferred: bool,
}

impl Action {
    fn validate(&self) -> Result<()> {
        if let Self::ExpireRetained { expired_before } = self {
            return if *expired_before <= now() {
                Ok(())
            } else {
                Err(Error::Path)
            };
        }
        match self {
            Self::Backup { destination_id }
            | Self::RestoreBackup { destination_id, .. }
            | Self::DeleteBackup { destination_id, .. }
                if !super::backup_jobs::destination_id(destination_id) =>
            {
                return Err(Error::Path);
            }
            _ => {}
        }
        let source = match self {
            Self::Snapshot
            | Self::Export
            | Self::Reset
            | Self::Backup { .. }
            | Self::ExpireRetained { .. } => return Ok(()),
            Self::Rollback { snapshot_id } | Self::DeleteSnapshot { snapshot_id } => snapshot_id,
            Self::RestoreTrash { trash_id } | Self::PurgeTrash { trash_id } => trash_id,
            Self::RestoreBackup { backup_id, .. } | Self::DeleteBackup { backup_id, .. } => {
                backup_id
            }
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
        self.preview_inner(expected, actor, action, false, &BackupCatalog::new())
    }
    pub fn preview_planned_action(
        &self,
        expected: u64,
        actor: &str,
        action: Action,
    ) -> Result<ActionImpact> {
        self.preview_inner(expected, actor, action, true, &BackupCatalog::new())
    }
    pub fn preview_planned_action_with_backups(
        &self,
        expected: u64,
        actor: &str,
        action: Action,
        catalog: &BackupCatalog,
    ) -> Result<ActionImpact> {
        self.preview_inner(expected, actor, action, true, catalog)
    }
    fn preview_inner(
        &self,
        expected: u64,
        actor: &str,
        action: Action,
        planned: bool,
        catalog: &BackupCatalog,
    ) -> Result<ActionImpact> {
        if actor.is_empty() || actor.len() > 256 {
            return Err(Error::Path);
        }
        action.validate()?;
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let original = current.load()?;
        current.revision(&original, expected)?;
        let fingerprint = current.action_fingerprint(&original, catalog, &action, None)?;
        let mut staged = original.clone();
        let mut retention = None;
        match &action {
            Action::ExpireRetained { expired_before } => {
                retention =
                    Some(current.expire_locked(&mut staged, actor, *expired_before, None)?);
                current.event(&mut staged, actor, "expire-retained", None, None)?;
            }
            Action::Export => {
                let capture = current.prepare_artifact(&staged, &id(), actor, now())?;
                staged
                    .artifacts
                    .insert(capture.artifact.id.clone(), capture.artifact.clone());
                current.event(
                    &mut staged,
                    actor,
                    "export",
                    None,
                    Some(capture.artifact.id),
                )?;
            }
            Action::Snapshot => {
                current.snapshot_locked(&mut staged, actor)?;
            }
            Action::Reset => {
                current.reset_locked(&mut staged, actor)?;
            }
            Action::Rollback { snapshot_id } => {
                current.rollback_locked(&mut staged, snapshot_id, actor)?;
            }
            Action::RestoreTrash { trash_id } => {
                if planned {
                    current.retain(&mut staged, true)?;
                    staged.generation = id();
                }
                current.restore_trash_prepared(&mut staged, trash_id, actor, false)?;
            }
            Action::PurgeTrash { trash_id } => {
                current.purge_trash_locked(&mut staged, trash_id, actor)?;
            }
            Action::DeleteSnapshot { snapshot_id } => {
                current.delete_snapshot_locked(&mut staged, snapshot_id, actor)?;
            }
            Action::Backup { destination_id } => {
                let capture = current.prepare_capture(
                    &staged,
                    current.destination(catalog, destination_id)?,
                    &id(),
                    now(),
                )?;
                staged
                    .backups
                    .insert(capture.backup.id.clone(), capture.backup.clone());
                current.event(&mut staged, actor, "backup", None, Some(capture.backup.id))?;
            }
            Action::RestoreBackup {
                destination_id,
                backup_id,
            } => {
                current.restore_backup_prepared(
                    &mut staged,
                    current.destination(catalog, destination_id)?,
                    backup_id,
                    actor,
                    false,
                )?;
            }
            Action::DeleteBackup {
                destination_id,
                backup_id,
            } => {
                let destination = current.destination(catalog, destination_id)?;
                let backup = current.backup_manifest(destination, backup_id)?;
                current.check_deletion_budget(destination, &backup, &id())?;
                staged.backups.remove(backup_id);
                current.event(
                    &mut staged,
                    actor,
                    "delete-backup",
                    None,
                    Some(backup_id.clone()),
                )?;
            }
        }
        current.check_budget(&staged)?;
        let paths: BTreeSet<_> = current
            .base
            .keys()
            .chain(original.view.upper.keys())
            .chain(staged.view.upper.keys())
            .collect();
        let affected_entries = paths
            .iter()
            .filter(|path| {
                current.lookup(&original.view, path) != current.lookup(&staged.view, path)
            })
            .count();
        let active_bytes_after = staged.view.upper.values().map(|e| e.size).sum();
        let retained_bytes_after: u64 = staged
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
        let retained_bytes_after =
            retained_bytes_after + current.artifact_usage(&staged)?.values().sum::<u64>();
        Ok(ActionImpact {
            retention,
            revision: original.revision,
            generation: original.generation,
            base_version: original.identity.base_version,
            fingerprint,
            recovery_retention_seconds: (matches!(
                action,
                Action::Reset | Action::Rollback { .. } | Action::RestoreBackup { .. }
            ) || (planned
                && matches!(action, Action::RestoreTrash { .. })))
            .then_some(current.config.policy.recovery_protection_seconds),
            physical_reclamation_deferred: matches!(
                action,
                Action::PurgeTrash { .. }
                    | Action::ExpireRetained { .. }
                    | Action::DeleteSnapshot { .. }
                    | Action::DeleteBackup { .. }
            ),
            action,
            affected_entries,
            active_bytes_after,
            retained_bytes_after,
            snapshots_after: staged.snapshots.len(),
            trash_after: staged.trash.len(),
            backups_after: staged.backups.len(),
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
        self.submit_inner(expected, actor, key, action, None, &BackupCatalog::new())
    }
    /// Check source under the serial lock to close the preview/admission race.
    pub fn submit_planned_job(
        &self,
        expected: u64,
        actor: &str,
        key: &str,
        action: Action,
        binding: RequestBinding,
    ) -> Result<Submission> {
        binding.validate()?;
        self.submit_inner(
            expected,
            actor,
            key,
            action,
            Some(binding),
            &BackupCatalog::new(),
        )
    }
    pub fn submit_planned_job_with_backups(
        &self,
        expected: u64,
        actor: &str,
        key: &str,
        action: Action,
        binding: RequestBinding,
        catalog: &BackupCatalog,
    ) -> Result<Submission> {
        binding.validate()?;
        self.submit_inner(expected, actor, key, action, Some(binding), catalog)
    }
    fn submit_inner(
        &self,
        expected: u64,
        actor: &str,
        key: &str,
        action: Action,
        binding: Option<RequestBinding>,
        catalog: &BackupCatalog,
    ) -> Result<Submission> {
        if actor.is_empty() || actor.len() > 256 || key.is_empty() || key.len() > 256 {
            return Err(Error::Path);
        }
        action.validate()?;
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let mut state = current.load()?;
        let key_digest = digest(key.as_bytes());
        if let Some(job) = state
            .jobs
            .values()
            .find(|j| j.actor == actor && j.key_digest == key_digest)
        {
            if job.expected_revision != expected
                || job.action != action
                || job.request_binding != binding
            {
                return Err(Error::Idempotency);
            }
            return Ok(Submission {
                job: job.clone(),
                replayed: true,
            });
        }
        current.revision(&state, expected)?;
        if state.jobs.values().any(|job| {
            matches!(job.action, Action::ExpireRetained { .. })
                && matches!(job.status, JobStatus::Queued | JobStatus::Running)
        }) {
            return Err(Error::Busy);
        }
        if let Some(binding) = &binding
            && current.action_fingerprint(&state, catalog, &action, None)?
                != binding.source_fingerprint
        {
            return Err(Error::Revision);
        }
        if state.jobs.len() >= JOB_LIMIT {
            return Err(Error::Quota);
        }
        let at = now();
        if matches!(action, Action::ExpireRetained { .. }) {
            // Reject concurrent accepted work before creating another durable job.
            if state
                .jobs
                .values()
                .any(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
            {
                return Err(Error::Busy);
            }
            state.schema = 6;
        }
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
            request_binding: binding,
        };
        state.jobs.insert(job.id.clone(), job.clone());
        current.save(&state)?;
        Ok(Submission {
            job,
            replayed: false,
        })
    }

    /// Locate an accepted exact request before requiring an ephemeral plan.
    /// The API must reauthorize scope/action first. Expiry or restart cannot
    /// cause an accepted retry to create another job.
    pub fn planned_submission(
        &self,
        expected: u64,
        actor: &str,
        key: &str,
        action: &Action,
        plan_id: &str,
    ) -> Result<Option<Job>> {
        if actor.is_empty()
            || actor.len() > 256
            || key.is_empty()
            || key.len() > 256
            || Uuid::parse_str(plan_id).is_err()
        {
            return Err(Error::Path);
        }
        action.validate()?;
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let state = current.load()?;
        let key_digest = digest(key.as_bytes());
        let Some(job) = state
            .jobs
            .values()
            .find(|job| job.actor == actor && job.key_digest == key_digest)
        else {
            return Ok(None);
        };
        if job.expected_revision != expected
            || job.action != *action
            || !job
                .request_binding
                .as_ref()
                .is_some_and(|binding| binding.plan_id == plan_id)
        {
            return Err(Error::Idempotency);
        }
        Ok(Some(job.clone()))
    }

    /// Actor scoping is mandatory even when a job id is known. Administrative
    /// lookup requires the caller to explicitly authorize that actor's scope.
    pub fn job(&self, job_id: &str, actor: &str) -> Result<Job> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        current
            .load()?
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
        self.execute_job_with_backups(job_id, actor, &BackupCatalog::new(), &mut authorize)
    }
    pub fn execute_job_with_backups<F>(
        &self,
        job_id: &str,
        actor: &str,
        catalog: &BackupCatalog,
        mut authorize: F,
    ) -> Result<Job>
    where
        F: FnMut(&Job) -> Result<()>,
    {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let mut original = current.load()?;
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
        // A restarted Running job may have published externally before its
        // local receipt committed. Keep that uncertainty resumable, including
        // when fresh authorization or configuration checks reject this retry.
        let mut external_started = job.status == JobStatus::Running
            && matches!(
                job.action,
                Action::Backup { .. } | Action::DeleteBackup { .. } | Action::Export
            );
        let operation = (|| {
            allowed?;
            current.revision(&original, job.expected_revision)?;
            if let Some(binding) = &job.request_binding {
                let mut source = original.clone();
                source.jobs.remove(job_id);
                if current.action_fingerprint(&source, catalog, &job.action, Some(job_id))?
                    != binding.source_fingerprint
                {
                    return Err(Error::Revision);
                }
            }
            job.status = JobStatus::Running;
            job.updated_at = now();
            original.jobs.insert(job.id.clone(), job.clone());
            current.save(&original)?;
            let mut staged = original.clone();
            let history_start = staged.history.len();
            let mut result = JobResult {
                retention: None,
                revision: staged.revision,
                generation: staged.generation.clone(),
                snapshot_id: None,
                recovery_snapshot_id: None,
                backup_id: None,
                artifact_id: None,
            };
            let mut capture = None;
            let mut deletion = None;
            let mut export = None;
            match &job.action {
                Action::ExpireRetained { expired_before } => {
                    let expired =
                        current.expire_locked(&mut staged, actor, *expired_before, Some(job_id))?;
                    let usage = current.storage_usage_locked(&staged, now())?;
                    result.retention = Some(RetentionJobResult {
                        expired_before: *expired_before,
                        snapshots: expired.snapshots,
                        trash: expired.trash,
                        retained_bytes_after: usage.retained_charged_bytes,
                        reclaimed_bytes: 0,
                        deferred_blob_bytes: usage.blob_unreferenced_bytes,
                        physical_reclamation_deferred: usage.blob_unreferenced_count > 0
                            || usage.artifact_orphan_count > 0
                            || usage.expired_artifact_count > 0
                            || usage.expired_snapshot_count > 0
                            || usage.expired_trash_count > 0,
                    });
                    // Even an empty sweep has one committed completion event.
                    current.event(
                        &mut staged,
                        actor,
                        "expire-retained",
                        None,
                        Some(job.id.clone()),
                    )?;
                }
                Action::Export => {
                    let capture =
                        current.prepare_artifact(&staged, &job.id, actor, job.created_at)?;
                    result.artifact_id = Some(capture.artifact.id.clone());
                    staged
                        .artifacts
                        .insert(capture.artifact.id.clone(), capture.artifact.clone());
                    current.event(
                        &mut staged,
                        actor,
                        "export",
                        None,
                        Some(capture.artifact.id.clone()),
                    )?;
                    export = Some(capture);
                }
                Action::Snapshot => {
                    result.snapshot_id = Some(current.snapshot_locked(&mut staged, actor)?)
                }
                Action::Reset => {
                    result.recovery_snapshot_id = Some(current.reset_locked(&mut staged, actor)?)
                }
                Action::Rollback { snapshot_id } => {
                    result.recovery_snapshot_id =
                        Some(current.rollback_locked(&mut staged, snapshot_id, actor)?)
                }
                Action::RestoreTrash { trash_id } => {
                    if job.request_binding.is_some() {
                        result.recovery_snapshot_id = Some(current.retain(&mut staged, true)?);
                        staged.generation = id();
                    }
                    current.restore_trash_locked(&mut staged, trash_id, actor)?
                }
                Action::PurgeTrash { trash_id } => {
                    current.purge_trash_locked(&mut staged, trash_id, actor)?
                }
                Action::DeleteSnapshot { snapshot_id } => {
                    current.delete_snapshot_locked(&mut staged, snapshot_id, actor)?
                }
                Action::Backup { destination_id } => {
                    let prepared = current.prepare_capture(
                        &staged,
                        current.destination(catalog, destination_id)?,
                        &job.id,
                        job.created_at,
                    )?;
                    result.backup_id = Some(prepared.backup.id.clone());
                    staged
                        .backups
                        .insert(prepared.backup.id.clone(), prepared.backup.clone());
                    current.event(
                        &mut staged,
                        actor,
                        "backup",
                        None,
                        Some(prepared.backup.id.clone()),
                    )?;
                    capture = Some(prepared);
                }
                Action::RestoreBackup {
                    destination_id,
                    backup_id,
                } => {
                    result.backup_id = Some(backup_id.clone());
                    result.recovery_snapshot_id = Some(current.restore_backup_prepared(
                        &mut staged,
                        current.destination(catalog, destination_id)?,
                        backup_id,
                        actor,
                        true,
                    )?);
                }
                Action::DeleteBackup {
                    destination_id,
                    backup_id,
                } => {
                    let backup = current.backup_manifest_for_job(
                        current.destination(catalog, destination_id)?,
                        backup_id,
                        Some(job_id),
                    )?;
                    current.check_deletion_budget(
                        current.destination(catalog, destination_id)?,
                        &backup,
                        job_id,
                    )?;
                    staged.backups.remove(backup_id);
                    current.event(
                        &mut staged,
                        actor,
                        "delete-backup",
                        None,
                        Some(backup_id.clone()),
                    )?;
                    result.backup_id = Some(backup_id.clone());
                    deletion = Some((destination_id.clone(), backup));
                }
            }
            current.check_budget(&staged)?;
            authorize(&job)?;
            if let Some(export) = &export {
                external_started = true;
                current.publish_artifact(export)?;
            }
            if let Some(capture) = &capture {
                external_started = true;
                current.publish_capture(capture)?;
            }
            if let Some((destination_id, backup)) = &deletion {
                external_started = true;
                current.publish_backup_deletion(
                    current.destination(catalog, destination_id)?,
                    backup,
                    job_id,
                )?;
            }
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
            current.save(&staged)?;
            Ok(completed)
        })();
        match operation {
            Ok(completed) => Ok(completed),
            Err(error) => {
                // A publication may succeed before directory sync reports an
                // I/O failure. Never overwrite an already committed success.
                let committed_state = current.load()?;
                if let Some(committed) = committed_state
                    .jobs
                    .get(job_id)
                    .filter(|j| j.status == JobStatus::Succeeded)
                {
                    return Ok(committed.clone());
                }
                // A durable external publication must remain resumable under
                // this job ID, rather than become a terminal failed receipt.
                if external_started {
                    return Err(error);
                }
                job.status = JobStatus::Failed;
                job.updated_at = now();
                job.error_code = Some(error_code(&error).into());
                original.jobs.insert(job.id.clone(), job.clone());
                current.save(&original)?;
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
