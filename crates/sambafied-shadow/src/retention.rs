//! Retained-object expiry is a manifest transaction, never cache eviction.
//! Callers supply current scoped authority; these are storage primitives only.
use super::*;

/// Physical usage and temporal counts observed under the same manifest lease.
#[derive(Debug, Clone)]
pub struct StorageObservation {
    pub observed_at: u64,
    pub usage: StorageUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageUsage {
    pub active_bytes: u64,
    pub active_files: usize,
    /// Logical retained references, including unavailable/expired artifacts.
    pub retained_bytes: u64,
    /// Admission accounting additionally charges unpublished/orphan archives.
    pub retained_charged_bytes: u64,
    pub receipt_archive_bytes: u64,
    pub receipt_physical_bytes: u64,
    pub receipt_orphan_bytes: u64,
    pub archived_job_count: u64,
    pub expired_snapshot_count: usize,
    pub expired_trash_count: usize,
    pub expired_artifact_count: usize,
    pub retired_artifact_count: usize,
    pub retired_artifact_physical_count: usize,
    pub retired_artifact_physical_bytes: u64,
    pub protected_snapshot_count: usize,
    pub unresolved_job_count: usize,
    /// Physical payload sizes, excluding manifests, locks and external backups.
    pub blob_physical_bytes: u64,
    pub blob_referenced_bytes: u64,
    pub blob_unreferenced_bytes: u64,
    pub blob_unreferenced_count: usize,
    pub artifact_physical_bytes: u64,
    pub artifact_orphan_bytes: u64,
    pub artifact_orphan_count: usize,
    pub artifact_missing_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpiryPreview {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    pub revision: u64,
    pub generation: String,
    pub observed_at: u64,
    pub snapshots: Vec<String>,
    pub trash: Vec<String>,
    pub usage: StorageUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpiryResult {
    pub revision: u64,
    pub generation: String,
    pub snapshots: Vec<String>,
    pub trash: Vec<String>,
    pub usage_before: StorageUsage,
    /// None means logical expiry committed but physical observation failed.
    pub usage_after: Option<StorageUsage>,
    pub physical_reclamation_deferred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionJobResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    pub expired_before: u64,
    pub snapshots: Vec<String>,
    pub trash: Vec<String>,
    pub retained_bytes_after: u64,
    /// The durable receipt is published before collection; credit no freed bytes.
    pub reclaimed_bytes: u64,
    pub deferred_blob_bytes: u64,
    pub physical_reclamation_deferred: bool,
}

fn total(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |sum, value| {
        sum.checked_add(value).ok_or(Error::Quota)
    })
}

impl Store {
    pub(crate) fn storage_usage_locked(&self, state: &State, at: u64) -> Result<StorageUsage> {
        let active_bytes = total(state.view.upper.values().map(|entry| entry.size))?;
        let retained_bytes = total(
            state
                .snapshots
                .values()
                .flat_map(|snapshot| snapshot.view.upper.values())
                .map(|entry| entry.size)
                .chain(
                    state
                        .trash
                        .values()
                        .filter(|trash| trash.from_upper)
                        .map(|trash| trash.entry.size),
                )
                .chain(
                    state
                        .artifacts
                        .values()
                        .filter(|a| a.retirement.is_none())
                        .map(|artifact| artifact.bytes),
                ),
        )?;
        let receipt_archive_bytes = state.receipt_archive.as_ref().map_or(0, |r| r.total_bytes);
        let receipt_physical_bytes = self.receipt_physical_bytes()?;
        let retained_bytes = retained_bytes
            .checked_add(receipt_archive_bytes)
            .ok_or(Error::Quota)?;
        let receipt_orphan_bytes = receipt_physical_bytes.saturating_sub(receipt_archive_bytes);
        let referenced: BTreeSet<_> = state
            .view
            .upper
            .values()
            .chain(state.snapshots.values().flat_map(|s| s.view.upper.values()))
            .chain(
                state
                    .trash
                    .values()
                    .filter(|t| t.from_upper)
                    .map(|t| &t.entry),
            )
            .filter_map(|entry| entry.digest.as_ref())
            .cloned()
            .collect();
        let blobs = self.namespace.join("blobs");
        let metadata = fs::symlink_metadata(&blobs)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Corrupt);
        }
        let blob_physical_bytes = tree_bytes(&blobs)?;
        let blob_unreferenced_count = fs::read_dir(&blobs)?.try_fold(0usize, |count, entry| {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Corrupt)?;
            if referenced.contains(&name) {
                Ok(count)
            } else {
                count.checked_add(1).ok_or(Error::Quota)
            }
        })?;
        let blob_referenced_bytes = total(
            referenced
                .iter()
                .map(|hash| {
                    let metadata = fs::symlink_metadata(self.blob_path(hash)?)?;
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        return Err(Error::Corrupt);
                    }
                    Ok(metadata.len())
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
        let physical_artifacts = self.physical_artifacts()?;
        let registered_artifacts = total(
            state
                .artifacts
                .values()
                .filter(|a| a.retirement.is_none())
                .map(|artifact| artifact.bytes),
        )?;
        let charged_artifacts = total(self.artifact_usage(state)?.values().copied())?;
        let retained_charged_bytes = retained_bytes
            .checked_sub(registered_artifacts)
            .and_then(|n| n.checked_add(charged_artifacts))
            .and_then(|n| n.checked_add(receipt_orphan_bytes))
            .ok_or(Error::Quota)?;
        Ok(StorageUsage {
            receipt_archive_bytes,
            receipt_physical_bytes,
            receipt_orphan_bytes,
            archived_job_count: state.receipt_archive.as_ref().map_or(0, |r| r.total_jobs),
            active_bytes,
            active_files: state.view.upper.len(),
            retained_bytes,
            retained_charged_bytes,
            expired_snapshot_count: state
                .snapshots
                .values()
                .filter(|s| s.expires_at <= at)
                .count(),
            expired_trash_count: state.trash.values().filter(|t| t.expires_at <= at).count(),
            expired_artifact_count: state
                .artifacts
                .values()
                .filter(|a| a.retirement.is_none() && a.expires_at <= at)
                .count(),
            retired_artifact_count: state
                .artifacts
                .values()
                .filter(|a| a.retirement.is_some())
                .count(),
            retired_artifact_physical_count: physical_artifacts
                .keys()
                .filter(|id| {
                    state
                        .artifacts
                        .get(*id)
                        .is_some_and(|a| a.retirement.is_some())
                })
                .count(),
            retired_artifact_physical_bytes: total(
                physical_artifacts
                    .iter()
                    .filter(|(id, _)| {
                        state
                            .artifacts
                            .get(*id)
                            .is_some_and(|a| a.retirement.is_some())
                    })
                    .map(|(_, bytes)| *bytes),
            )?,
            protected_snapshot_count: state
                .snapshots
                .values()
                .filter(|s| s.protected_until > at)
                .count(),
            unresolved_job_count: state
                .jobs
                .values()
                .filter(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
                .count(),
            blob_physical_bytes,
            blob_referenced_bytes,
            blob_unreferenced_bytes: blob_physical_bytes
                .checked_sub(blob_referenced_bytes)
                .ok_or(Error::Corrupt)?,
            blob_unreferenced_count,
            artifact_physical_bytes: total(physical_artifacts.values().copied())?,
            artifact_orphan_bytes: total(
                physical_artifacts
                    .iter()
                    .filter(|(id, _)| !state.artifacts.contains_key(*id))
                    .map(|(_, bytes)| *bytes),
            )?,
            artifact_orphan_count: physical_artifacts
                .keys()
                .filter(|id| !state.artifacts.contains_key(*id))
                .count(),
            artifact_missing_count: state
                .artifacts
                .iter()
                .filter(|(id, artifact)| {
                    artifact.retirement.is_none() && !physical_artifacts.contains_key(*id)
                })
                .count(),
        })
    }

    /// Read one policy/data/physical view without pruning or changing revision.
    pub fn storage_usage(&self) -> Result<StorageUsage> {
        let _lease = self.lease()?;
        let operation = self.serial()?;
        let current = &operation.store;
        current.storage_usage_locked(&current.load()?, now())
    }

    pub(crate) fn expiry_preview_locked(&self, state: &State, at: u64) -> Result<ExpiryPreview> {
        if at > now() {
            return Err(Error::Path);
        }
        // Every accepted job is revision-bound. Advancing that revision during
        // cleanup would invalidate even an unrelated accepted exact replay.
        if state
            .jobs
            .values()
            .any(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
        {
            return Err(Error::Busy);
        }
        if state
            .snapshots
            .iter()
            .any(|(key, record)| key != &record.id)
            || state.trash.iter().any(|(key, record)| key != &record.id)
        {
            return Err(Error::Corrupt);
        }
        Ok(ExpiryPreview {
            artifacts: vec![],
            revision: state.revision,
            generation: state.generation.clone(),
            observed_at: at,
            snapshots: state
                .snapshots
                .values()
                .filter(|s| s.expires_at <= at && s.protected_until <= at)
                .map(|s| s.id.clone())
                .collect(),
            trash: state
                .trash
                .values()
                .filter(|t| t.expires_at <= at)
                .map(|t| t.id.clone())
                .collect(),
            usage: self.storage_usage_locked(state, at)?,
        })
    }

    pub(crate) fn expire_locked(
        &self,
        state: &mut State,
        actor: &str,
        cutoff: u64,
        own_job: Option<&str>,
    ) -> Result<ExpiryPreview> {
        let mut source = state.clone();
        if let Some(job) = own_job {
            source.jobs.remove(job);
        }
        let preview = self.expiry_preview_locked(&source, cutoff)?;
        if state
            .history
            .len()
            .checked_add(preview.snapshots.len())
            .and_then(|n| n.checked_add(preview.trash.len()))
            .is_none_or(|n| n > self.config.policy.history_limit)
        {
            return Err(Error::Quota);
        }
        for snapshot in &preview.snapshots {
            state.snapshots.remove(snapshot).ok_or(Error::Corrupt)?;
            self.event(
                state,
                actor,
                "expire-snapshot",
                None,
                Some(snapshot.clone()),
            )?;
        }
        for trash in &preview.trash {
            let record = state.trash.remove(trash).ok_or(Error::Corrupt)?;
            self.event(
                state,
                actor,
                "expire-trash",
                Some(record.path),
                Some(trash.clone()),
            )?;
        }
        Ok(preview)
    }

    pub(crate) fn retire_artifacts_locked(
        &self,
        state: &mut State,
        actor: &str,
        cutoff: u64,
        own_job: Option<&str>,
    ) -> Result<ExpiryPreview> {
        let mut source = state.clone();
        if let Some(job) = own_job {
            source.jobs.remove(job);
        }
        let mut preview = self.expiry_preview_locked(&source, cutoff)?;
        preview.snapshots.clear();
        preview.trash.clear();
        preview.artifacts = state
            .artifacts
            .values()
            .filter(|a| a.retirement.is_none() && a.expires_at <= cutoff)
            .map(|a| a.id.clone())
            .collect();
        if state
            .history
            .len()
            .checked_add(preview.artifacts.len())
            .is_none_or(|n| n > self.config.policy.history_limit)
        {
            return Err(Error::Quota);
        }
        for id in &preview.artifacts {
            self.event(state, actor, "expire-artifact", None, Some(id.clone()))?;
            let retirement = ArtifactRetirement {
                job_id: own_job.unwrap_or("preview").into(),
                at: now(),
                expired_before: cutoff,
                revision: state.revision,
            };
            state
                .artifacts
                .get_mut(id)
                .ok_or(Error::Corrupt)?
                .retirement = Some(retirement);
        }
        Ok(preview)
    }

    /// Informational expiry candidates; never authorization or reservation.
    pub fn preview_expiry(&self, expected: u64) -> Result<ExpiryPreview> {
        let _maintenance = self.maintenance()?;
        let operation = self.serial()?;
        let current = &operation.store;
        let state = current.load()?;
        current.revision(&state, expected)?;
        current.expiry_preview_locked(&state, now())
    }

    /// Authorize before calling. Expiry events and reference removal publish
    /// atomically; blob collection occurs afterwards and may be deferred.
    /// Artifacts, jobs, external backups and active deletion markers are retained.
    pub fn expire_retained(&self, expected: u64, actor: &str) -> Result<ExpiryResult> {
        if actor.is_empty() || actor.len() > 256 {
            return Err(Error::Path);
        }
        let _maintenance = self.maintenance()?;
        let operation = self.serial()?;
        let current = &operation.store;
        let mut state = current.load()?;
        current.revision(&state, expected)?;
        let preview = current.expiry_preview_locked(&state, now())?;
        // Reject the whole batch before either manifest or physical mutation.
        if state
            .history
            .len()
            .checked_add(preview.snapshots.len())
            .and_then(|n| n.checked_add(preview.trash.len()))
            .is_none_or(|n| n > current.config.policy.history_limit)
        {
            return Err(Error::Quota);
        }
        for snapshot in &preview.snapshots {
            state.snapshots.remove(snapshot).ok_or(Error::Corrupt)?;
            current.event(
                &mut state,
                actor,
                "expire-snapshot",
                None,
                Some(snapshot.clone()),
            )?;
        }
        for trash in &preview.trash {
            let record = state.trash.remove(trash).ok_or(Error::Corrupt)?;
            current.event(
                &mut state,
                actor,
                "expire-trash",
                Some(record.path),
                Some(trash.clone()),
            )?;
        }
        if !preview.snapshots.is_empty() || !preview.trash.is_empty() {
            current.save(&state)?;
        }
        // Observation must not turn a committed expiry into a false failure.
        let usage_after = current.storage_usage_locked(&state, now()).ok();
        let deferred = usage_after.as_ref().is_none_or(|usage| {
            usage.blob_unreferenced_count > 0
                || usage.artifact_orphan_count > 0
                || usage.expired_artifact_count > 0
                || usage.expired_snapshot_count > 0
                || usage.expired_trash_count > 0
        });
        Ok(ExpiryResult {
            revision: state.revision,
            generation: state.generation,
            snapshots: preview.snapshots,
            trash: preview.trash,
            usage_before: preview.usage,
            usage_after,
            physical_reclamation_deferred: deferred,
        })
    }
}
