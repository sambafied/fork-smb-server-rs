//! Bounded manifest slots with durable, immutable retry authority.
use super::*;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHUNKS: usize = 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptArchiveReference {
    pub sha256: String,
    pub bytes: u64,
    pub total_jobs: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptArchiveCheckpoint {
    pub source_revision: u64,
    pub committed_revision: u64,
    pub actor: String,
    pub at: u64,
    pub batch_digest: String,
    pub job_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptArchiveBatch {
    pub schema: u32,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub revision: u64,
    pub previous: Option<ReceiptArchiveReference>,
    pub jobs: BTreeMap<String, Job>,
}
impl ReceiptArchiveBatch {
    pub fn fingerprint(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptArchival {
    pub reference: ReceiptArchiveReference,
    pub checkpoint: ReceiptArchiveCheckpoint,
    pub replayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptArchivePreview {
    pub schema: u32,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub revision: u64,
    pub batch_digest: String,
    pub live_job_count: usize,
    pub pending_job_count: usize,
    pub archived_job_count: u64,
    pub archive_bytes: u64,
    pub usage: StorageUsage,
    pub can_archive: bool,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Chunk {
    batch: ReceiptArchiveBatch,
    checkpoint: ReceiptArchiveCheckpoint,
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn batch(state: &State) -> ReceiptArchiveBatch {
    ReceiptArchiveBatch {
        schema: 1,
        identity: state.identity.clone(),
        base_digest: state.base_digest.clone(),
        generation: state.generation.clone(),
        revision: state.revision,
        previous: state.receipt_archive.clone(),
        jobs: state.jobs.clone(),
    }
}

impl Store {
    pub fn preview_receipt_archival(&self, actor: &str) -> Result<ReceiptArchivePreview> {
        if actor.is_empty() || actor.len() > 256 || actor.chars().any(char::is_control) {
            return Err(Error::Path);
        }
        let _lease = self.lease()?;
        let operation = self.serial()?;
        let current = &operation.store;
        let state = current.load()?;
        let batch = batch(&state);
        let batch_digest = batch.fingerprint()?;
        let usage = current.storage_usage_locked(&state, now())?;
        let pending_job_count = state
            .jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Queued | JobStatus::Running))
            .count();
        let checkpoint = ReceiptArchiveCheckpoint {
            source_revision: state.revision,
            committed_revision: state.revision.checked_add(1).ok_or(Error::Quota)?,
            actor: actor.into(),
            at: now(),
            batch_digest: batch_digest.clone(),
            job_count: state.jobs.len(),
        };
        let archive_bytes = serde_json::to_vec(&Chunk { batch, checkpoint })?.len() as u64;
        let directory = current.receipt_directory()?;
        let chunks = if directory.exists() {
            fs::read_dir(directory)?.count()
        } else {
            0
        };
        let blocker = if state.jobs.is_empty() {
            Some("empty_jobs")
        } else if pending_job_count > 0 {
            Some("pending_jobs")
        } else if state.history.len() >= current.config.policy.history_limit {
            Some("history_capacity")
        } else if archive_bytes > MAX_BYTES
            || chunks >= MAX_CHUNKS
            || usage
                .receipt_archive_bytes
                .checked_add(archive_bytes)
                .is_none_or(|n| n > MAX_TOTAL_BYTES)
        {
            Some("archive_capacity")
        } else if archive_bytes > current.config.policy.temporary_bytes {
            Some("staging_capacity")
        } else if usage
            .retained_charged_bytes
            .checked_add(archive_bytes)
            .is_none_or(|n| n > current.config.policy.retained_bytes)
        {
            Some("retained_capacity")
        } else {
            None
        };
        Ok(ReceiptArchivePreview {
            schema: 1,
            identity: state.identity,
            base_digest: state.base_digest,
            generation: state.generation,
            revision: state.revision,
            batch_digest,
            live_job_count: state.jobs.len(),
            pending_job_count,
            archived_job_count: usage.archived_job_count,
            archive_bytes,
            usage,
            can_archive: blocker.is_none(),
            blocker: blocker.map(str::to_owned),
        })
    }
    fn receipt_directory(&self) -> Result<PathBuf> {
        let path = self.namespace.join("receipts");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(Error::Corrupt),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        Ok(path)
    }
    pub(crate) fn receipt_physical_bytes(&self) -> Result<u64> {
        let path = self.receipt_directory()?;
        if !path.exists() {
            return Ok(0);
        }
        let entries = fs::read_dir(&path)?.collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() > MAX_CHUNKS {
            return Err(Error::Quota);
        }
        tree_bytes(&path)
    }
    fn read_receipt_chunk(&self, reference: &ReceiptArchiveReference) -> Result<Chunk> {
        if !valid_digest(&reference.sha256)
            || reference.bytes == 0
            || reference.bytes > MAX_BYTES
            || reference.total_jobs == 0
            || reference.total_bytes > MAX_TOTAL_BYTES
        {
            return Err(Error::Corrupt);
        }
        let path = self
            .receipt_directory()?
            .join(format!("{}.json", reference.sha256));
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Corrupt);
        }
        let bytes = bounded_read(&path, MAX_BYTES)?;
        if bytes.len() as u64 != reference.bytes || digest(&bytes) != reference.sha256 {
            return Err(Error::Corrupt);
        }
        let chunk: Chunk = serde_json::from_slice(&bytes)?;
        let count = chunk
            .batch
            .previous
            .as_ref()
            .map_or(0, |r| r.total_jobs)
            .checked_add(chunk.batch.jobs.len() as u64)
            .ok_or(Error::Corrupt)?;
        if chunk.batch.schema != 1
            || chunk.batch.jobs.is_empty()
            || chunk.batch.jobs.len() > 1024
            || chunk.batch.identity != self.config.identity
            || chunk.batch.base_digest != self.base_digest
            || count != reference.total_jobs
            || chunk
                .batch
                .previous
                .as_ref()
                .map_or(0, |r| r.total_bytes)
                .checked_add(reference.bytes)
                != Some(reference.total_bytes)
            || chunk.checkpoint.source_revision != chunk.batch.revision
            || chunk.batch.revision.checked_add(1) != Some(chunk.checkpoint.committed_revision)
            || chunk.checkpoint.job_count != chunk.batch.jobs.len()
            || chunk.checkpoint.batch_digest != chunk.batch.fingerprint()?
            || chunk.checkpoint.actor.is_empty()
            || chunk.checkpoint.actor.len() > 256
            || chunk.checkpoint.actor.chars().any(char::is_control)
            || chunk.batch.jobs.iter().any(|(id, job)| {
                Uuid::parse_str(id).map_or(true, |parsed| parsed.to_string() != *id)
                    || job.id != *id
                    || !valid_digest(&job.key_digest)
                    || job.actor.is_empty()
                    || job.actor.len() > 256
                    || job.actor.chars().any(char::is_control)
                    || job.action.validate().is_err()
                    || job.expected_revision > chunk.batch.revision
                    || job.updated_at < job.created_at
                    || !matches!(job.status, JobStatus::Succeeded | JobStatus::Failed)
                    || (job.status == JobStatus::Succeeded
                        && (job.result.is_none() || job.error_code.is_some()))
                    || (job.status == JobStatus::Failed
                        && (job.result.is_some() || job.error_code.is_none()))
                    || job
                        .result
                        .as_ref()
                        .is_some_and(|r| r.revision > chunk.batch.revision)
            })
        {
            return Err(Error::Corrupt);
        }
        Ok(chunk)
    }
    /// Includes archived receipts. No archived key may become a new submission.
    pub(crate) fn receipt_jobs(&self, state: &State) -> Result<BTreeMap<String, Job>> {
        if (state.schema < 9 && state.receipt_archive.is_some())
            || (state.schema == 9 && state.receipt_archive.is_none())
        {
            return Err(Error::Corrupt);
        }
        let mut jobs = state.jobs.clone();
        let mut seen = BTreeSet::new();
        let mut next = state.receipt_archive.clone();
        let mut boundary = state.revision;
        while let Some(reference) = next {
            if !seen.insert(reference.sha256.clone()) || seen.len() > MAX_CHUNKS {
                return Err(Error::Corrupt);
            }
            let chunk = self.read_receipt_chunk(&reference)?;
            if chunk.checkpoint.committed_revision > boundary {
                return Err(Error::Corrupt);
            }
            boundary = chunk.checkpoint.source_revision;
            for (id, job) in chunk.batch.jobs {
                if jobs.insert(id, job).is_some() {
                    return Err(Error::Corrupt);
                }
            }
            next = chunk.batch.previous;
        }
        unique_keys(&jobs)?;
        Ok(jobs)
    }
    /// Read projection only: persisted live slots remain distinct from archives.
    pub fn inspect_with_job_receipts(&self) -> Result<State> {
        let _lease = self.lease()?;
        let operation = self.serial()?;
        let mut state = operation.store.load()?;
        state.jobs = operation.store.receipt_jobs(&state)?;
        Ok(state)
    }
    pub fn job_receipts(&self) -> Result<BTreeMap<String, Job>> {
        let _lease = self.lease()?;
        let operation = self.serial()?;
        operation.store.receipt_jobs(&operation.store.load()?)
    }
    pub fn receipt_archive_batch(&self) -> Result<ReceiptArchiveBatch> {
        let _lease = self.lease()?;
        let operation = self.serial()?;
        Ok(batch(&operation.store.load()?))
    }
    pub fn archive_job_receipts(
        &self,
        expected_digest: &str,
        expected_revision: u64,
        actor: &str,
    ) -> Result<ReceiptArchival> {
        if !valid_digest(expected_digest)
            || actor.is_empty()
            || actor.len() > 256
            || actor.chars().any(char::is_control)
        {
            return Err(Error::Path);
        }
        let _maintenance = self.maintenance()?;
        let operation = self.serial()?;
        let current = &operation.store;
        let mut state = current.load()?;
        if let Some(reference) = &state.receipt_archive {
            let chunk = current.read_receipt_chunk(reference)?;
            if chunk.checkpoint.batch_digest == expected_digest
                && chunk.checkpoint.source_revision == expected_revision
            {
                if chunk.checkpoint.actor != actor {
                    return Err(Error::Idempotency);
                }
                return Ok(ReceiptArchival {
                    reference: reference.clone(),
                    checkpoint: chunk.checkpoint,
                    replayed: true,
                });
            }
        }
        let pending = batch(&state);
        if state.revision != expected_revision || pending.fingerprint()? != expected_digest {
            return Err(Error::Revision);
        }
        if state
            .jobs
            .values()
            .any(|j| matches!(j.status, JobStatus::Queued | JobStatus::Running))
        {
            return Err(Error::Busy);
        }
        if state.jobs.is_empty() {
            return Err(Error::Path);
        }
        let retained_before = current
            .storage_usage_locked(&state, now())?
            .retained_charged_bytes;
        let checkpoint = ReceiptArchiveCheckpoint {
            source_revision: state.revision,
            committed_revision: state.revision.checked_add(1).ok_or(Error::Quota)?,
            actor: actor.into(),
            at: now(),
            batch_digest: expected_digest.into(),
            job_count: state.jobs.len(),
        };
        let chunk = Chunk {
            batch: pending,
            checkpoint: checkpoint.clone(),
        };
        let bytes = serde_json::to_vec(&chunk)?;
        if bytes.len() as u64 > MAX_BYTES
            || bytes.len() as u64 > current.config.policy.temporary_bytes
        {
            return Err(Error::Quota);
        }
        let reference = ReceiptArchiveReference {
            sha256: digest(&bytes),
            bytes: bytes.len() as u64,
            total_jobs: state
                .receipt_archive
                .as_ref()
                .map_or(0, |r| r.total_jobs)
                .checked_add(state.jobs.len() as u64)
                .ok_or(Error::Quota)?,
            total_bytes: state
                .receipt_archive
                .as_ref()
                .map_or(0, |r| r.total_bytes)
                .checked_add(bytes.len() as u64)
                .ok_or(Error::Quota)?,
        };
        if reference.total_bytes > MAX_TOTAL_BYTES {
            return Err(Error::Quota);
        }
        state.schema = 9;
        state.jobs.clear();
        state.receipt_archive = Some(reference.clone());
        current.event(&mut state, actor, "archive-jobs", None, None)?;
        current.check_budget(&state)?;
        // Reserve archive capacity before publishing any file. Orphans remain charged.
        let physical = current.receipt_physical_bytes()?;
        let path = current
            .receipt_directory()?
            .join(format!("{}.json", reference.sha256));
        let extra = if path.exists() { 0 } else { reference.bytes };
        if extra != 0
            && path.parent().is_some_and(|parent| {
                parent.exists()
                    && fs::read_dir(parent).map_or(true, |entries| entries.count() >= MAX_CHUNKS)
            })
        {
            return Err(Error::Quota);
        }
        if retained_before.checked_add(extra).ok_or(Error::Quota)?
            > current.config.policy.retained_bytes
            || physical.checked_add(extra).ok_or(Error::Quota)?
                > current.config.policy.retained_bytes
        {
            return Err(Error::Quota);
        }
        fs::create_dir_all(current.receipt_directory()?)?;
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::Corrupt);
            }
            if bounded_read(&path, MAX_BYTES)? != bytes {
                return Err(Error::Corrupt);
            }
        } else {
            let mut file = AtomicWriteFile::open(&path)?;
            file.write_all(&bytes)?;
            file.commit()?;
        }
        current.save(&state)?;
        Ok(ReceiptArchival {
            reference,
            checkpoint,
            replayed: false,
        })
    }
}
fn unique_keys(jobs: &BTreeMap<String, Job>) -> Result<()> {
    let mut keys = BTreeSet::new();
    for job in jobs.values() {
        if !keys.insert((&job.actor, &job.key_digest)) {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
