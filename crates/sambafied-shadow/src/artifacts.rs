//! Durable, private export publications. API policy authorization remains mandatory.
use super::*;
use std::io::{Seek, SeekFrom};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    pub ttl_seconds: u64,
    pub count_limit: usize,
    pub byte_limit: u64,
}
impl ArtifactPolicy {
    pub(crate) fn validate(&self, retained: u64) -> Result<()> {
        if !(1..=315_360_000).contains(&self.ttl_seconds)
            || !(1..=1024).contains(&self.count_limit)
            || self.byte_limit == 0
            || self.byte_limit > retained
        {
            return Err(Error::Quota);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportArtifact {
    pub id: String,
    pub actor: String,
    pub identity: Identity,
    pub generation: String,
    pub revision: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub bytes: u64,
    pub sha256: String,
}

pub(crate) struct ArtifactCapture {
    pub(crate) artifact: ExportArtifact,
    prepared: super::export::PreparedExport,
}
fn canonical_id(value: &str) -> Result<()> {
    if Uuid::parse_str(value).map_err(|_| Error::Path)?.to_string() != value {
        return Err(Error::Path);
    }
    Ok(())
}
impl Store {
    fn artifacts_dir(&self) -> Result<PathBuf> {
        let path = self.namespace.join("artifacts");
        match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => Err(Error::Corrupt),
            Ok(_) => Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
            Err(error) => Err(error.into()),
        }
    }
    fn artifact_path(&self, artifact_id: &str) -> Result<PathBuf> {
        canonical_id(artifact_id)?;
        Ok(self.artifacts_dir()?.join(format!("{artifact_id}.tar")))
    }
    /// Physical archives include unpublished receipts and expired objects.
    /// They remain charged until actual physical reclamation.
    pub(crate) fn physical_artifacts(&self) -> Result<BTreeMap<String, u64>> {
        let path = self.artifacts_dir()?;
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(error.into()),
        };
        let mut result = BTreeMap::new();
        for entry in entries {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::Corrupt);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Corrupt)?;
            let artifact_id = name.strip_suffix(".tar").ok_or(Error::Corrupt)?;
            canonical_id(artifact_id).map_err(|_| Error::Corrupt)?;
            if result.len() >= 1024 {
                return Err(Error::Quota);
            }
            result.insert(artifact_id.to_owned(), metadata.len());
        }
        Ok(result)
    }
    pub(crate) fn artifact_usage(&self, state: &State) -> Result<BTreeMap<String, u64>> {
        let mut physical = self.physical_artifacts()?;
        for (id, artifact) in &state.artifacts {
            physical
                .entry(id.clone())
                .and_modify(|bytes| *bytes = (*bytes).max(artifact.bytes))
                .or_insert(artifact.bytes);
        }
        Ok(physical)
    }
    pub(crate) fn validate_artifacts(&self, state: &State) -> Result<()> {
        if state.schema < 5 && !state.artifacts.is_empty() {
            return Err(Error::Corrupt);
        }
        for (id, artifact) in &state.artifacts {
            canonical_id(id).map_err(|_| Error::Corrupt)?;
            if artifact.id != *id
                || artifact.identity != state.identity
                || artifact.actor.is_empty()
                || artifact.actor.len() > 256
                || artifact.created_at >= artifact.expires_at
                || artifact.bytes == 0
                || artifact.sha256.len() != 64
                || !artifact
                    .sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(Error::Corrupt);
            }
            let job = state.jobs.get(id).ok_or(Error::Corrupt)?;
            if job.status != JobStatus::Succeeded
                || job.action != Action::Export
                || job.actor != artifact.actor
                || job.result.as_ref().and_then(|r| r.artifact_id.as_ref()) != Some(id)
                || job.created_at != artifact.created_at
                || job.expected_revision != artifact.revision
                || job.result.as_ref().is_none_or(|r| {
                    r.generation != artifact.generation
                        || artifact.revision.checked_add(1) != Some(r.revision)
                })
            {
                return Err(Error::Corrupt);
            }
        }
        for job in state
            .jobs
            .values()
            .filter(|j| j.action == Action::Export && j.status == JobStatus::Succeeded)
        {
            if job.result.as_ref().and_then(|r| r.artifact_id.as_ref()) != Some(&job.id)
                || !state.artifacts.contains_key(&job.id)
            {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_artifact(
        &self,
        state: &State,
        artifact_id: &str,
        actor: &str,
        created: u64,
    ) -> Result<ArtifactCapture> {
        canonical_id(artifact_id)?;
        let policy = self
            .config
            .policy
            .artifacts
            .as_ref()
            .ok_or(Error::Unsupported)?;
        policy.validate(self.config.policy.retained_bytes)?;
        let prepared = self.prepare_export(state)?;
        let mut usage = self.artifact_usage(state)?;
        usage
            .entry(artifact_id.to_owned())
            .and_modify(|n| *n = (*n).max(prepared.preflight.bytes))
            .or_insert(prepared.preflight.bytes);
        let total = usage
            .values()
            .try_fold(0u64, |sum, n| sum.checked_add(*n))
            .ok_or(Error::Quota)?;
        if usage.len() > policy.count_limit || total > policy.byte_limit {
            return Err(Error::Quota);
        }
        let summary = self.write_export(&prepared, std::io::sink())?;
        let expires_at = created
            .checked_add(policy.ttl_seconds)
            .ok_or(Error::Quota)?;
        if expires_at <= now() {
            return Err(Error::Retention);
        }
        Ok(ArtifactCapture {
            artifact: ExportArtifact {
                id: artifact_id.to_owned(),
                actor: actor.to_owned(),
                identity: state.identity.clone(),
                generation: summary.generation,
                revision: summary.revision,
                created_at: created,
                expires_at,
                bytes: summary.bytes,
                sha256: summary.sha256,
            },
            prepared,
        })
    }
    pub(crate) fn publish_artifact(&self, capture: &ArtifactCapture) -> Result<()> {
        let path = self.artifact_path(&capture.artifact.id)?;
        if path.exists() {
            self.verify_artifact_file(&capture.artifact)?;
            return Ok(());
        }
        let parent = self.artifacts_dir()?;
        fs::create_dir_all(&parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
        }
        let mut file = AtomicWriteFile::open(&path)?;
        let summary = self.write_export(&capture.prepared, &mut file)?;
        if summary.bytes != capture.artifact.bytes || summary.sha256 != capture.artifact.sha256 {
            return Err(Error::Corrupt);
        }
        file.commit()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    fn verify_artifact_file(&self, artifact: &ExportArtifact) -> Result<File> {
        let path = self.artifact_path(&artifact.id)?;
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != artifact.bytes {
            return Err(Error::Corrupt);
        }
        let mut file = File::open(path)?;
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            bytes = bytes.checked_add(read as u64).ok_or(Error::Quota)?;
            if bytes > artifact.bytes {
                return Err(Error::Corrupt);
            }
            hash.update(&buffer[..read]);
        }
        if bytes != artifact.bytes || format!("{:x}", hash.finalize()) != artifact.sha256 {
            return Err(Error::Corrupt);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    /// An actor-scoped durable record, not an authorization grant.
    pub fn artifact(&self, artifact_id: &str, actor: &str) -> Result<ExportArtifact> {
        canonical_id(artifact_id)?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let state = current.load()?;
        let artifact = state
            .artifacts
            .get(artifact_id)
            .filter(|a| a.actor == actor)
            .ok_or(Error::NotFound)?;
        if artifact.expires_at <= now() {
            return Err(Error::Retention);
        }
        Ok(artifact.clone())
    }
    /// Verify the private archive and recheck current authorization before the
    /// verified descriptor is returned. The callback must enforce API policy.
    pub fn open_artifact<F>(
        &self,
        artifact_id: &str,
        actor: &str,
        mut authorize: F,
    ) -> Result<(ExportArtifact, File)>
    where
        F: FnMut(&ExportArtifact) -> Result<()>,
    {
        canonical_id(artifact_id)?;
        let _serial = self.serial()?;
        let current = &_serial.store;
        let state = current.load()?;
        let artifact = state
            .artifacts
            .get(artifact_id)
            .filter(|a| a.actor == actor)
            .ok_or(Error::NotFound)?;
        if artifact.expires_at <= now() {
            return Err(Error::Retention);
        }
        authorize(artifact)?;
        let file = current.verify_artifact_file(artifact)?;
        if artifact.expires_at <= now() {
            return Err(Error::Retention);
        }
        authorize(artifact)?;
        Ok((artifact.clone(), file))
    }
}
