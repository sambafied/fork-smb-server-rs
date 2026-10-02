//! Server-owned destination selection and resumable external publications.
use super::*;

pub type BackupCatalog = BTreeMap<String, BackupDestination>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupDeletion {
    schema: u32,
    backup_id: String,
    pub(crate) job_id: String,
    destination_id: String,
    identity: Identity,
}

pub(crate) struct Capture {
    pub(crate) backup: Backup,
    payload: BTreeMap<String, Vec<u8>>,
    path: PathBuf,
    published: bool,
}

pub(crate) fn destination_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

impl Store {
    pub(crate) fn destination<'a>(
        &self,
        catalog: &'a BackupCatalog,
        id: &str,
    ) -> Result<&'a BackupDestination> {
        let destination = catalog
            .get(id)
            .filter(|d| d.id == id)
            .ok_or(Error::NotFound)?;
        self.backup_namespace(destination)?;
        Ok(destination)
    }

    pub(crate) fn action_fingerprint(
        &self,
        state: &State,
        catalog: &BackupCatalog,
        action: &Action,
        job: Option<&str>,
    ) -> Result<String> {
        let external = match action {
            Action::RestoreBackup {
                destination_id,
                backup_id,
            }
            | Action::DeleteBackup {
                destination_id,
                backup_id,
            } => {
                let deleting_job = matches!(action, Action::DeleteBackup { .. })
                    .then_some(job)
                    .flatten();
                let mut backup = self.backup_manifest_for_job(
                    self.destination(catalog, destination_id)?,
                    backup_id,
                    deleting_job,
                )?;
                // Older manifests are upgraded when deletion is tombstoned.
                backup.schema = 2;
                Some(backup)
            }
            _ => None,
        };
        let fingerprint = if catalog.is_empty() && external.is_none() {
            digest(&serde_json::to_vec(&(state, &self.config.policy))?)
        } else {
            digest(&serde_json::to_vec(&(
                state,
                &self.config.policy,
                catalog,
                external,
            ))?)
        };
        match self.policy_revision {
            None => Ok(fingerprint),
            Some(revision) => Ok(digest(&serde_json::to_vec(&(fingerprint, revision))?)),
        }
    }

    pub(crate) fn backup_deletion(
        &self,
        destination: &BackupDestination,
        backup_id: &str,
    ) -> Result<Option<BackupDeletion>> {
        let marker = self
            .backup_namespace(destination)?
            .join(backup_id)
            .join("deleted.json");
        if !marker.exists() {
            return Ok(None);
        }
        let deletion: BackupDeletion = serde_json::from_slice(&bounded_read(&marker, 4096)?)?;
        if deletion.schema != 1
            || deletion.backup_id != backup_id
            || deletion.destination_id != destination.id
            || deletion.identity != self.config.identity
            || Uuid::parse_str(&deletion.job_id).is_err()
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(deletion))
    }

    pub(crate) fn prepare_capture(
        &self,
        state: &State,
        destination: &BackupDestination,
        backup_id: &str,
        created_at: u64,
    ) -> Result<Capture> {
        self.verify_view(&state.view)?;
        let namespace = self.backup_namespace(destination)?;
        let path = namespace.join(backup_id);
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::Path);
            }
        }
        let count = if namespace.exists() {
            fs::read_dir(&namespace)?.try_fold(0usize, |count, entry| {
                entry?;
                count
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("entry count overflow"))
            })?
        } else {
            0
        };
        if count >= destination.count_limit && !path.exists() {
            return Err(Error::Quota);
        }
        let physical = if namespace.exists() {
            tree_bytes(&namespace)?
        } else {
            0
        };
        let mut payload = BTreeMap::new();
        let mut size = 0u64;
        let mut additional = 0u64;
        for hash in state
            .view
            .upper
            .values()
            .filter_map(|entry| entry.digest.as_ref())
        {
            if payload.contains_key(hash) {
                continue;
            }
            let bytes = bounded_read(&self.blob_path(hash)?, self.config.policy.max_file_bytes)?;
            if digest(&bytes) != *hash {
                return Err(Error::Corrupt);
            }
            size = size.checked_add(bytes.len() as u64).ok_or(Error::Quota)?;
            let existing = path.join("blobs").join(hash);
            if existing.exists() {
                if bounded_read(&existing, self.config.policy.max_file_bytes)? != bytes {
                    return Err(Error::Corrupt);
                }
            } else {
                additional = additional
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::Quota)?;
            }
            payload.insert(hash.clone(), bytes);
        }
        if size > self.config.policy.temporary_bytes {
            return Err(Error::Quota);
        }
        let backup = Backup {
            schema: 2,
            id: backup_id.into(),
            destination_id: destination.id.clone(),
            failure_domain: destination.failure_domain.clone(),
            identity: state.identity.clone(),
            base_digest: state.base_digest.clone(),
            generation: state.generation.clone(),
            created_at,
            expires_at: created_at.saturating_add(destination.ttl_seconds),
            bytes: size,
            view: state.view.clone(),
        };
        if backup.expires_at <= now() {
            return Err(Error::Retention);
        }
        let published = path.join("manifest.json").exists();
        if published {
            let existing = self.backup_manifest(destination, backup_id)?;
            if serde_json::to_vec(&existing)? != serde_json::to_vec(&backup)? {
                return Err(Error::Corrupt);
            }
        } else {
            additional = additional
                .checked_add(serde_json::to_vec(&backup)?.len() as u64)
                .ok_or(Error::Quota)?;
        }
        if physical.checked_add(additional).ok_or(Error::Quota)? > destination.byte_limit {
            return Err(Error::Quota);
        }
        Ok(Capture {
            backup,
            payload,
            path,
            published,
        })
    }

    pub(crate) fn publish_capture(&self, capture: &Capture) -> Result<()> {
        if capture.published {
            return Ok(());
        }
        fs::create_dir_all(capture.path.join("blobs"))?;
        for (hash, bytes) in &capture.payload {
            let path = capture.path.join("blobs").join(hash);
            if path.exists() {
                if bounded_read(&path, self.config.policy.max_file_bytes)? != *bytes {
                    return Err(Error::Corrupt);
                }
                continue;
            }
            let mut file = AtomicWriteFile::open(path)?;
            file.write_all(bytes)?;
            file.commit()?;
        }
        #[cfg(unix)]
        File::open(capture.path.join("blobs"))?.sync_all()?;
        atomic_json(&capture.path.join("manifest.json"), &capture.backup)?;
        #[cfg(unix)]
        {
            File::open(&capture.path)?.sync_all()?;
            File::open(capture.path.parent().ok_or(Error::Path)?)?.sync_all()?;
        }
        Ok(())
    }

    pub(crate) fn publish_backup_deletion(
        &self,
        destination: &BackupDestination,
        backup: &Backup,
        job_id: &str,
    ) -> Result<()> {
        if let Some(deleted) = self.backup_deletion(destination, &backup.id)? {
            return if deleted.job_id == job_id {
                Ok(())
            } else {
                Err(Error::NotFound)
            };
        }
        self.check_deletion_budget(destination, backup, job_id)?;
        let path = self.backup_namespace(destination)?.join(&backup.id);
        let mut compatible = backup.clone();
        compatible.schema = 2; // older readers must not resurrect a deleted backup
        atomic_json(&path.join("manifest.json"), &compatible)?;
        atomic_json(
            &path.join("deleted.json"),
            &BackupDeletion {
                schema: 1,
                backup_id: backup.id.clone(),
                job_id: job_id.into(),
                destination_id: destination.id.clone(),
                identity: self.config.identity.clone(),
            },
        )?;
        #[cfg(unix)]
        File::open(&path)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn check_deletion_budget(
        &self,
        destination: &BackupDestination,
        backup: &Backup,
        job_id: &str,
    ) -> Result<()> {
        if let Some(deleted) = self.backup_deletion(destination, &backup.id)? {
            return if deleted.job_id == job_id {
                Ok(())
            } else {
                Err(Error::NotFound)
            };
        }
        let mut compatible = backup.clone();
        compatible.schema = 2;
        let marker = BackupDeletion {
            schema: 1,
            backup_id: backup.id.clone(),
            job_id: job_id.into(),
            destination_id: destination.id.clone(),
            identity: self.config.identity.clone(),
        };
        // Reserve the replacement manifest's temporary bytes as well as the
        // durable tombstone. Deleted payload remains charged to this quota.
        let marker_bytes = serde_json::to_vec(&marker)?.len() as u64;
        let required = tree_bytes(&self.backup_namespace(destination)?)?
            .checked_add(serde_json::to_vec(&compatible)?.len() as u64)
            .and_then(|size| size.checked_add(marker_bytes))
            .ok_or(Error::Quota)?;
        if required > destination.byte_limit {
            return Err(Error::Quota);
        }
        Ok(())
    }
}
