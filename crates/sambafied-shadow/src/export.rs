//! Consistent, bounded shadow-only archives. Publication and authorization are
//! management-layer responsibilities; a partial writer is never an artifact.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub schema: u32,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub revision: u64,
    pub view: View,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportSummary {
    pub bytes: u64,
    pub sha256: String,
    pub generation: String,
    pub revision: u64,
}

/// Pure archive preflight. This is not a job receipt or download artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportPreflight {
    pub bytes: u64,
    pub generation: String,
    pub revision: u64,
}

pub(crate) struct PreparedExport {
    manifest: ExportManifest,
    manifest_bytes: Vec<u8>,
    blobs: BTreeMap<String, u64>,
    pub(crate) preflight: ExportPreflight,
}

struct ArchiveWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
    limit: u64,
}
impl<W: Write> Write for ArchiveWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.limit.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("export exceeds staging budget"));
        }
        let written = self.inner.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.bytes += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn member_bytes(size: u64) -> Result<u64> {
    size.checked_add(511)
        .and_then(|v| (v / 512).checked_mul(512))
        .and_then(|v| v.checked_add(512))
        .ok_or(Error::Quota)
}
fn append<W: Write>(archive: &mut tar::Builder<W>, path: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    archive.append_data(&mut header, path, data)?;
    Ok(())
}

impl Store {
    /// Capture a consistent portable tar containing `manifest.json` and only
    /// referenced upper blobs. The caller must authorize the resource and use
    /// a private staging writer, publishing it only after this returns success.
    /// This read does not create a snapshot, history event, job or backup.
    pub fn export_archive<W: Write>(&self, expected: u64, writer: W) -> Result<ExportSummary> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let state = self.load()?;
        self.revision(&state, expected)?;
        let prepared = self.prepare_export(&state)?;
        self.write_export(&prepared, writer)
    }

    /// Validate all upper content and compute exact tar bytes without creating
    /// an archive, job, history entry, or changing overlay state.
    pub fn export_preflight(&self, expected: u64) -> Result<ExportPreflight> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let state = self.load()?;
        self.revision(&state, expected)?;
        Ok(self.prepare_export(&state)?.preflight)
    }

    // Management execution already owns both locks. Keeping preparation and
    // writing separate lets it check quota and authorization before staging.
    pub(crate) fn prepare_export(&self, state: &State) -> Result<PreparedExport> {
        for (path, entry) in &state.view.upper {
            if path.is_empty()
                || normalize(path).map_err(|_| Error::Corrupt)? != *path
                || entry.name.contains(['/', '\\'])
                || normalize(&entry.name).map_err(|_| Error::Corrupt)?
                    != path.rsplit('/').next().ok_or(Error::Corrupt)?
                // Copy-up and rename preserve the pinned base object's stable
                // identity; only newly created objects receive UUIDs.
                || (Uuid::parse_str(&entry.object_id).is_err()
                    && !self.base.values().any(|base| base.object_id == entry.object_id))
                || entry.size > self.config.policy.max_file_bytes
                || (entry.directory && (entry.size != 0 || entry.digest.is_some()))
            {
                return Err(Error::Corrupt);
            }
        }
        for marker in &state.view.whiteouts {
            if marker.is_empty() || normalize(marker).map_err(|_| Error::Corrupt)? != *marker {
                return Err(Error::Corrupt);
            }
        }
        let manifest = ExportManifest {
            schema: 1,
            identity: state.identity.clone(),
            base_digest: state.base_digest.clone(),
            generation: state.generation.clone(),
            revision: state.revision,
            view: state.view.clone(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let mut blobs = BTreeMap::new();
        for entry in manifest
            .view
            .upper
            .values()
            .filter(|entry| !entry.directory)
        {
            let hash = entry.digest.as_ref().ok_or(Error::Corrupt)?;
            if blobs
                .insert(hash.clone(), entry.size)
                .is_some_and(|size| size != entry.size)
            {
                return Err(Error::Corrupt);
            }
        }
        let mut expected_bytes = member_bytes(manifest_bytes.len() as u64)?;
        for size in blobs.values() {
            expected_bytes = expected_bytes
                .checked_add(member_bytes(*size)?)
                .ok_or(Error::Quota)?;
        }
        expected_bytes = expected_bytes.checked_add(1024).ok_or(Error::Quota)?;
        if expected_bytes > self.config.policy.temporary_bytes {
            return Err(Error::Quota);
        }
        // Complete validation before touching the caller's staging writer.
        for (hash, size) in &blobs {
            let bytes = bounded_read(&self.blob_path(hash)?, self.config.policy.max_file_bytes)?;
            if bytes.len() as u64 != *size || digest(&bytes) != *hash {
                return Err(Error::Corrupt);
            }
        }
        let preflight = ExportPreflight {
            bytes: expected_bytes,
            generation: manifest.generation.clone(),
            revision: manifest.revision,
        };
        Ok(PreparedExport {
            manifest,
            manifest_bytes,
            blobs,
            preflight,
        })
    }

    pub(crate) fn write_export<W: Write>(
        &self,
        prepared: &PreparedExport,
        writer: W,
    ) -> Result<ExportSummary> {
        let expected_bytes = prepared.preflight.bytes;
        let writer = ArchiveWriter {
            inner: writer,
            hash: Sha256::new(),
            bytes: 0,
            limit: expected_bytes,
        };
        let mut archive = tar::Builder::new(writer);
        archive.follow_symlinks(false);
        append(&mut archive, "manifest.json", &prepared.manifest_bytes)?;
        for (hash, size) in &prepared.blobs {
            let bytes = bounded_read(&self.blob_path(hash)?, self.config.policy.max_file_bytes)?;
            if bytes.len() as u64 != *size || digest(&bytes) != *hash {
                return Err(Error::Corrupt);
            }
            append(&mut archive, &format!("blobs/{hash}.blob"), &bytes)?;
        }
        let mut writer = archive.into_inner()?;
        writer.flush()?;
        if writer.bytes != expected_bytes {
            return Err(Error::Corrupt);
        }
        Ok(ExportSummary {
            bytes: writer.bytes,
            sha256: format!("{:x}", writer.hash.finalize()),
            generation: prepared.manifest.generation.clone(),
            revision: prepared.manifest.revision,
        })
    }
}
