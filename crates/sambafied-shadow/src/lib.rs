//! Persistent private namespaces over a pinned local base.
//!
//! Content blobs are immutable. A single atomically replaced manifest publishes
//! content, deletion markers, recovery references and history together. Clients
//! hold a shared maintenance lease; generation changes require its exclusive
//! counterpart. The lease works across the API and SMB engine processes.
#![forbid(unsafe_code)]

mod management;
pub use management::{Action, ActionImpact, Job, JobResult, JobStatus, Submission};

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage I/O failed")]
    Io(#[from] std::io::Error),
    #[error("manifest is invalid")]
    Json(#[from] serde_json::Error),
    #[error("invalid or unsupported path")]
    Path,
    #[error("object not found")]
    NotFound,
    #[error("object already exists")]
    Exists,
    #[error("directory is not empty")]
    NotEmpty,
    #[error("overlay has active handles or is under maintenance")]
    Busy,
    #[error("revision changed")]
    Revision,
    #[error("storage budget exceeded")]
    Quota,
    #[error("content or base identity differs from its pinned manifest")]
    Corrupt,
    #[error("recovery point is protected or expired")]
    Retention,
    #[error("operation is not supported")]
    Unsupported,
    #[error("management authorization denied")]
    Denied,
    #[error("idempotency key was used with different inputs")]
    Idempotency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub organization: String,
    pub share: String,
    pub principal: String,
    pub base_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub active_bytes: u64,
    pub active_files: usize,
    pub retained_bytes: u64,
    pub temporary_bytes: u64,
    pub max_file_bytes: u64,
    pub snapshot_limit: usize,
    pub history_limit: usize,
    pub snapshot_ttl_seconds: u64,
    pub recovery_protection_seconds: u64,
    pub trash_ttl_seconds: u64,
}

impl Policy {
    fn validate(&self) -> Result<()> {
        if self.active_bytes == 0
            || self.active_files == 0
            || self.max_file_bytes == 0
            || self.temporary_bytes < self.max_file_bytes
            || self.snapshot_limit == 0
            || self.history_limit == 0
            || self.snapshot_ttl_seconds == 0
            || self.recovery_protection_seconds == 0
            || self.recovery_protection_seconds > self.snapshot_ttl_seconds
            || self.trash_ttl_seconds == 0
        {
            return Err(Error::Quota);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub root: PathBuf,
    pub base: PathBuf,
    pub identity: Identity,
    pub policy: Policy,
}

/// Only server configuration supplies destination paths. Management requests
/// select `id`; a caller-provided filesystem path is never a destination.
#[derive(Debug, Clone)]
pub struct BackupDestination {
    pub id: String,
    pub root: PathBuf,
    pub byte_limit: u64,
    pub count_limit: usize,
    pub ttl_seconds: u64,
    pub failure_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub schema: u32,
    pub id: String,
    pub destination_id: String,
    pub failure_domain: String,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub bytes: u64,
    pub view: View,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Stable identity across copy-up and rename in this private namespace.
    pub object_id: String,
    pub name: String,
    pub directory: bool,
    pub size: u64,
    /// SHA-256 of the immutable content; directories have no content reference.
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct View {
    pub upper: BTreeMap<String, Entry>,
    /// A directory marker hides its whole lower subtree. Upper descendants are
    /// still visible, so deletion followed by recreation remains opaque.
    pub whiteouts: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub generation: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub protected_until: u64,
    pub view: View,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trash {
    pub id: String,
    pub path: String,
    pub entry: Entry,
    pub from_upper: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub revision: u64,
    pub generation: String,
    pub actor: String,
    pub operation: String,
    pub path: Option<String>,
    pub object_id: Option<String>,
    pub at: u64,
    #[serde(default)]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub identity: Identity,
    pub base_digest: String,
    pub generation: String,
    pub revision: u64,
    pub view: View,
    pub snapshots: BTreeMap<String, Snapshot>,
    pub trash: BTreeMap<String, Trash>,
    #[serde(default)]
    pub backups: BTreeMap<String, Backup>,
    pub history: Vec<Event>,
    #[serde(default)]
    pub jobs: BTreeMap<String, Job>,
}

#[derive(Debug)]
pub struct Store {
    config: Config,
    namespace: PathBuf,
    base: BTreeMap<String, Entry>,
    base_paths: BTreeMap<String, PathBuf>,
    base_digest: String,
}

/// A lease is retained for the complete lifetime of an SMB handle. Dropping
/// it closes the independent lock file, releasing the cross-process lease.
#[derive(Debug)]
pub struct Lease {
    _file: File,
}

#[derive(Debug)]
pub struct Handle {
    pub store: Arc<Store>,
    pub path: String,
    pub object_id: String,
    pub directory: bool,
    pub writable: bool,
    pub generation: String,
    _lease: Lease,
}

/// File opening semantics, corresponding to the NT create dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDisposition {
    Supersede,
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}

/// The action committed by an atomic open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAction {
    Superseded,
    Opened,
    Created,
    Overwritten,
}

/// An atomic open request supplied by the trusted protocol adapter.
#[derive(Debug, Clone, Copy)]
pub struct OpenRequest<'a> {
    pub path: &'a str,
    pub directory: bool,
    pub writable: bool,
    pub disposition: OpenDisposition,
    pub actor: &'a str,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn id() -> String {
    Uuid::new_v4().to_string()
}

/// Normalize Windows-style paths into a single case-insensitive namespace.
/// ADS, wildcards, device names and ambiguous trailing-dot/space names are
/// explicitly unsupported; they never become host paths.
pub fn normalize(path: &str) -> Result<String> {
    if path.len() > 1024 || path.starts_with(['/', '\\']) {
        return Err(Error::Path);
    }
    let path = path.replace('\\', "/");
    if path.is_empty() {
        return Ok(path);
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|c| c.is_control() || "<>:\"|?*".contains(c))
        {
            return Err(Error::Path);
        }
        let lower = part.to_lowercase();
        let stem = lower.split('.').next().unwrap_or("");
        if matches!(stem, "con" | "prn" | "aux" | "nul")
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(Error::Path);
        }
        parts.push(lower);
    }
    Ok(parts.join("/"))
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::Quota);
    }
    let mut file = AtomicWriteFile::open(path)?;
    file.write_all(&bytes)?;
    file.commit()?;
    Ok(())
}

fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Corrupt);
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit.checked_add(1).ok_or(Error::Quota)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Quota);
    }
    Ok(bytes)
}

fn lock(path: &Path, exclusive: bool, nonblocking: bool) -> Result<Lease> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if nonblocking {
        let result = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        result.map_err(|_| Error::Busy)?;
    } else if exclusive {
        file.lock()?;
    } else {
        file.lock_shared()?;
    }
    Ok(Lease { _file: file })
}

impl Store {
    /// Initialize or reopen an opaque namespace. The base tree is hashed and
    /// must match the persisted pinned identity on every subsequent open.
    pub fn open(mut config: Config) -> Result<Arc<Self>> {
        config.policy.validate()?;
        if [
            &config.identity.organization,
            &config.identity.share,
            &config.identity.principal,
            &config.identity.base_version,
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
        {
            return Err(Error::Path);
        }
        if !config.root.is_absolute() || !config.base.is_absolute() {
            return Err(Error::Path);
        }
        config.base = fs::canonicalize(&config.base)?;
        config.root = fs::canonicalize(&config.root)?;
        if config.root.starts_with(&config.base) || config.base.starts_with(&config.root) {
            return Err(Error::Path);
        }
        let opaque = digest(&serde_json::to_vec(&config.identity)?);
        let namespace = config.root.join(opaque);
        fs::create_dir_all(namespace.join("blobs"))?;
        let mut base = BTreeMap::new();
        let mut base_paths = BTreeMap::new();
        scan_base(
            &config.base,
            &config.base,
            &mut base,
            &mut base_paths,
            &config.policy,
        )?;
        let base_digest = digest(&serde_json::to_vec(&base)?);
        let store = Arc::new(Self {
            config,
            namespace,
            base,
            base_paths,
            base_digest,
        });
        let _serial = store.serial()?;
        if store.state_path().exists() {
            let mut state = store.load()?;
            if state.schema == 1 {
                let _maintenance = store.maintenance()?;
                state.schema = 2;
                store.save(&state)?;
            }
            store.collect_blobs(&state)?;
        } else {
            store.save(&State {
                schema: 2,
                identity: store.config.identity.clone(),
                base_digest: store.base_digest.clone(),
                generation: id(),
                revision: 0,
                view: View::default(),
                snapshots: BTreeMap::new(),
                trash: BTreeMap::new(),
                backups: BTreeMap::new(),
                history: Vec::new(),
                jobs: BTreeMap::new(),
            })?;
        }
        drop(_serial);
        Ok(store)
    }

    pub fn namespace(&self) -> &Path {
        &self.namespace
    }
    fn state_path(&self) -> PathBuf {
        self.namespace.join("state.json")
    }
    fn serial(&self) -> Result<Lease> {
        lock(&self.namespace.join("state.lock"), true, false)
    }
    pub fn lease(&self) -> Result<Lease> {
        lock(&self.namespace.join("maintenance.lock"), false, true)
    }
    fn maintenance(&self) -> Result<Lease> {
        lock(&self.namespace.join("maintenance.lock"), true, true)
    }
    fn load(&self) -> Result<State> {
        let state: State =
            serde_json::from_slice(&bounded_read(&self.state_path(), 16 * 1024 * 1024)?)?;
        if !matches!(state.schema, 1 | 2)
            || (state.schema == 1 && !state.jobs.is_empty())
            || state.identity != self.config.identity
            || state.base_digest != self.base_digest
        {
            return Err(Error::Corrupt);
        }
        Ok(state)
    }
    fn save(&self, state: &State) -> Result<()> {
        self.check_budget(state)?;
        atomic_json(&self.state_path(), state)?;
        #[cfg(unix)]
        File::open(&self.namespace)?.sync_all()?;
        // Reclamation failure leaves extra blobs; physical admission limits
        // prevent unbounded growth without misreporting a committed activation.
        let _ = self.collect_blobs(state);
        Ok(())
    }

    fn collect_blobs(&self, state: &State) -> Result<()> {
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
            .filter_map(|e| e.digest.as_ref())
            .cloned()
            .collect();
        for entry in fs::read_dir(self.namespace.join("blobs"))? {
            let entry = entry?;
            let hash = entry.file_name().to_string_lossy().to_string();
            if self.blob_path(&hash).is_err() {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(Error::Corrupt);
            }
            if !referenced.contains(&hash) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    pub fn inspect(&self) -> Result<State> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        self.load()
    }
    fn lookup<'a>(&'a self, view: &'a View, path: &str) -> Option<&'a Entry> {
        view.upper.get(path).or_else(|| {
            if view
                .whiteouts
                .iter()
                .any(|w| path == w || path.starts_with(&format!("{w}/")))
            {
                None
            } else {
                self.base.get(path)
            }
        })
    }
    fn parent_exists(&self, view: &View, path: &str) -> bool {
        let parent = path.rsplit_once('/').map(|x| x.0).unwrap_or("");
        parent.is_empty() || self.lookup(view, parent).is_some_and(|e| e.directory)
    }
    pub fn stat(&self, path: &str) -> Result<Entry> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        if path.is_empty() {
            return Ok(Entry {
                object_id: "root".to_string(),
                name: String::new(),
                directory: true,
                size: 0,
                digest: None,
            });
        }
        self.lookup(&self.load()?.view, &path)
            .cloned()
            .ok_or(Error::NotFound)
    }
    fn listing(&self, view: &View, path: &str) -> Result<Vec<Entry>> {
        if !path.is_empty() && !self.lookup(view, path).is_some_and(|e| e.directory) {
            return Err(Error::NotFound);
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let keys: BTreeSet<_> = self.base.keys().chain(view.upper.keys()).cloned().collect();
        Ok(keys
            .iter()
            .filter(|k| k.starts_with(&prefix) && !k[prefix.len()..].contains('/'))
            .filter_map(|k| self.lookup(view, k).cloned())
            .collect())
    }
    pub fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        self.listing(&self.load()?.view, &normalize(path)?)
    }
    fn bytes(&self, state: &State, path: &str) -> Result<Vec<u8>> {
        let entry = self.lookup(&state.view, path).ok_or(Error::NotFound)?;
        if entry.directory {
            return Err(Error::Unsupported);
        }
        let content = if state.view.upper.contains_key(path) {
            bounded_read(
                &self.blob_path(entry.digest.as_deref().ok_or(Error::Corrupt)?)?,
                self.config.policy.max_file_bytes,
            )?
        } else {
            let source = self.base_paths.get(path).ok_or(Error::Corrupt)?;
            // The configured base must be immutable and unavailable for SMB
            // writes. Reject changed content rather than silently rebasing.
            if fs::symlink_metadata(source)?.file_type().is_symlink() {
                return Err(Error::Corrupt);
            }
            bounded_read(source, self.config.policy.max_file_bytes)?
        };
        if content.len() as u64 != entry.size || Some(digest(&content)) != entry.digest {
            return Err(Error::Corrupt);
        }
        Ok(content)
    }
    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        self.bytes(&self.load()?, &normalize(path)?)
    }
    fn blob_path(&self, hash: &str) -> Result<PathBuf> {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::Corrupt);
        }
        Ok(self.namespace.join("blobs").join(hash))
    }
    fn put_blob(&self, content: &[u8]) -> Result<String> {
        if content.len() as u64 > self.config.policy.max_file_bytes
            || content.len() as u64 > self.config.policy.temporary_bytes
        {
            return Err(Error::Quota);
        }
        let hash = digest(content);
        let path = self.blob_path(&hash)?;
        if path.exists() {
            if digest(&bounded_read(&path, self.config.policy.max_file_bytes)?) != hash {
                return Err(Error::Corrupt);
            }
        } else {
            let physical = tree_bytes(&self.namespace.join("blobs"))?;
            let limit = self
                .config
                .policy
                .active_bytes
                .saturating_add(self.config.policy.retained_bytes)
                .saturating_add(self.config.policy.temporary_bytes);
            if physical.saturating_add(content.len() as u64) > limit {
                return Err(Error::Quota);
            }
            let mut file = AtomicWriteFile::open(&path)?;
            file.write_all(content)?;
            file.commit()?;
            #[cfg(unix)]
            File::open(self.namespace.join("blobs"))?.sync_all()?;
        }
        Ok(hash)
    }
    fn event(
        &self,
        state: &mut State,
        actor: &str,
        operation: &str,
        path: Option<String>,
        object_id: Option<String>,
    ) -> Result<()> {
        if actor.is_empty() || actor.len() > 256 {
            return Err(Error::Path);
        }
        if state.history.len() >= self.config.policy.history_limit {
            return Err(Error::Quota);
        }
        state.revision = state.revision.checked_add(1).ok_or(Error::Quota)?;
        state.history.push(Event {
            sequence: state.revision,
            revision: state.revision,
            generation: state.generation.clone(),
            actor: actor.to_string(),
            operation: operation.to_string(),
            path,
            object_id,
            at: now(),
            job_id: None,
        });
        Ok(())
    }
    fn publish_file(&self, state: &mut State, path: &str, content: &[u8]) -> Result<()> {
        if content.len() as u64 > self.config.policy.max_file_bytes {
            return Err(Error::Quota);
        }
        if !self.parent_exists(&state.view, path) {
            return Err(Error::NotFound);
        }
        if self.lookup(&state.view, path).is_some_and(|e| e.directory) {
            return Err(Error::Unsupported);
        }
        let entry = Entry {
            object_id: self
                .lookup(&state.view, path)
                .map(|e| e.object_id.clone())
                .unwrap_or_else(id),
            name: path.rsplit('/').next().ok_or(Error::Path)?.to_string(),
            directory: false,
            size: content.len() as u64,
            digest: Some(digest(content)),
        };
        state.view.upper.insert(path.to_string(), entry);
        self.check_budget(state)?;
        self.put_blob(content)?;
        Ok(())
    }
    pub fn write_file(&self, path: &str, content: &[u8], actor: &str) -> Result<()> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        if path.is_empty() {
            return Err(Error::Path);
        }
        let mut state = self.load()?;
        self.publish_file(&mut state, &path, content)?;
        self.event(&mut state, actor, "write", Some(path), None)?;
        self.save(&state)
    }
    pub fn mkdir(&self, path: &str, actor: &str) -> Result<()> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        if path.is_empty() {
            return Err(Error::Exists);
        }
        let mut state = self.load()?;
        if self.lookup(&state.view, &path).is_some() {
            return Err(Error::Exists);
        }
        if !self.parent_exists(&state.view, &path) {
            return Err(Error::NotFound);
        }
        state.view.upper.insert(
            path.clone(),
            Entry {
                object_id: id(),
                name: path.rsplit('/').next().unwrap().to_string(),
                directory: true,
                size: 0,
                digest: None,
            },
        );
        self.check_budget(&state)?;
        self.event(&mut state, actor, "mkdir", Some(path), None)?;
        self.save(&state)
    }
    pub fn delete(&self, path: &str, actor: &str) -> Result<String> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        if path.is_empty() {
            return Err(Error::Path);
        }
        let mut state = self.load()?;
        self.delete_locked(&mut state, path, actor)
    }
    /// Delete a path only if it still has the required kind. The kind check
    /// and deletion share one lock, avoiding unlink/rmdir check-then-use races.
    pub fn delete_typed(&self, path: &str, directory: bool, actor: &str) -> Result<String> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        let mut state = self.load()?;
        if self
            .lookup(&state.view, &path)
            .ok_or(Error::NotFound)?
            .directory
            != directory
        {
            return Err(Error::Unsupported);
        }
        self.delete_locked(&mut state, path, actor)
    }
    /// Delete the currently visible object held by a private open handle,
    /// refusing to delete a replacement created at its former path.
    pub fn delete_handle(&self, handle: &Handle, actor: &str) -> Result<String> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        let _serial = self.serial()?;
        let mut state = self.load()?;
        if state.generation != handle.generation {
            return Err(Error::Revision);
        }
        let path = self.handle_path(&state, handle)?;
        self.delete_locked(&mut state, path, actor)
    }
    fn delete_locked(&self, state: &mut State, path: String, actor: &str) -> Result<String> {
        if path.is_empty() {
            return Err(Error::Path);
        }
        let entry = self
            .lookup(&state.view, &path)
            .cloned()
            .ok_or(Error::NotFound)?;
        if entry.directory && !self.listing(&state.view, &path)?.is_empty() {
            return Err(Error::NotEmpty);
        }
        let trash_id = id();
        let from_upper = state.view.upper.remove(&path).is_some();
        state.view.whiteouts.insert(path.clone());
        let created_at = now();
        state.trash.insert(
            trash_id.clone(),
            Trash {
                id: trash_id.clone(),
                path: path.clone(),
                entry,
                from_upper,
                created_at,
                expires_at: created_at.saturating_add(self.config.policy.trash_ttl_seconds),
            },
        );
        self.event(state, actor, "delete", Some(path), Some(trash_id.clone()))?;
        self.check_budget(state)?;
        self.save(state)?;
        Ok(trash_id)
    }
    pub fn rename(&self, source: &str, target: &str, replace: bool, actor: &str) -> Result<()> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let source = normalize(source)?;
        let target = normalize(target)?;
        if source.is_empty() || target.is_empty() {
            return Err(Error::Path);
        }
        let mut state = self.load()?;
        self.rename_locked(&mut state, source, target, replace, actor)
    }
    /// Rename by stable handle identity rather than a potentially reused path.
    pub fn rename_handle(
        &self,
        handle: &Handle,
        target: &str,
        replace: bool,
        actor: &str,
    ) -> Result<()> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        let _serial = self.serial()?;
        let mut state = self.load()?;
        if state.generation != handle.generation {
            return Err(Error::Revision);
        }
        let source = self.handle_path(&state, handle)?;
        self.rename_locked(&mut state, source, normalize(target)?, replace, actor)
    }
    fn rename_locked(
        &self,
        state: &mut State,
        source: String,
        target: String,
        replace: bool,
        actor: &str,
    ) -> Result<()> {
        if source.is_empty() || target.is_empty() {
            return Err(Error::Path);
        }
        let entry = self
            .lookup(&state.view, &source)
            .cloned()
            .ok_or(Error::NotFound)?;
        // Directory moves need a qualified complete-subtree transaction.
        if entry.directory {
            return Err(Error::Unsupported);
        }
        if source == target {
            return Ok(());
        }
        if self.lookup(&state.view, &target).is_some() && !replace {
            return Err(Error::Exists);
        }
        let bytes = self.bytes(state, &source)?;
        state.view.upper.remove(&source);
        state.view.whiteouts.insert(source.clone());
        self.publish_file(state, &target, &bytes)?;
        state
            .view
            .upper
            .get_mut(&target)
            .ok_or(Error::Corrupt)?
            .object_id = entry.object_id;
        self.event(
            state,
            actor,
            "rename",
            Some(format!("{source} -> {target}")),
            None,
        )?;
        self.save(state)
    }
    fn check_budget(&self, state: &State) -> Result<()> {
        let policy = &self.config.policy;
        let active = state
            .view
            .upper
            .values()
            .try_fold(0u64, |sum, e| sum.checked_add(e.size))
            .ok_or(Error::Quota)?;
        let retained = state
            .snapshots
            .values()
            .flat_map(|s| s.view.upper.values())
            .map(|e| e.size)
            .chain(
                state
                    .trash
                    .values()
                    .filter(|t| t.from_upper)
                    .map(|t| t.entry.size),
            )
            .try_fold(0u64, |sum, size| sum.checked_add(size))
            .ok_or(Error::Quota)?;
        if active > policy.active_bytes
            || state.view.upper.len() > policy.active_files
            || retained > policy.retained_bytes
            || state.snapshots.len() > policy.snapshot_limit
            || state.history.len() > policy.history_limit
        {
            return Err(Error::Quota);
        }
        Ok(())
    }
    fn revision(&self, state: &State, expected: u64) -> Result<()> {
        if state.revision != expected {
            Err(Error::Revision)
        } else {
            Ok(())
        }
    }
    fn retain(&self, state: &mut State, protected: bool) -> Result<String> {
        let snapshot_id = id();
        let created_at = now();
        state.snapshots.insert(
            snapshot_id.clone(),
            Snapshot {
                id: snapshot_id.clone(),
                generation: state.generation.clone(),
                created_at,
                expires_at: created_at.saturating_add(self.config.policy.snapshot_ttl_seconds),
                protected_until: if protected {
                    created_at.saturating_add(self.config.policy.recovery_protection_seconds)
                } else {
                    0
                },
                view: state.view.clone(),
            },
        );
        self.check_budget(state)?;
        Ok(snapshot_id)
    }
    pub fn snapshot(&self, expected: u64, actor: &str) -> Result<String> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        let result = self.snapshot_locked(&mut state, actor)?;
        self.save(&state)?;
        Ok(result)
    }
    fn snapshot_locked(&self, state: &mut State, actor: &str) -> Result<String> {
        let snapshot = self.retain(state, false)?;
        self.event(state, actor, "snapshot", None, Some(snapshot.clone()))?;
        Ok(snapshot)
    }
    pub fn reset(&self, expected: u64, actor: &str) -> Result<String> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        let result = self.reset_locked(&mut state, actor)?;
        self.save(&state)?;
        Ok(result)
    }
    fn reset_locked(&self, state: &mut State, actor: &str) -> Result<String> {
        let recovery = self.retain(state, true)?;
        state.view = View::default();
        state.generation = id();
        self.event(state, actor, "reset", None, Some(recovery.clone()))?;
        Ok(recovery)
    }
    pub fn rollback(&self, expected: u64, snapshot_id: &str, actor: &str) -> Result<String> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        let result = self.rollback_locked(&mut state, snapshot_id, actor)?;
        self.save(&state)?;
        Ok(result)
    }
    fn rollback_locked(&self, state: &mut State, snapshot_id: &str, actor: &str) -> Result<String> {
        let snapshot = state
            .snapshots
            .get(snapshot_id)
            .cloned()
            .ok_or(Error::NotFound)?;
        if snapshot.expires_at <= now() {
            return Err(Error::Retention);
        }
        self.verify_view(&snapshot.view)?;
        let recovery = self.retain(state, true)?;
        state.view = snapshot.view;
        state.generation = id();
        self.event(
            state,
            actor,
            "rollback",
            None,
            Some(snapshot_id.to_string()),
        )?;
        Ok(recovery)
    }
    fn verify_view(&self, view: &View) -> Result<()> {
        for (path, entry) in &view.upper {
            if normalize(path)? != *path {
                return Err(Error::Corrupt);
            }
            if !entry.directory {
                let hash = entry.digest.as_deref().ok_or(Error::Corrupt)?;
                let bytes =
                    bounded_read(&self.blob_path(hash)?, self.config.policy.max_file_bytes)?;
                if bytes.len() as u64 != entry.size || digest(&bytes) != hash {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }
    pub fn restore_trash(&self, expected: u64, trash_id: &str, actor: &str) -> Result<()> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        self.restore_trash_locked(&mut state, trash_id, actor)?;
        self.save(&state)?;
        Ok(())
    }
    fn restore_trash_locked(&self, state: &mut State, trash_id: &str, actor: &str) -> Result<()> {
        self.restore_trash_prepared(state, trash_id, actor, true)
    }
    // Preview shares restore validation but never publishes content or a manifest.
    fn restore_trash_prepared(
        &self,
        state: &mut State,
        trash_id: &str,
        actor: &str,
        publish: bool,
    ) -> Result<()> {
        let trash = state.trash.get(trash_id).cloned().ok_or(Error::NotFound)?;
        if trash.expires_at <= now() {
            return Err(Error::Retention);
        }
        if self.lookup(&state.view, &trash.path).is_some() {
            return Err(Error::Exists);
        }
        if !self.parent_exists(&state.view, &trash.path) {
            return Err(Error::NotFound);
        }
        if trash.from_upper {
            state.view.upper.insert(trash.path.clone(), trash.entry);
            self.verify_view(&state.view)?;
        } else {
            // Keep directory opacity: removing an ancestor whiteout could
            // expose unrelated siblings. A restored base file is copied up.
            if trash.entry.directory {
                state.view.upper.insert(trash.path.clone(), trash.entry);
            } else {
                let pinned = State {
                    view: View::default(),
                    ..state.clone()
                };
                let bytes = self.bytes(&pinned, &trash.path)?;
                if publish {
                    self.publish_file(state, &trash.path, &bytes)?;
                } else {
                    if bytes.len() as u64 > self.config.policy.temporary_bytes {
                        return Err(Error::Quota);
                    }
                    let blob = self.blob_path(&digest(&bytes))?;
                    if blob.exists()
                        && digest(&bounded_read(&blob, self.config.policy.max_file_bytes)?)
                            != digest(&bytes)
                    {
                        return Err(Error::Corrupt);
                    }
                    state
                        .view
                        .upper
                        .insert(trash.path.clone(), trash.entry.clone());
                    self.check_budget(state)?;
                }
                state
                    .view
                    .upper
                    .get_mut(&trash.path)
                    .ok_or(Error::Corrupt)?
                    .object_id = trash.entry.object_id;
            }
        }
        state.trash.remove(trash_id);
        self.event(
            state,
            actor,
            "restore-trash",
            Some(trash.path),
            Some(trash_id.to_string()),
        )?;
        Ok(())
    }
    pub fn purge_trash(&self, expected: u64, trash_id: &str, actor: &str) -> Result<()> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        self.purge_trash_locked(&mut state, trash_id, actor)?;
        self.save(&state)?;
        Ok(())
    }
    fn purge_trash_locked(&self, state: &mut State, trash_id: &str, actor: &str) -> Result<()> {
        let trash = state.trash.remove(trash_id).ok_or(Error::NotFound)?;
        // The whiteout remains: purge must not resurrect the base entry.
        self.event(
            state,
            actor,
            "purge-trash",
            Some(trash.path),
            Some(trash_id.to_string()),
        )?;
        Ok(())
    }
    pub fn delete_snapshot(&self, expected: u64, snapshot_id: &str, actor: &str) -> Result<()> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        self.delete_snapshot_locked(&mut state, snapshot_id, actor)?;
        self.save(&state)?;
        Ok(())
    }
    fn delete_snapshot_locked(
        &self,
        state: &mut State,
        snapshot_id: &str,
        actor: &str,
    ) -> Result<()> {
        let snapshot = state.snapshots.get(snapshot_id).ok_or(Error::NotFound)?;
        if snapshot.protected_until > now() {
            return Err(Error::Retention);
        }
        state.snapshots.remove(snapshot_id);
        self.event(
            state,
            actor,
            "delete-snapshot",
            None,
            Some(snapshot_id.to_string()),
        )?;
        Ok(())
    }
    fn backup_namespace(&self, destination: &BackupDestination) -> Result<PathBuf> {
        if destination.id.is_empty()
            || destination.failure_domain.is_empty()
            || destination.ttl_seconds == 0
            || destination.count_limit == 0
            || destination.byte_limit == 0
            || !destination.root.is_absolute()
        {
            return Err(Error::Path);
        }
        let root = fs::canonicalize(&destination.root)?;
        if root.starts_with(&self.config.base)
            || self.config.base.starts_with(&root)
            || root.starts_with(&self.config.root)
            || self.config.root.starts_with(&root)
        {
            return Err(Error::Path);
        }
        let namespace = root.join(self.namespace.file_name().ok_or(Error::Path)?);
        fs::create_dir_all(&namespace)?;
        Ok(namespace)
    }
    /// Capture a quiescent shadow-only backup. Base files are references, not
    /// payload. Content hashes are verified before publishing its manifest.
    pub fn backup(
        &self,
        expected: u64,
        destination: &BackupDestination,
        actor: &str,
    ) -> Result<String> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        self.verify_view(&state.view)?;
        let namespace = self.backup_namespace(destination)?;
        // Count incomplete captures as well: interrupted staging cannot provide
        // unlimited storage outside the declared backup budget.
        let existing: Vec<_> = fs::read_dir(&namespace)?.collect::<std::io::Result<_>>()?;
        if existing.len() >= destination.count_limit {
            return Err(Error::Quota);
        }
        let physical = tree_bytes(&namespace)?;
        let hashes: BTreeSet<_> = state
            .view
            .upper
            .values()
            .filter_map(|e| e.digest.as_ref())
            .cloned()
            .collect();
        let mut payload = BTreeMap::new();
        let mut size = 0u64;
        for hash in &hashes {
            let bytes = bounded_read(&self.blob_path(hash)?, self.config.policy.max_file_bytes)?;
            if digest(&bytes) != *hash {
                return Err(Error::Corrupt);
            }
            size = size.checked_add(bytes.len() as u64).ok_or(Error::Quota)?;
            payload.insert(hash.clone(), bytes);
        }
        if size > self.config.policy.temporary_bytes {
            return Err(Error::Quota);
        }
        let backup_id = id();
        let created_at = now();
        let backup = Backup {
            schema: 1,
            id: backup_id.clone(),
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
        let metadata_bytes = serde_json::to_vec(&backup)?.len() as u64;
        if physical.saturating_add(size).saturating_add(metadata_bytes) > destination.byte_limit {
            return Err(Error::Quota);
        }
        // Check history/metadata budget before creating any external payload.
        state.backups.insert(backup_id.clone(), backup.clone());
        self.event(&mut state, actor, "backup", None, Some(backup_id.clone()))?;
        self.check_budget(&state)?;
        let path = namespace.join(&backup_id);
        fs::create_dir(&path)?;
        fs::create_dir(path.join("blobs"))?;
        for (hash, bytes) in payload {
            let mut file = AtomicWriteFile::open(path.join("blobs").join(hash))?;
            file.write_all(&bytes)?;
            file.commit()?;
        }
        #[cfg(unix)]
        File::open(path.join("blobs"))?.sync_all()?;
        atomic_json(&path.join("manifest.json"), &backup)?;
        #[cfg(unix)]
        {
            File::open(&path)?.sync_all()?;
            File::open(&namespace)?.sync_all()?;
        }
        self.save(&state)?;
        Ok(backup_id)
    }
    /// Discover backups by their protected configured namespace, including
    /// after loss of the upper store's local index. Incomplete captures have
    /// no committed manifest and are not reported as usable backups.
    pub fn list_backups(&self, destination: &BackupDestination) -> Result<Vec<Backup>> {
        let _lease = self.lease()?;
        let _serial = self.serial()?;
        let namespace = self.backup_namespace(destination)?;
        let mut backups = Vec::new();
        for entry in fs::read_dir(namespace)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir()
                || Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err()
            {
                return Err(Error::Corrupt);
            }
            let path = entry.path().join("manifest.json");
            if !path.exists() {
                continue;
            }
            backups.push(self.backup_manifest(destination, &entry.file_name().to_string_lossy())?);
        }
        backups.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(backups)
    }
    fn backup_manifest(&self, destination: &BackupDestination, backup_id: &str) -> Result<Backup> {
        let parsed = Uuid::parse_str(backup_id).map_err(|_| Error::Path)?;
        if parsed.to_string() != backup_id {
            return Err(Error::Path);
        }
        let namespace = self.backup_namespace(destination)?;
        let backup: Backup = serde_json::from_slice(&bounded_read(
            &namespace.join(backup_id).join("manifest.json"),
            16 * 1024 * 1024,
        )?)?;
        if backup.schema != 1
            || backup.identity != self.config.identity
            || backup.base_digest != self.base_digest
            || backup.id != backup_id
            || backup.destination_id != destination.id
        {
            return Err(Error::Corrupt);
        }
        Ok(backup)
    }
    pub fn restore_backup(
        &self,
        expected: u64,
        destination: &BackupDestination,
        backup_id: &str,
        actor: &str,
    ) -> Result<String> {
        let _maintenance = self.maintenance()?;
        let _serial = self.serial()?;
        let mut state = self.load()?;
        self.revision(&state, expected)?;
        let result = self.restore_backup_locked(&mut state, destination, backup_id, actor)?;
        self.save(&state)?;
        Ok(result)
    }
    fn restore_backup_locked(
        &self,
        state: &mut State,
        destination: &BackupDestination,
        backup_id: &str,
        actor: &str,
    ) -> Result<String> {
        let backup = self.backup_manifest(destination, backup_id)?;
        if backup.expires_at <= now() {
            return Err(Error::Retention);
        }
        if backup.bytes > self.config.policy.temporary_bytes {
            return Err(Error::Quota);
        }
        let path = self
            .backup_namespace(destination)?
            .join(backup_id)
            .join("blobs");
        let mut payload = BTreeMap::new();
        let mut actual_size = 0u64;
        for (logical, entry) in &backup.view.upper {
            if normalize(logical)? != *logical || entry.size > self.config.policy.max_file_bytes {
                return Err(Error::Corrupt);
            }
            if entry.directory {
                continue;
            }
            let hash = entry.digest.as_deref().ok_or(Error::Corrupt)?;
            self.blob_path(hash)?; // validate hash before using it as a host component
            let bytes = bounded_read(&path.join(hash), self.config.policy.max_file_bytes)?;
            if bytes.len() as u64 != entry.size || digest(&bytes) != hash {
                return Err(Error::Corrupt);
            }
            if !payload.contains_key(hash) {
                actual_size = actual_size
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::Quota)?;
            }
            payload.insert(hash.to_string(), bytes);
        }
        if actual_size != backup.bytes {
            return Err(Error::Corrupt);
        }
        let recovery = self.retain(state, true)?;
        state.view = backup.view;
        state.generation = id();
        state.backups.insert(
            backup_id.to_string(),
            self.backup_manifest(destination, backup_id)?,
        );
        self.event(
            state,
            actor,
            "restore-backup",
            None,
            Some(backup_id.to_string()),
        )?;
        self.check_budget(state)?;
        for bytes in payload.values() {
            self.put_blob(bytes)?;
        }
        Ok(recovery)
    }
    /// Create, truncate or open under one manifest lock. Checking existence
    /// separately from creation would race another connection's create.
    /// Destructive dispositions require write access, even for a missing file.
    pub fn create_handle(
        self: &Arc<Self>,
        path: &str,
        directory: bool,
        writable: bool,
        disposition: OpenDisposition,
        actor: &str,
    ) -> Result<(Handle, Entry, OpenAction)> {
        self.create_handle_checked(
            OpenRequest {
                path,
                directory,
                writable,
                disposition,
                actor,
            },
            |_| true,
        )
    }
    /// Reserve protocol share modes using the chosen stable object identity
    /// before any create/truncate publication. The callback must not block or
    /// re-enter this store. The adapter releases its reservation on failure.
    pub fn create_handle_checked(
        self: &Arc<Self>,
        request: OpenRequest<'_>,
        check: impl FnOnce(&Entry) -> bool,
    ) -> Result<(Handle, Entry, OpenAction)> {
        let OpenRequest {
            path,
            directory,
            writable,
            disposition,
            actor,
        } = request;
        use OpenDisposition::*;
        let lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        let mut state = self.load()?;
        let existing = if path.is_empty() {
            Some(Entry {
                object_id: "root".into(),
                name: String::new(),
                directory: true,
                size: 0,
                digest: None,
            })
        } else {
            self.lookup(&state.view, &path).cloned()
        };
        if existing
            .as_ref()
            .is_some_and(|entry| entry.directory != directory)
        {
            return Err(Error::Unsupported);
        }
        if matches!(disposition, Supersede | Overwrite | OverwriteIf) && (!writable || directory) {
            return Err(Error::Unsupported);
        }
        let action = match (&existing, disposition) {
            (Some(_), Create) => return Err(Error::Exists),
            (None, Open | Overwrite) => return Err(Error::NotFound),
            (Some(_), Open | OpenIf) => OpenAction::Opened,
            (Some(_), Supersede) => OpenAction::Superseded,
            (Some(_), Overwrite | OverwriteIf) => OpenAction::Overwritten,
            (None, _) => OpenAction::Created,
        };
        let candidate = existing.clone().unwrap_or_else(|| Entry {
            object_id: id(),
            name: path.rsplit('/').next().unwrap_or("").into(),
            directory,
            size: 0,
            digest: if directory { None } else { Some(digest(&[])) },
        });
        if !check(&candidate) {
            return Err(Error::Busy);
        }
        if action != OpenAction::Opened {
            if !writable || path.is_empty() {
                return Err(Error::Unsupported);
            }
            if directory {
                if !self.parent_exists(&state.view, &path) {
                    return Err(Error::NotFound);
                }
                state.view.upper.insert(path.clone(), candidate.clone());
                self.check_budget(&state)?;
            } else {
                // Preserve identity for existing opens. This keeps other
                // handles coherent when a client truncates a lower file.
                if action == OpenAction::Created {
                    state.view.upper.insert(path.clone(), candidate.clone());
                }
                self.publish_file(&mut state, &path, &[])?;
            }
            let operation = match action {
                OpenAction::Created => "create",
                OpenAction::Superseded => "supersede",
                OpenAction::Overwritten => "overwrite",
                OpenAction::Opened => unreachable!(),
            };
            self.event(&mut state, actor, operation, Some(path.clone()), None)?;
            self.save(&state)?;
        }
        let entry = if path.is_empty() {
            existing.ok_or(Error::NotFound)?
        } else {
            self.lookup(&state.view, &path)
                .cloned()
                .ok_or(Error::NotFound)?
        };
        let handle = Handle {
            store: self.clone(),
            path,
            object_id: entry.object_id.clone(),
            directory,
            writable,
            generation: state.generation,
            _lease: lease,
        };
        Ok((handle, entry, action))
    }

    /// Metadata resolved by object identity, including after a private rename.
    pub fn stat_handle(&self, handle: &Handle) -> Result<Entry> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        let _serial = self.serial()?;
        let state = self.load()?;
        if handle.generation != state.generation {
            return Err(Error::Revision);
        }
        if handle.object_id == "root" {
            return Ok(Entry {
                object_id: "root".into(),
                name: String::new(),
                directory: true,
                size: 0,
                digest: None,
            });
        }
        let path = self.handle_path(&state, handle)?;
        self.lookup(&state.view, &path)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Truncate or zero-extend a writable open object in one manifest commit.
    pub fn resize_handle(&self, handle: &Handle, size: u64, actor: &str) -> Result<()> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        if !handle.writable || handle.directory {
            return Err(Error::Unsupported);
        }
        if size > self.config.policy.max_file_bytes {
            return Err(Error::Quota);
        }
        let _serial = self.serial()?;
        let mut state = self.load()?;
        if handle.generation != state.generation {
            return Err(Error::Revision);
        }
        let path = self.handle_path(&state, handle)?;
        let mut content = self.bytes(&state, &path)?;
        content.resize(usize::try_from(size).map_err(|_| Error::Quota)?, 0);
        self.publish_file(&mut state, &path, &content)?;
        self.event(
            &mut state,
            actor,
            "resize",
            Some(path),
            Some(handle.object_id.clone()),
        )?;
        self.save(&state)
    }

    /// Open a coherent path handle. All subsequent reads resolve the current
    /// private object, so a read handle opened before copy-up sees later writes.
    pub fn open_handle(self: &Arc<Self>, path: &str, writable: bool) -> Result<Handle> {
        let lease = self.lease()?;
        let _serial = self.serial()?;
        let path = normalize(path)?;
        let state = self.load()?;
        let directory = if path.is_empty() {
            true
        } else {
            self.lookup(&state.view, &path)
                .ok_or(Error::NotFound)?
                .directory
        };
        let object_id = if path.is_empty() {
            "root".to_string()
        } else {
            self.lookup(&state.view, &path)
                .ok_or(Error::NotFound)?
                .object_id
                .clone()
        };
        Ok(Handle {
            store: self.clone(),
            path,
            object_id,
            directory,
            writable,
            generation: state.generation,
            _lease: lease,
        })
    }
    pub fn read_handle(&self, handle: &Handle, offset: u64, len: usize) -> Result<Vec<u8>> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        let _serial = self.serial()?;
        let state = self.load()?;
        if handle.generation != state.generation {
            return Err(Error::Revision);
        }
        let path = self.handle_path(&state, handle)?;
        let bytes = self.bytes(&state, &path)?;
        let start = usize::try_from(offset)
            .map_err(|_| Error::Quota)?
            .min(bytes.len());
        Ok(bytes[start..start.saturating_add(len).min(bytes.len())].to_vec())
    }
    pub fn write_handle(
        &self,
        handle: &Handle,
        offset: u64,
        data: &[u8],
        actor: &str,
    ) -> Result<()> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        if !handle.writable || handle.directory {
            return Err(Error::Unsupported);
        }
        let _serial = self.serial()?;
        let mut state = self.load()?;
        if handle.generation != state.generation {
            return Err(Error::Revision);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Quota)?;
        if end > self.config.policy.max_file_bytes {
            return Err(Error::Quota);
        }
        let path = self.handle_path(&state, handle)?;
        let mut bytes = self.bytes(&state, &path)?;
        bytes.resize(bytes.len().max(end as usize), 0);
        bytes[offset as usize..end as usize].copy_from_slice(data);
        self.publish_file(&mut state, &path, &bytes)?;
        self.event(&mut state, actor, "write", Some(path), None)?;
        self.save(&state)
    }
    fn handle_path(&self, state: &State, handle: &Handle) -> Result<String> {
        if self.namespace != handle.store.namespace {
            return Err(Error::Corrupt);
        }
        state
            .view
            .upper
            .iter()
            .chain(self.base.iter())
            .find(|(path, entry)| {
                entry.object_id == handle.object_id
                    && self
                        .lookup(&state.view, path)
                        .is_some_and(|visible| visible.object_id == handle.object_id)
            })
            .map(|(path, _)| path.clone())
            .ok_or(Error::NotFound)
    }
}

fn scan_base(
    root: &Path,
    dir: &Path,
    entries: &mut BTreeMap<String, Entry>,
    paths: &mut BTreeMap<String, PathBuf>,
    policy: &Policy,
) -> Result<()> {
    for item in fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || (!meta.is_dir() && !meta.is_file()) {
            return Err(Error::Path);
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Error::Path)?
            .to_str()
            .ok_or(Error::Path)?;
        let normalized = normalize(relative)?;
        if meta.len() > policy.max_file_bytes && !meta.is_dir() {
            return Err(Error::Quota);
        }
        let entry = Entry {
            object_id: digest(format!("base:{normalized}").as_bytes()),
            name: item.file_name().to_str().ok_or(Error::Path)?.to_string(),
            directory: meta.is_dir(),
            size: if meta.is_dir() { 0 } else { meta.len() },
            digest: if meta.is_dir() {
                None
            } else {
                Some(digest(&bounded_read(&path, policy.max_file_bytes)?))
            },
        };
        if entries.insert(normalized.clone(), entry).is_some() {
            return Err(Error::Exists);
        }
        paths.insert(normalized, path.clone());
        if meta.is_dir() {
            scan_base(root, &path, entries, paths, policy)?;
        }
    }
    Ok(())
}

fn tree_bytes(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for item in fs::read_dir(path)? {
        let item = item?;
        let meta = fs::symlink_metadata(item.path())?;
        if meta.file_type().is_symlink() {
            return Err(Error::Corrupt);
        }
        let bytes = if meta.is_dir() {
            tree_bytes(&item.path())?
        } else {
            meta.len()
        };
        total = total.checked_add(bytes).ok_or(Error::Quota)?;
    }
    Ok(total)
}
