//! Per-principal merged storage. Blocking manifest/content work runs on a
//! bounded Tokio blocking pool, never on the io_uring connection thread.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use sambafied_shadow::{
    Config, Handle, OpenAction, OpenDisposition, OpenRequest, SharePolicyCatalog, Store,
};
use smb_server_proto::types::{AttrFlags, FileTime};
use smb_server_vfs::{
    CreateArgs, Entry, FileMeta, OpenCheck, OpenFile, SetOp, Vfs, VfsError, VfsResult,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
};

const READ_DATA: u32 = 0x0000_0001;
const WRITE_DATA: u32 = 0x0000_0002;
const APPEND_DATA: u32 = 0x0000_0004;
const DELETE: u32 = 0x0001_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const DIRECTORY: u32 = 1;
const NON_DIRECTORY: u32 = 0x40;
const DELETE_ON_CLOSE: u32 = 0x1000;
const WORKERS: usize = 16;

#[derive(Debug, Default)]
struct Registry {
    handles: BTreeMap<String, Vec<Weak<Handle>>>,
    pending: BTreeSet<String>,
    intents: BTreeMap<String, BTreeSet<usize>>,
}
#[derive(Debug)]
struct Inner {
    handle: Arc<Handle>,
    cursor: u64,
    deletable: bool,
    cleanup: Arc<Cleanup>,
}

#[derive(Debug)]
struct Cleanup {
    closed: std::sync::atomic::AtomicBool,
    delete: std::sync::atomic::AtomicBool,
    handle: Arc<Handle>,
    key: String,
    registry: Arc<Mutex<Registry>>,
    store: Arc<Store>,
    actor: String,
    workers: Arc<tokio::sync::Semaphore>,
}
impl Cleanup {
    fn run(&self) -> VfsResult<()> {
        use std::sync::atomic::Ordering;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut registry = registry_lock(&self.registry)?;
        if self.delete.load(Ordering::Acquire) {
            registry.pending.insert(self.key.clone());
        }
        if let Some(intents) = registry.intents.get_mut(&self.key) {
            intents.remove(&(Arc::as_ptr(&self.handle) as usize));
            if intents.is_empty() {
                registry.intents.remove(&self.key);
            }
        }
        let others = registry.handles.get_mut(&self.key).is_some_and(|handles| {
            handles.retain(|weak| {
                weak.upgrade()
                    .is_some_and(|other| !Arc::ptr_eq(&other, &self.handle))
            });
            !handles.is_empty()
        });
        if !others {
            registry.handles.remove(&self.key);
            registry.intents.remove(&self.key);
            if registry.pending.remove(&self.key) {
                self.store
                    .delete_handle(&self.handle, &self.actor)
                    .map_err(error)?;
            }
        }
        Ok(())
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if self.cleanup.closed.load(Ordering::Acquire) {
            return;
        }
        let cleanup = self.cleanup.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let workers = cleanup.workers.clone();
                if let Ok(permit) = workers.acquire_owned().await {
                    let _ = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        if let Err(error) = cleanup.run() {
                            tracing::warn!(%error, "shadow handle cleanup failed");
                        }
                    })
                    .await;
                }
            });
        } else if let Err(error) = cleanup.run() {
            tracing::warn!(%error, "shadow handle cleanup failed outside runtime");
        }
    }
}

/// One backend is constructed for one server-configured stable principal.
/// No wire request chooses the private root or principal.
#[derive(Debug)]
pub struct ShadowVfs {
    store: Arc<Store>,
    actor: String,
    key_prefix: String,
    registry: Arc<Mutex<Registry>>,
    workers: Arc<tokio::sync::Semaphore>,
}

fn error(error: sambafied_shadow::Error) -> VfsError {
    use sambafied_shadow::Error::*;
    match error {
        Io(e) => smb_server_vfs::map_io(e),
        NotFound => VfsError::NotFound,
        Exists => VfsError::AlreadyExists,
        NotEmpty => VfsError::DirectoryNotEmpty,
        Path => VfsError::InvalidArgument,
        Unsupported => VfsError::NotSupported,
        Busy => VfsError::SharingViolation,
        Revision | Quota | Corrupt | Retention | Json(_) | Denied | Idempotency => {
            VfsError::AccessDenied
        }
    }
}
fn meta(entry: &sambafied_shadow::Entry) -> FileMeta {
    FileMeta {
        // Persistent timestamps/attributes require separate qualification.
        times: [FileTime::from_unix(0, 0); 4],
        attrs: AttrFlags::new(if entry.directory {
            AttrFlags::DIRECTORY
        } else {
            AttrFlags::ARCHIVE
        }),
        alloc: entry.size.div_ceil(4096).saturating_mul(4096),
        eof: entry.size,
        is_dir: entry.directory,
    }
}
fn inner(open: &OpenFile) -> VfsResult<&Inner> {
    open.inner_as::<Inner>().ok_or(VfsError::InvalidArgument)
}
fn registry_lock(registry: &Mutex<Registry>) -> VfsResult<std::sync::MutexGuard<'_, Registry>> {
    registry.lock().map_err(|_| VfsError::AccessDenied)
}

impl ShadowVfs {
    /// Validate and open a server-owned namespace during startup.
    pub fn new(config: Config) -> VfsResult<Self> {
        let actor = config.identity.principal.clone();
        let store = Store::open(config).map_err(error)?;
        Ok(Self::from_store(store, actor))
    }
    /// Open against the trusted share authority; each operation leases current policy.
    pub fn new_with_policy_catalog(config: Config, catalog: SharePolicyCatalog) -> VfsResult<Self> {
        let actor = config.identity.principal.clone();
        let store = Store::open_with_policy_catalog(config, catalog).map_err(error)?;
        Ok(Self::from_store(store, actor))
    }
    fn from_store(store: Arc<Store>, actor: String) -> Self {
        let key_prefix = format!("{}::", store.namespace().display());
        Self {
            store,
            actor,
            key_prefix,
            registry: Arc::new(Mutex::new(Registry::default())),
            workers: Arc::new(tokio::sync::Semaphore::new(WORKERS)),
        }
    }
    async fn run<T, F>(&self, operation: F) -> VfsResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Store>, String) -> VfsResult<T> + Send + 'static,
    {
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| VfsError::AccessDenied)?;
        let store = self.store.clone();
        let actor = self.actor.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(store, actor)
        })
        .await
        .map_err(|_| VfsError::AccessDenied)?
    }
}

#[async_trait(?Send)]
impl Vfs for ShadowVfs {
    fn atomic_open_checks(&self) -> bool {
        true
    }
    async fn create(
        &self,
        rel: &str,
        is_dir: bool,
        access: u32,
        disposition: u32,
        options: u32,
        attrs: u32,
    ) -> VfsResult<(Box<OpenFile>, FileMeta, u32)> {
        self.create_checked(
            CreateArgs {
                rel,
                is_dir,
                access,
                disposition,
                options,
                attrs,
            },
            Arc::new(|_| Ok(())),
        )
        .await
    }
    async fn create_checked(
        &self,
        args: CreateArgs<'_>,
        check: OpenCheck,
    ) -> VfsResult<(Box<OpenFile>, FileMeta, u32)> {
        let CreateArgs {
            rel,
            is_dir,
            access,
            disposition,
            options,
            attrs,
        } = args;
        let disposition = match disposition {
            0 => OpenDisposition::Supersede,
            1 => OpenDisposition::Open,
            2 => OpenDisposition::Create,
            3 => OpenDisposition::OpenIf,
            4 => OpenDisposition::Overwrite,
            5 => OpenDisposition::OverwriteIf,
            _ => return Err(VfsError::InvalidArgument),
        };
        if attrs & !(AttrFlags::ARCHIVE | AttrFlags::DIRECTORY | 0x80) != 0 {
            return Err(VfsError::NotSupported);
        }
        if options & DIRECTORY != 0 && options & NON_DIRECTORY != 0 {
            return Err(VfsError::InvalidArgument);
        }
        let requested_directory = is_dir || options & DIRECTORY != 0;
        let can_read = access & (READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
        let can_write = access & (WRITE_DATA | APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
        if access & APPEND_DATA != 0 && access & (WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) == 0 {
            return Err(VfsError::NotSupported);
        }
        let deletable = access & (DELETE | GENERIC_ALL) != 0;
        if options & DELETE_ON_CLOSE != 0 && !deletable {
            return Err(VfsError::AccessDenied);
        }
        let path = sambafied_shadow::normalize(rel).map_err(error)?;
        let registry = self.registry.clone();
        let cleanup_registry = self.registry.clone();
        let workers = self.workers.clone();
        let prefix = self.key_prefix.clone();
        let (guard, metadata, action) = self
            .run(move |store, actor| {
                let mut registry = registry_lock(&registry)?;
                let directory = match store.stat(&path) {
                    Ok(existing) => {
                        let key = format!("{prefix}{}", existing.object_id);
                        if registry.pending.contains(&key)
                            || registry
                                .intents
                                .get(&key)
                                .is_some_and(|intents| !intents.is_empty())
                        {
                            return Err(VfsError::AccessDenied);
                        }
                        requested_directory || (existing.directory && options & NON_DIRECTORY == 0)
                    }
                    Err(sambafied_shadow::Error::NotFound) => requested_directory,
                    Err(e) => return Err(error(e)),
                };
                let (handle, entry, action) = store
                    .create_handle_checked(
                        OpenRequest {
                            path: &path,
                            directory,
                            writable: can_write,
                            disposition,
                            actor: &actor,
                        },
                        |entry| check(&format!("{prefix}{}", entry.object_id)).is_ok(),
                    )
                    .map_err(error)?;
                let handle = Arc::new(handle);
                let key = format!("{prefix}{}", handle.object_id);
                let handles = registry.handles.entry(key.clone()).or_default();
                handles.retain(|weak| weak.strong_count() > 0);
                handles.push(Arc::downgrade(&handle));
                if options & DELETE_ON_CLOSE != 0 {
                    registry
                        .intents
                        .entry(key.clone())
                        .or_default()
                        .insert(Arc::as_ptr(&handle) as usize);
                }
                let cleanup = Arc::new(Cleanup {
                    closed: std::sync::atomic::AtomicBool::new(false),
                    delete: std::sync::atomic::AtomicBool::new(options & DELETE_ON_CLOSE != 0),
                    handle: handle.clone(),
                    key: key.clone(),
                    registry: cleanup_registry,
                    store,
                    actor,
                    workers,
                });
                // Construct the drop guard before returning from blocking work.
                // Cancellation while joining must still clean registered handles.
                let guard = Inner {
                    handle,
                    cursor: 0,
                    deletable,
                    cleanup,
                };
                Ok((guard, meta(&entry), action))
            })
            .await?;
        let open = Box::new(OpenFile {
            path: guard.cleanup.key.clone(),
            rel: guard.handle.path.replace('/', "\\"),
            is_dir: guard.handle.directory,
            can_read,
            can_write,
            delete_on_close: options & DELETE_ON_CLOSE != 0,
            delete_pending: false,
            inner: Box::new(guard),
        });
        let action = match action {
            OpenAction::Superseded => 0,
            OpenAction::Opened => 1,
            OpenAction::Created => 2,
            OpenAction::Overwritten => 3,
        };
        Ok((open, metadata, action))
    }
    async fn read(&self, open: &mut OpenFile, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        if !open.can_read {
            return Err(VfsError::AccessDenied);
        }
        let handle = inner(open)?.handle.clone();
        self.run(move |store, _| store.read_handle(&handle, offset, len).map_err(error))
            .await
    }
    async fn write(
        &self,
        open: &mut OpenFile,
        offset: u64,
        data: &[u8],
        _write_through: bool,
    ) -> VfsResult<u64> {
        if !open.can_write {
            return Err(VfsError::AccessDenied);
        }
        let handle = inner(open)?.handle.clone();
        let bytes = data.to_vec();
        self.run(move |store, actor| {
            store
                .write_handle(&handle, offset, &bytes, &actor)
                .map_err(error)?;
            Ok(bytes.len() as u64)
        })
        .await
    }
    async fn seek(&self, open: &mut OpenFile, mode: u16, offset: i64) -> VfsResult<u64> {
        let handle = inner(open)?.handle.clone();
        let cursor = inner(open)?.cursor;
        let pos = self
            .run(move |store, _| {
                let base = match mode {
                    0 => 0,
                    1 => cursor,
                    2 => store.stat_handle(&handle).map_err(error)?.size,
                    _ => return Err(VfsError::InvalidArgument),
                };
                u64::try_from(i128::from(base) + i128::from(offset))
                    .map_err(|_| VfsError::InvalidArgument)
            })
            .await?;
        open.inner_as_mut::<Inner>()
            .ok_or(VfsError::InvalidArgument)?
            .cursor = pos;
        Ok(pos)
    }
    async fn flush(&self, open: &mut OpenFile) -> VfsResult<()> {
        let handle = inner(open)?.handle.clone();
        self.run(move |store, _| store.stat_handle(&handle).map(|_| ()).map_err(error))
            .await
    }
    async fn flush_all(&self) -> VfsResult<()> {
        Ok(())
    } // Each publication is already synced.
    async fn close(&self, open: Box<OpenFile>) -> VfsResult<()> {
        if inner(&open)?.handle.store.namespace() != self.store.namespace() {
            return Err(VfsError::AccessDenied);
        }
        let cleanup = inner(&open)?.cleanup.clone();
        cleanup.delete.store(
            open.delete_on_close || open.delete_pending,
            std::sync::atomic::Ordering::Release,
        );
        self.run(move |_, _| cleanup.run()).await
    }
    async fn mkdir(&self, rel: &str) -> VfsResult<()> {
        let rel = rel.to_string();
        self.run(move |store, actor| store.mkdir(&rel, &actor).map_err(error))
            .await
    }
    async fn rmdir(&self, rel: &str) -> VfsResult<()> {
        let rel = rel.to_string();
        self.run(move |store, actor| {
            store
                .delete_typed(&rel, true, &actor)
                .map(|_| ())
                .map_err(error)
        })
        .await
    }
    async fn check_dir(&self, rel: &str) -> VfsResult<()> {
        let metadata = self.stat(rel).await?;
        if metadata.is_dir {
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }
    async fn unlink(&self, rel: &str) -> VfsResult<()> {
        let rel = rel.to_string();
        self.run(move |store, actor| {
            store
                .delete_typed(&rel, false, &actor)
                .map(|_| ())
                .map_err(error)
        })
        .await
    }
    async fn delete_pattern(&self, _dir: &str, _pattern: &str) -> VfsResult<bool> {
        Err(VfsError::NotSupported)
    }
    async fn rename(&self, old: &str, new: &str) -> VfsResult<()> {
        let (old, new) = (old.to_string(), new.to_string());
        self.run(move |store, actor| store.rename(&old, &new, false, &actor).map_err(error))
            .await
    }
    async fn list(&self, rel: &str) -> VfsResult<Vec<Entry>> {
        let rel = rel.to_string();
        self.run(move |store, _| {
            Ok(store
                .list(&rel)
                .map_err(error)?
                .into_iter()
                .map(|entry| Entry {
                    name: entry.name.clone(),
                    meta: meta(&entry),
                })
                .collect())
        })
        .await
    }
    async fn stat(&self, rel: &str) -> VfsResult<FileMeta> {
        let rel = rel.to_string();
        let registry = self.registry.clone();
        let opaque = rel.starts_with(&self.key_prefix);
        self.run(move |store, _| {
            let entry = if opaque {
                let handle = registry_lock(&registry)?
                    .handles
                    .get(&rel)
                    .and_then(|handles| handles.iter().find_map(Weak::upgrade))
                    .ok_or(VfsError::NotFound)?;
                store.stat_handle(&handle).map_err(error)?
            } else {
                store.stat(&rel).map_err(error)?
            };
            Ok(meta(&entry))
        })
        .await
    }
    async fn set_info_open(&self, open: &mut OpenFile, op: &SetOp) -> VfsResult<()> {
        let handle = inner(open)?.handle.clone();
        match op {
            SetOp::Disposition { delete } => {
                if !inner(open)?.deletable {
                    return Err(VfsError::AccessDenied);
                }
                let cleanup = inner(open)?.cleanup.clone();
                let deleting = *delete || open.delete_on_close;
                self.run(move |store, _| {
                    store.stat_handle(&cleanup.handle).map_err(error)?;
                    let mut registry = registry_lock(&cleanup.registry)?;
                    let pointer = Arc::as_ptr(&cleanup.handle) as usize;
                    if deleting {
                        registry
                            .intents
                            .entry(cleanup.key.clone())
                            .or_default()
                            .insert(pointer);
                    } else if let Some(intents) = registry.intents.get_mut(&cleanup.key) {
                        intents.remove(&pointer);
                    }
                    cleanup
                        .delete
                        .store(deleting, std::sync::atomic::Ordering::Release);
                    Ok(())
                })
                .await?;
                open.delete_pending = *delete;
                Ok(())
            }
            SetOp::EndOfFile(size) => {
                if !open.can_write {
                    return Err(VfsError::AccessDenied);
                }
                let size = *size;
                self.run(move |store, actor| {
                    store.resize_handle(&handle, size, &actor).map_err(error)
                })
                .await
            }
            SetOp::Rename {
                replace_if_exists,
                name,
            } => {
                // Replacing another open object needs target share-mode checks.
                // Withhold replacement until those semantics are qualified.
                if *replace_if_exists {
                    return Err(VfsError::NotSupported);
                }
                if !inner(open)?.deletable {
                    return Err(VfsError::AccessDenied);
                }
                let target = name.clone();
                let replace = *replace_if_exists;
                self.run(move |store, actor| {
                    store
                        .rename_handle(&handle, &target, replace, &actor)
                        .map_err(error)
                })
                .await?;
                open.rel = sambafied_shadow::normalize(name)
                    .map_err(error)?
                    .replace('/', "\\");
                Ok(())
            }
            SetOp::Basic {
                access: None,
                write: None,
            } => {
                // Clients send unchanged timestamps before delete disposition.
                // Validate the handle without copying up or changing metadata.
                self.run(move |store, _| store.stat_handle(&handle).map(|_| ()).map_err(error))
                    .await
            }
            SetOp::Allocation(_) | SetOp::Basic { .. } | SetOp::Ea { .. } => {
                Err(VfsError::NotSupported)
            }
        }
    }
    async fn set_info_path(&self, _rel: &str, _op: &SetOp) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }
    async fn query_disk(&self) -> VfsResult<(u32, u32, u16, u16)> {
        self.run(move |store, _| {
            let (state, policy, _) = store.inspect_with_policy().map_err(error)?;
            let limit = policy.active_bytes;
            let used: u64 = state.view.upper.values().map(|entry| entry.size).sum();
            let total = limit.div_ceil(4096).min(u32::MAX as u64) as u32;
            let free = limit.saturating_sub(used).div_ceil(4096).min(total as u64) as u32;
            Ok((total, free, 8, 512))
        })
        .await
    }
    async fn set_security(&self, _rel: &str, _descriptor: &[u8]) -> VfsResult<()> {
        // Never inherit the trait's accept-and-discard ACL setter.
        Err(VfsError::NotSupported)
    }
}

/// Fail-closed placeholder for every unmapped code path of a shadow share.
/// It never holds or opens the immutable base directory.
#[derive(Debug, Default)]
pub struct UnmappedVfs;

#[async_trait(?Send)]
impl Vfs for UnmappedVfs {
    async fn create(
        &self,
        _: &str,
        _: bool,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
    ) -> VfsResult<(Box<OpenFile>, FileMeta, u32)> {
        Err(VfsError::AccessDenied)
    }
    async fn read(&self, _: &mut OpenFile, _: u64, _: usize) -> VfsResult<Vec<u8>> {
        Err(VfsError::AccessDenied)
    }
    async fn write(&self, _: &mut OpenFile, _: u64, _: &[u8], _: bool) -> VfsResult<u64> {
        Err(VfsError::AccessDenied)
    }
    async fn seek(&self, _: &mut OpenFile, _: u16, _: i64) -> VfsResult<u64> {
        Err(VfsError::AccessDenied)
    }
    async fn flush(&self, _: &mut OpenFile) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn flush_all(&self) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn close(&self, _: Box<OpenFile>) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn mkdir(&self, _: &str) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn rmdir(&self, _: &str) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn check_dir(&self, _: &str) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn unlink(&self, _: &str) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn delete_pattern(&self, _: &str, _: &str) -> VfsResult<bool> {
        Err(VfsError::AccessDenied)
    }
    async fn rename(&self, _: &str, _: &str) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn list(&self, _: &str) -> VfsResult<Vec<Entry>> {
        Err(VfsError::AccessDenied)
    }
    async fn stat(&self, _: &str) -> VfsResult<FileMeta> {
        Err(VfsError::AccessDenied)
    }
    async fn set_info_open(&self, _: &mut OpenFile, _: &SetOp) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn set_info_path(&self, _: &str, _: &SetOp) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
    async fn query_disk(&self) -> VfsResult<(u32, u32, u16, u16)> {
        Err(VfsError::AccessDenied)
    }
    async fn set_security(&self, _: &str, _: &[u8]) -> VfsResult<()> {
        Err(VfsError::AccessDenied)
    }
}
