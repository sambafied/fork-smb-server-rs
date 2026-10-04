use sambafied_shadow::{
    Action, ArtifactPolicy, Config, Error, Identity, JobStatus, Policy, State, Store,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

struct Lab {
    _temp: tempfile::TempDir,
    config: Config,
}
impl Lab {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let root = temp.path().join("private");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(base.join("BASE.DAT"), b"immutable").unwrap();
        Self {
            config: Config {
                root,
                base,
                identity: Identity {
                    organization: "org".into(),
                    share: "games".into(),
                    principal: "alice".into(),
                    base_version: "v1".into(),
                },
                policy: Policy {
                    active_bytes: 4096,
                    active_files: 20,
                    retained_bytes: 4 * 1024 * 1024,
                    temporary_bytes: 2 * 1024 * 1024,
                    max_file_bytes: 1024,
                    snapshot_limit: 20,
                    history_limit: 100,
                    snapshot_ttl_seconds: 3600,
                    recovery_protection_seconds: 300,
                    trash_ttl_seconds: 3600,
                    artifacts: None,
                },
            },
            _temp: temp,
        }
    }
    fn open(&self) -> std::sync::Arc<Store> {
        Store::open(self.config.clone()).unwrap()
    }
}
fn rewrite(store: &Store, change: impl FnOnce(&mut State)) {
    let path = store.namespace().join("state.json");
    let mut state: State = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    change(&mut state);
    fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
}
fn bytes(path: &Path) -> Vec<u8> {
    fs::read(path.join("state.json")).unwrap()
}

#[test]
fn full_live_manifest_releases_slots_without_losing_original_jobs_or_retry_authority() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let accepted = store
        .submit_job(revision, "alice", "original", Action::Snapshot)
        .unwrap()
        .job;
    let terminal = store
        .execute_job(&accepted.id, "alice", |_| Ok(()))
        .unwrap();
    rewrite(&store, |state| {
        for index in 0..1023 {
            let mut job = terminal.clone();
            job.id = uuid::Uuid::new_v4().to_string();
            job.key_digest = format!("{:x}", Sha256::digest(format!("synthetic-{index}")));
            state.jobs.insert(job.id.clone(), job);
        }
    });
    let before = store.inspect().unwrap();
    let raw = bytes(store.namespace());
    assert!(matches!(
        store.submit_job(before.revision, "alice", "new", Action::Snapshot),
        Err(Error::Quota)
    ));
    assert_eq!(bytes(store.namespace()), raw);
    let batch = store.receipt_archive_batch().unwrap();
    let digest = batch.fingerprint().unwrap();
    let archived = store
        .archive_job_receipts(&digest, batch.revision, "operator")
        .unwrap();
    let after = store.inspect().unwrap();
    assert_eq!(after.schema, 9);
    assert!(after.jobs.is_empty());
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        serde_json::to_value(&after.view).unwrap(),
        serde_json::to_value(&before.view).unwrap()
    );
    assert_eq!(store.job_receipts().unwrap(), before.jobs);
    assert_eq!(archived.reference.total_jobs, 1024);
    assert_eq!(store.job(&terminal.id, "alice").unwrap(), terminal);
    assert!(matches!(
        store.job(&terminal.id, "bob"),
        Err(Error::NotFound)
    ));
    assert_eq!(
        store
            .submit_job(revision, "alice", "original", Action::Snapshot)
            .unwrap()
            .job,
        terminal
    );
    assert!(matches!(
        store.submit_job(revision, "alice", "original", Action::Reset),
        Err(Error::Idempotency)
    ));
    let fresh = store
        .submit_job(after.revision, "alice", "new", Action::Snapshot)
        .unwrap()
        .job;
    let replay = store
        .archive_job_receipts(&digest, batch.revision, "operator")
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.reference, archived.reference);
    assert_eq!(replay.checkpoint, archived.checkpoint);
    assert_eq!(store.inspect().unwrap().jobs[&fresh.id], fresh);
    assert!(matches!(
        store.archive_job_receipts(&digest, batch.revision, "other"),
        Err(Error::Idempotency)
    ));
    assert!(matches!(
        store.execute_job(&terminal.id, "alice", |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    let restarted = lab.open();
    assert_eq!(restarted.job(&terminal.id, "alice").unwrap(), terminal);
    let usage = restarted.storage_usage().unwrap();
    assert_eq!(usage.receipt_archive_bytes, archived.reference.total_bytes);
    assert_eq!(usage.receipt_physical_bytes, archived.reference.total_bytes);
    assert_eq!(usage.receipt_orphan_bytes, 0);
    assert_eq!(usage.archived_job_count, 1024);
}

#[test]
fn export_and_retirement_jobs_remain_valid_across_archives_and_history_acknowledgement() {
    let mut lab = Lab::new();
    lab.config.policy.artifacts = Some(ArtifactPolicy {
        ttl_seconds: 1,
        count_limit: 2,
        byte_limit: 1024 * 1024,
    });
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let job = store
        .submit_job(revision, "alice", "export", Action::Export)
        .unwrap()
        .job;
    let terminal = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    let history = store.history_audit_batch().unwrap();
    let anchor = store
        .acknowledge_history(
            &history.fingerprint().unwrap(),
            history.revision,
            "operator",
        )
        .unwrap()
        .checkpoint;
    let batch = store.receipt_archive_batch().unwrap();
    store
        .archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    assert_eq!(store.inspect().unwrap().history_checkpoint, Some(anchor));
    assert_eq!(
        store
            .submit_job(revision, "alice", "export", Action::Export)
            .unwrap()
            .job,
        terminal
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    let revision = store.inspect().unwrap().revision;
    let action = Action::ExpireArtifacts {
        expired_before: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let retired = store
        .submit_job(revision, "alice", "retire", action.clone())
        .unwrap()
        .job;
    let retired = store.execute_job(&retired.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(retired.status, JobStatus::Succeeded);
    let batch = store.receipt_archive_batch().unwrap();
    let receipt = store
        .archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    assert_eq!(receipt.reference.total_jobs, 2);
    let restarted = lab.open();
    assert_eq!(restarted.job(&job.id, "alice").unwrap(), terminal);
    assert_eq!(
        restarted
            .submit_job(revision, "alice", "retire", action)
            .unwrap()
            .job,
        retired
    );
    let history = restarted.history_audit_batch().unwrap();
    restarted
        .acknowledge_history(
            &history.fingerprint().unwrap(),
            history.revision,
            "operator",
        )
        .unwrap();
    assert_eq!(restarted.inspect().unwrap().schema, 9);
    assert_eq!(restarted.job_receipts().unwrap().len(), 2);
}

#[test]
fn busy_stale_empty_quota_and_corrupt_archive_fail_closed() {
    let lab = Lab::new();
    let store = lab.open();
    let batch = store.receipt_archive_batch().unwrap();
    assert!(matches!(
        store.archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator"),
        Err(Error::Path)
    ));
    let job = store
        .submit_job(0, "alice", "snapshot", Action::Snapshot)
        .unwrap()
        .job;
    let batch = store.receipt_archive_batch().unwrap();
    let before = bytes(store.namespace());
    assert!(matches!(
        store.archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator"),
        Err(Error::Busy)
    ));
    assert_eq!(bytes(store.namespace()), before);
    store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert!(matches!(
        store.archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator"),
        Err(Error::Revision)
    ));
    let batch = store.receipt_archive_batch().unwrap();
    let active = store.open_handle("BASE.DAT", false).unwrap();
    assert!(matches!(
        store.archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator"),
        Err(Error::Busy)
    ));
    drop(active);
    let receipt = store
        .archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    let path = store
        .namespace()
        .join("receipts")
        .join(format!("{}.json", receipt.reference.sha256));
    let saved = fs::read(&path).unwrap();
    fs::write(&path, b"bad").unwrap();
    assert!(matches!(store.inspect(), Err(Error::Corrupt)));
    assert!(
        store
            .submit_job(2, "alice", "new", Action::Snapshot)
            .is_err()
    );
    fs::write(&path, saved).unwrap();
    assert!(store.inspect().is_ok());
    fs::write(
        store.namespace().join("receipts").join("unpublished"),
        b"orphan",
    )
    .unwrap();
    assert_eq!(store.storage_usage().unwrap().receipt_orphan_bytes, 6);
    rewrite(&store, |state| state.schema = 8);
    assert!(matches!(store.inspect(), Err(Error::Corrupt)));
}

#[cfg(windows)]
#[test]
fn blocked_manifest_publication_retains_live_receipts_and_charges_unpublished_chunk() {
    use std::os::windows::fs::OpenOptionsExt;
    let lab = Lab::new();
    let store = lab.open();
    let job = store
        .submit_job(0, "alice", "snapshot", Action::Snapshot)
        .unwrap()
        .job;
    let terminal = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    let batch = store.receipt_archive_batch().unwrap();
    let before = bytes(store.namespace());
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(store.namespace().join("state.json"))
        .unwrap();
    assert!(matches!(
        store.archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator"),
        Err(Error::Io(_))
    ));
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(store.job(&job.id, "alice").unwrap(), terminal);
    let usage = store.storage_usage().unwrap();
    assert!(usage.receipt_orphan_bytes > 0);
    assert_eq!(usage.receipt_archive_bytes, 0);
    drop(blocker);
    let result = store
        .archive_job_receipts(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    assert!(!result.replayed);
    assert_eq!(store.job(&job.id, "alice").unwrap(), terminal);
}
