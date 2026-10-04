use sambafied_shadow::{Config, Error, Identity, Policy, State, Store};
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
                    retained_bytes: 8192,
                    temporary_bytes: 2048,
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
fn full_history_drains_exact_batch_and_refills_without_changing_user_data() {
    let mut lab = Lab::new();
    lab.config.policy.history_limit = 1;
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    assert!(matches!(
        store.write_file("OTHER.DAT", b"blocked", "alice"),
        Err(Error::Quota)
    ));
    let before = store.inspect().unwrap();
    let manifest = bytes(store.namespace());
    let batch = store.history_audit_batch().unwrap();
    assert_eq!(batch.events.len(), 1);
    assert_eq!(bytes(store.namespace()), manifest);
    let tag = batch.fingerprint().unwrap();
    let receipt = store
        .acknowledge_history(&tag, batch.revision, "operator")
        .unwrap();
    assert!(!receipt.replayed);
    assert_eq!(receipt.checkpoint.event_count, 1);
    assert_eq!(receipt.checkpoint.first_sequence, 1);
    let after = store.inspect().unwrap();
    assert_eq!(after.schema, 8);
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        serde_json::to_value(&after.view).unwrap(),
        serde_json::to_value(&before.view).unwrap()
    );
    assert_eq!(after.revision, before.revision + 1);
    assert!(after.history.is_empty());
    assert_eq!(
        fs::read(lab.config.base.join("BASE.DAT")).unwrap(),
        b"immutable"
    );
    store.write_file("OTHER.DAT", b"next", "alice").unwrap();
    let newer = store.inspect().unwrap();
    assert_eq!(newer.history.len(), 1);
    assert!(newer.history[0].sequence > receipt.checkpoint.committed_revision);
    let replay = lab
        .open()
        .acknowledge_history(&tag, batch.revision, "operator")
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.checkpoint, receipt.checkpoint);
    assert_eq!(store.inspect().unwrap().revision, newer.revision);
    assert_eq!(store.inspect().unwrap().history.len(), 1);
    let next = store.history_audit_batch().unwrap();
    let second = store
        .acknowledge_history(&next.fingerprint().unwrap(), next.revision, "operator")
        .unwrap();
    assert!(second.checkpoint.previous_checkpoint_digest.is_some());
    assert_eq!(next.checkpoint, Some(receipt.checkpoint));
    assert_eq!(
        lab.open().inspect().unwrap().history_checkpoint,
        Some(second.checkpoint)
    );
}

#[test]
fn wrong_stale_empty_and_cross_actor_acknowledgements_preserve_state() {
    let lab = Lab::new();
    let store = lab.open();
    let empty = store.history_audit_batch().unwrap();
    assert!(matches!(
        store.acknowledge_history(&empty.fingerprint().unwrap(), empty.revision, "operator"),
        Err(Error::Path)
    ));
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let batch = store.history_audit_batch().unwrap();
    let before = bytes(store.namespace());
    for (digest, revision, actor) in [
        ("0".repeat(64), batch.revision, "operator"),
        (batch.fingerprint().unwrap(), batch.revision + 1, "operator"),
        ("invalid".into(), batch.revision, "operator"),
        (batch.fingerprint().unwrap(), batch.revision, "bad\nactor"),
    ] {
        assert!(store.acknowledge_history(&digest, revision, actor).is_err());
        assert_eq!(bytes(store.namespace()), before);
    }
    let tag = batch.fingerprint().unwrap();
    store
        .acknowledge_history(&tag, batch.revision, "operator")
        .unwrap();
    let acknowledged = bytes(store.namespace());
    assert!(matches!(
        store.acknowledge_history(&tag, batch.revision, "other"),
        Err(Error::Idempotency)
    ));
    assert_eq!(bytes(store.namespace()), acknowledged);
}

#[test]
fn accepted_jobs_and_live_leases_block_drain_and_completed_exact_retry_survives() {
    use sambafied_shadow::Action;
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let batch = store.history_audit_batch().unwrap();
    let tag = batch.fingerprint().unwrap();
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.acknowledge_history(&tag, batch.revision, "operator"),
        Err(Error::Busy)
    ));
    drop(lease);
    let job = store
        .submit_job(batch.revision, "alice", "capture", Action::Snapshot)
        .unwrap()
        .job;
    let pending = bytes(store.namespace());
    assert!(matches!(
        store.acknowledge_history(&tag, batch.revision, "operator"),
        Err(Error::Busy)
    ));
    assert_eq!(bytes(store.namespace()), pending);
    let terminal = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    let batch = store.history_audit_batch().unwrap();
    let before = store.inspect().unwrap();
    store
        .acknowledge_history(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    let after = store.inspect().unwrap();
    assert_eq!(
        serde_json::to_value(&after.jobs).unwrap(),
        serde_json::to_value(&before.jobs).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&after.snapshots).unwrap(),
        serde_json::to_value(&before.snapshots).unwrap()
    );
    let replay = lab
        .open()
        .submit_job(job.expected_revision, "alice", "capture", Action::Snapshot)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        serde_json::to_value(replay.job).unwrap(),
        serde_json::to_value(terminal).unwrap()
    );
    assert!(matches!(
        store.submit_job(job.expected_revision, "alice", "capture", Action::Reset),
        Err(Error::Idempotency)
    ));
}

#[test]
fn corrupt_or_downgraded_checkpoints_fail_closed() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let batch = store.history_audit_batch().unwrap();
    store
        .acknowledge_history(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    let valid = bytes(store.namespace());
    for mode in 0..5 {
        fs::write(store.namespace().join("state.json"), &valid).unwrap();
        rewrite(&store, |state| match mode {
            0 => state.schema = 7,
            1 => state.history_checkpoint = None,
            2 => {
                state
                    .history_checkpoint
                    .as_mut()
                    .unwrap()
                    .committed_revision += 1
            }
            3 => state.history_checkpoint.as_mut().unwrap().batch_digest = "bad".into(),
            _ => state.history.push(batch.events[0].clone()),
        });
        assert!(matches!(store.inspect(), Err(Error::Corrupt)));
    }
    fs::write(store.namespace().join("state.json"), valid).unwrap();
    assert!(lab.open().inspect().is_ok());
}

#[test]
fn subsequent_expiry_actions_preserve_checkpoint_schema_and_replay_authority() {
    use sambafied_shadow::Action;
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let batch = store.history_audit_batch().unwrap();
    let checkpoint = store
        .acknowledge_history(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap()
        .checkpoint;
    for (key, action) in [
        ("artifacts", Action::ExpireArtifacts { expired_before: 0 }),
        ("retained", Action::ExpireRetained { expired_before: 0 }),
    ] {
        let state = store.inspect().unwrap();
        let preview = store
            .preview_action(state.revision, "alice", action.clone())
            .unwrap();
        assert!(preview.retention.is_some());
        let job = store
            .submit_job(state.revision, "alice", key, action.clone())
            .unwrap()
            .job;
        let terminal = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
        let after = lab.open().inspect().unwrap();
        assert_eq!(after.schema, 8);
        assert_eq!(after.history_checkpoint, Some(checkpoint.clone()));
        assert!(
            after
                .history
                .iter()
                .all(|e| e.sequence > checkpoint.committed_revision)
        );
        let replay = store
            .submit_job(state.revision, "alice", key, action)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(
            serde_json::to_value(replay.job).unwrap(),
            serde_json::to_value(terminal).unwrap()
        );
    }
}

#[test]
fn legacy_trash_generation_is_retained_before_its_delete_event_is_archived() {
    let lab = Lab::new();
    let store = lab.open();
    let generation = store.inspect().unwrap().generation;
    let trash = store.delete("BASE.DAT", "alice").unwrap();
    assert_eq!(
        store.inspect().unwrap().trash[&trash].generation.as_deref(),
        Some(generation.as_str())
    );
    // Simulate the old supported record shape; the pending audit contains truth.
    rewrite(&store, |state| {
        state.trash.get_mut(&trash).unwrap().generation = None
    });
    let before = store.inspect().unwrap();
    let batch = store.history_audit_batch().unwrap();
    store
        .acknowledge_history(&batch.fingerprint().unwrap(), batch.revision, "operator")
        .unwrap();
    let after = lab.open().inspect().unwrap();
    assert!(after.history.is_empty());
    assert_eq!(
        after.trash[&trash].generation.as_deref(),
        Some(generation.as_str())
    );
    assert_eq!(
        after.trash[&trash].expires_at,
        before.trash[&trash].expires_at
    );
    assert_eq!(after.trash[&trash].path, before.trash[&trash].path);
    assert_eq!(
        serde_json::to_value(&after.view).unwrap(),
        serde_json::to_value(&before.view).unwrap()
    );
    assert!(after.view.whiteouts.contains(&after.trash[&trash].path));
    assert_eq!(
        fs::read(lab.config.base.join("BASE.DAT")).unwrap(),
        b"immutable"
    );
}

#[cfg(windows)]
#[test]
fn blocked_publication_keeps_complete_outbox_and_retry_commits_once() {
    use std::os::windows::fs::OpenOptionsExt;
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let batch = store.history_audit_batch().unwrap();
    let tag = batch.fingerprint().unwrap();
    let before = bytes(store.namespace());
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(store.namespace().join("state.json"))
        .unwrap();
    assert!(matches!(
        store.acknowledge_history(&tag, batch.revision, "operator"),
        Err(Error::Io(_))
    ));
    assert_eq!(bytes(store.namespace()), before);
    drop(blocker);
    assert!(
        !store
            .acknowledge_history(&tag, batch.revision, "operator")
            .unwrap()
            .replayed
    );
    assert!(
        store
            .acknowledge_history(&tag, batch.revision, "operator")
            .unwrap()
            .replayed
    );
}
