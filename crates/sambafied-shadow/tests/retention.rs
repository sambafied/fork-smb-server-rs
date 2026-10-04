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
fn expire_all(state: &mut State) {
    for snapshot in state.snapshots.values_mut() {
        snapshot.created_at = 0;
        snapshot.expires_at = 1;
        snapshot.protected_until = 0;
    }
    for trash in state.trash.values_mut() {
        trash.created_at = 0;
        trash.expires_at = 1;
    }
}

#[test]
fn expiry_commits_per_object_audit_reclaims_only_last_references_and_preserves_whiteouts() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let snapshot = store.snapshot(1, "alice").unwrap();
    store.delete("SAVE.DAT", "alice").unwrap();
    store.delete("BASE.DAT", "alice").unwrap();
    let mut bob_config = lab.config.clone();
    bob_config.identity.principal = "bob".into();
    let bob = Store::open(bob_config).unwrap();
    bob.write_file("BOB.DAT", b"bob-only", "bob").unwrap();
    let bob_before = bytes(bob.namespace());
    rewrite(&store, expire_all);
    let before = store.inspect().unwrap();
    let raw_before = bytes(store.namespace());
    let preview = store.preview_expiry(before.revision).unwrap();
    assert_eq!(preview.snapshots, vec![snapshot.clone()]);
    assert_eq!(preview.trash.len(), 2);
    assert_eq!(bytes(store.namespace()), raw_before);
    assert_eq!(preview.usage.retained_bytes, 14);
    assert_eq!(preview.usage.blob_physical_bytes, 7);
    let outcome = store
        .expire_retained(before.revision, "retention-service")
        .unwrap();
    let after = store.inspect().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.view, before.view);
    assert_eq!(after.revision, before.revision + 3);
    assert!(after.snapshots.is_empty() && after.trash.is_empty());
    let events = &after.history[before.history.len()..];
    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|e| e.actor == "retention-service" && e.object_id.is_some())
    );
    assert_eq!(events[0].operation, "expire-snapshot");
    assert_eq!(events[0].object_id.as_ref(), Some(&snapshot));
    assert!(events[1..].iter().all(|e| e.operation == "expire-trash"));
    assert_eq!(outcome.usage_after.as_ref().unwrap().blob_physical_bytes, 0);
    assert!(!outcome.physical_reclamation_deferred);
    assert!(matches!(store.read("BASE.DAT"), Err(Error::NotFound)));
    assert_eq!(
        fs::read(lab.config.base.join("BASE.DAT")).unwrap(),
        b"immutable"
    );
    assert_eq!(bytes(bob.namespace()), bob_before);
    assert_eq!(bob.read("BOB.DAT").unwrap(), b"bob-only");
    let duplicate = store
        .expire_retained(after.revision, "retention-service")
        .unwrap();
    assert_eq!(duplicate.revision, after.revision);
    assert!(duplicate.snapshots.is_empty() && duplicate.trash.is_empty());
}

#[test]
fn expired_snapshot_retains_active_and_other_snapshot_deduplicated_content() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let expired = store.snapshot(1, "alice").unwrap();
    let live = store.snapshot(2, "alice").unwrap();
    rewrite(&store, |state| {
        let snapshot = state.snapshots.get_mut(&expired).unwrap();
        snapshot.created_at = 0;
        snapshot.expires_at = 1;
    });
    let usage = store.storage_usage().unwrap();
    assert_eq!(usage.active_bytes, 7);
    assert_eq!(usage.retained_bytes, 14);
    assert_eq!(usage.blob_referenced_bytes, 7);
    assert_eq!(usage.expired_snapshot_count, 1);
    let outcome = store.expire_retained(3, "retention-service").unwrap();
    assert_eq!(outcome.snapshots, vec![expired]);
    assert_eq!(outcome.usage_after.unwrap().blob_physical_bytes, 7);
    assert!(store.inspect().unwrap().snapshots.contains_key(&live));
    assert_eq!(store.read("SAVE.DAT").unwrap(), b"private");
}

#[test]
fn protection_is_not_shortened_by_expiry_or_policy_changes() {
    let mut lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let recovery = store.reset(1, "alice").unwrap();
    rewrite(&store, |state| {
        state.snapshots.get_mut(&recovery).unwrap().expires_at = 1;
    });
    lab.config.policy.recovery_protection_seconds = 1;
    lab.config.policy.snapshot_ttl_seconds = 2;
    let store = lab.open();
    let before = bytes(store.namespace());
    let preview = store.preview_expiry(2).unwrap();
    assert!(preview.snapshots.is_empty());
    assert_eq!(preview.usage.expired_snapshot_count, 1);
    assert_eq!(preview.usage.protected_snapshot_count, 1);
    let outcome = store.expire_retained(2, "retention-service").unwrap();
    assert_eq!(outcome.revision, 2);
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(outcome.usage_after.unwrap().blob_referenced_bytes, 7);
}

#[test]
fn expired_artifacts_and_their_success_receipts_remain_registered_and_charged() {
    use sambafied_shadow::{Action, ArtifactPolicy, JobStatus};
    let mut lab = Lab::new();
    lab.config.policy.retained_bytes = 65536;
    lab.config.policy.temporary_bytes = 65536;
    lab.config.policy.artifacts = Some(ArtifactPolicy {
        ttl_seconds: 3600,
        count_limit: 8,
        byte_limit: 32768,
    });
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    let accepted = store
        .submit_job(2, "alice", "export-receipt", Action::Export)
        .unwrap();
    assert_eq!(
        store
            .execute_job(&accepted.job.id, "alice", |_| Ok(()))
            .unwrap()
            .status,
        JobStatus::Succeeded
    );
    // Coherent aged receipt fixture; this is not a real-time archive expiry receipt.
    rewrite(&store, |state| {
        expire_all(state);
        let artifact = state.artifacts.get_mut(&accepted.job.id).unwrap();
        artifact.created_at = 0;
        artifact.expires_at = 1;
        state.jobs.get_mut(&accepted.job.id).unwrap().created_at = 0;
    });
    let before = store.inspect().unwrap();
    let archive = store
        .namespace()
        .join("artifacts")
        .join(format!("{}.tar", accepted.job.id));
    let archive_before = fs::read(&archive).unwrap();
    assert_eq!(store.storage_usage().unwrap().expired_artifact_count, 1);
    let result = store.expire_retained(3, "retention-service").unwrap();
    assert_eq!(result.snapshots.len(), 1);
    assert!(result.physical_reclamation_deferred);
    let after = store.inspect().unwrap();
    assert_eq!(after.artifacts, before.artifacts);
    assert_eq!(after.jobs, before.jobs);
    assert_eq!(fs::read(archive).unwrap(), archive_before);
    assert_eq!(
        result.usage_after.unwrap().retained_charged_bytes,
        archive_before.len() as u64
    );
    let replay = store
        .submit_job(2, "alice", "export-receipt", Action::Export)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.job.id, accepted.job.id);
}

#[test]
fn zero_length_orphans_still_report_deferred_physical_collection() {
    let lab = Lab::new();
    let store = lab.open();
    let directory = store.namespace().join("artifacts");
    fs::create_dir(&directory).unwrap();
    let archive = directory.join(format!("{}.tar", uuid::Uuid::new_v4()));
    fs::write(&archive, b"").unwrap();
    let blob = store
        .namespace()
        .join("blobs")
        .join("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    fs::write(&blob, b"").unwrap();
    let usage = store.storage_usage().unwrap();
    assert_eq!(usage.blob_unreferenced_bytes, 0);
    assert_eq!(usage.blob_unreferenced_count, 1);
    assert_eq!(usage.artifact_orphan_bytes, 0);
    assert_eq!(usage.artifact_orphan_count, 1);
    let result = store.expire_retained(0, "retention-service").unwrap();
    assert!(result.physical_reclamation_deferred);
    assert!(archive.exists() && blob.exists());
}

#[test]
fn full_audit_busy_stale_and_invalid_actor_leave_manifest_and_blobs_unchanged() {
    let mut lab = Lab::new();
    lab.config.policy.history_limit = 2;
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    rewrite(&store, expire_all);
    let before = bytes(store.namespace());
    let blob_before = store.storage_usage().unwrap().blob_physical_bytes;
    assert!(matches!(
        store.expire_retained(2, "retention-service"),
        Err(Error::Quota)
    ));
    assert!(matches!(
        store.expire_retained(1, "retention-service"),
        Err(Error::Revision)
    ));
    assert!(matches!(store.expire_retained(2, ""), Err(Error::Path)));
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.expire_retained(2, "retention-service"),
        Err(Error::Busy)
    ));
    assert!(matches!(store.preview_expiry(2), Err(Error::Busy)));
    drop(lease);
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(
        store.storage_usage().unwrap().blob_physical_bytes,
        blob_before
    );
}

#[test]
fn corrupted_record_key_cannot_expire_another_record() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let expired = store.snapshot(1, "alice").unwrap();
    let protected = store.reset(2, "alice").unwrap();
    rewrite(&store, |state| {
        let record = state.snapshots.get_mut(&expired).unwrap();
        record.expires_at = 1;
        record.id = protected;
    });
    let before = bytes(store.namespace());
    assert!(matches!(
        store.expire_retained(3, "retention-service"),
        Err(Error::Corrupt)
    ));
    assert_eq!(bytes(store.namespace()), before);
}

#[test]
fn physical_artifact_orphans_are_visible_and_never_deleted_as_expired_data() {
    let lab = Lab::new();
    let store = lab.open();
    let directory = store.namespace().join("artifacts");
    fs::create_dir(&directory).unwrap();
    let orphan = directory.join(format!("{}.tar", uuid::Uuid::new_v4()));
    fs::write(&orphan, b"orphan").unwrap();
    let before = bytes(store.namespace());
    let usage = store.storage_usage().unwrap();
    assert_eq!(usage.artifact_physical_bytes, 6);
    assert_eq!(usage.artifact_orphan_bytes, 6);
    assert_eq!(usage.retained_bytes, 0);
    assert_eq!(usage.retained_charged_bytes, 6);
    let result = store.expire_retained(0, "retention-service").unwrap();
    assert!(result.physical_reclamation_deferred);
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(fs::read(orphan).unwrap(), b"orphan");
}

#[cfg(windows)]
#[test]
fn committed_expiry_reports_deferred_collection_and_retry_preserves_audit() {
    use std::os::windows::fs::OpenOptionsExt;
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    store.delete("SAVE.DAT", "alice").unwrap();
    rewrite(&store, expire_all);
    let path = fs::read_dir(store.namespace().join("blobs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&path)
        .unwrap();
    let result = store.expire_retained(3, "retention-service").unwrap();
    assert!(result.physical_reclamation_deferred);
    assert_eq!(result.usage_after.unwrap().blob_unreferenced_bytes, 7);
    let state = store.inspect().unwrap();
    assert!(state.snapshots.is_empty() && state.trash.is_empty());
    assert_eq!(
        state
            .history
            .iter()
            .filter(|e| e.operation.starts_with("expire-"))
            .count(),
        2
    );
    drop(blocker);
    let reopened = lab.open();
    assert_eq!(reopened.storage_usage().unwrap().blob_unreferenced_bytes, 0);
    assert_eq!(reopened.inspect().unwrap().revision, state.revision);
}

#[test]
fn queued_and_interrupted_jobs_block_expiry_without_losing_exact_retry() {
    use sambafied_shadow::{Action, JobStatus};
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    let submission = store
        .submit_job(2, "alice", "accepted-before-expiry", Action::Snapshot)
        .unwrap();
    rewrite(&store, expire_all);
    for status in [JobStatus::Queued, JobStatus::Running] {
        rewrite(&store, |state| {
            state.jobs.get_mut(&submission.job.id).unwrap().status = status
        });
        let before = bytes(store.namespace());
        assert_eq!(store.storage_usage().unwrap().unresolved_job_count, 1);
        assert!(matches!(store.preview_expiry(2), Err(Error::Busy)));
        assert!(matches!(
            store.expire_retained(2, "retention-service"),
            Err(Error::Busy)
        ));
        assert_eq!(bytes(store.namespace()), before);
        let replay = store
            .submit_job(2, "alice", "accepted-before-expiry", Action::Snapshot)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.job.id, submission.job.id);
    }
    let completed = store
        .execute_job(&submission.job.id, "alice", |_| Ok(()))
        .unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    let outcome = store.expire_retained(3, "retention-service").unwrap();
    assert_eq!(outcome.snapshots.len(), 1);
    assert_eq!(store.job(&submission.job.id, "alice").unwrap(), completed);
}

#[cfg(windows)]
#[test]
fn failed_manifest_publication_cannot_remove_references_audit_or_blobs() {
    use std::os::windows::fs::OpenOptionsExt;
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    store.delete("SAVE.DAT", "alice").unwrap();
    rewrite(&store, expire_all);
    let before = bytes(store.namespace());
    let usage_before = store.storage_usage().unwrap();
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(store.namespace().join("state.json"))
        .unwrap();
    assert!(matches!(
        store.expire_retained(3, "retention-service"),
        Err(Error::Io(_))
    ));
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(store.storage_usage().unwrap(), usage_before);
    drop(blocker);
    assert_eq!(
        store
            .expire_retained(3, "retention-service")
            .unwrap()
            .snapshots
            .len(),
        1
    );
}

#[cfg(unix)]
#[test]
fn redirected_blob_root_fails_before_manifest_or_foreign_file_mutation() {
    use std::os::unix::fs::symlink;
    let lab = Lab::new();
    let store = lab.open();
    let outside = lab._temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let foreign = outside.join("a".repeat(64));
    fs::write(&foreign, b"foreign").unwrap();
    fs::remove_dir(store.namespace().join("blobs")).unwrap();
    symlink(&outside, store.namespace().join("blobs")).unwrap();
    let before = bytes(store.namespace());
    assert!(matches!(store.storage_usage(), Err(Error::Corrupt)));
    assert!(matches!(
        store.expire_retained(0, "retention-service"),
        Err(Error::Corrupt)
    ));
    assert_eq!(bytes(store.namespace()), before);
    assert_eq!(fs::read(foreign).unwrap(), b"foreign");
}

#[test]
fn planned_expiry_binds_cutoff_and_survives_schema_upgrade_restart_and_exact_retry() {
    use sambafied_shadow::{Action, JobStatus, RequestBinding};
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let expired = store.snapshot(1, "alice").unwrap();
    let later = store.snapshot(2, "alice").unwrap();
    store.delete("SAVE.DAT", "alice").unwrap();
    store.delete("BASE.DAT", "alice").unwrap();
    rewrite(&store, |state| {
        expire_all(state);
        state.snapshots.get_mut(&later).unwrap().expires_at = 2;
    });
    let before = store.inspect().unwrap();
    let raw = bytes(store.namespace());
    let action = Action::ExpireRetained { expired_before: 1 };
    let preview = store
        .preview_planned_action(before.revision, "alice", action.clone())
        .unwrap();
    assert_eq!(
        preview.retention.as_ref().unwrap().snapshots,
        vec![expired.clone()]
    );
    assert_eq!(preview.retention.as_ref().unwrap().trash.len(), 2);
    assert_eq!(bytes(store.namespace()), raw);
    let binding = RequestBinding {
        plan_id: uuid::Uuid::new_v4().to_string(),
        source_fingerprint: preview.fingerprint,
    };
    let accepted = store
        .submit_planned_job(
            before.revision,
            "alice",
            "expiry",
            action.clone(),
            binding.clone(),
        )
        .unwrap();
    assert_eq!(store.inspect().unwrap().schema, 6);
    assert!(
        store
            .submit_planned_job(
                before.revision,
                "alice",
                "expiry",
                action.clone(),
                binding.clone()
            )
            .unwrap()
            .replayed
    );
    assert!(matches!(
        store.submit_job(before.revision, "alice", "competitor", Action::Snapshot),
        Err(Error::Busy)
    ));
    assert!(matches!(
        store.submit_planned_job(
            before.revision,
            "alice",
            "expiry",
            Action::ExpireRetained { expired_before: 2 },
            binding.clone()
        ),
        Err(Error::Idempotency)
    ));
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.execute_job(&accepted.job.id, "alice", |_| Ok(())),
        Err(Error::Busy)
    ));
    drop(lease);
    drop(store);
    let store = lab.open();
    let completed = store
        .execute_job(&accepted.job.id, "alice", |_| Ok(()))
        .unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    let receipt = completed
        .result
        .as_ref()
        .unwrap()
        .retention
        .as_ref()
        .unwrap();
    assert_eq!(receipt.expired_before, 1);
    assert_eq!(receipt.snapshots, vec![expired]);
    assert_eq!(receipt.trash.len(), 2);
    assert_eq!(receipt.reclaimed_bytes, 0);
    let after = store.inspect().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.view, before.view);
    assert!(after.snapshots.contains_key(&later));
    assert!(after.trash.is_empty());
    assert_eq!(after.revision, before.revision + 4);
    let events = &after.history[before.history.len()..];
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|e| e.job_id.as_ref() == Some(&completed.id))
    );
    assert_eq!(events.last().unwrap().operation, "expire-retained");
    assert_eq!(
        fs::read(lab.config.base.join("BASE.DAT")).unwrap(),
        b"immutable"
    );
    assert!(matches!(store.read("BASE.DAT"), Err(Error::NotFound)));
    let terminal = bytes(store.namespace());
    assert_eq!(
        store
            .planned_submission(
                before.revision,
                "alice",
                "expiry",
                &action,
                &binding.plan_id
            )
            .unwrap(),
        Some(completed.clone())
    );
    assert_eq!(
        store
            .execute_job(&completed.id, "alice", |_| Ok(()))
            .unwrap(),
        completed
    );
    assert_eq!(bytes(store.namespace()), terminal);
    assert!(matches!(
        store.job(&completed.id, "bob"),
        Err(Error::NotFound)
    ));
}

#[test]
fn planned_expiry_requires_capacity_for_completion_and_current_authority() {
    use sambafied_shadow::{Action, JobStatus};
    let mut lab = Lab::new();
    lab.config.policy.history_limit = 3;
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    store.snapshot(1, "alice").unwrap();
    rewrite(&store, expire_all);
    let before = store.inspect().unwrap();
    let raw = bytes(store.namespace());
    let action = Action::ExpireRetained { expired_before: 1 };
    assert!(matches!(
        store.preview_planned_action(before.revision, "alice", action),
        Err(Error::Quota)
    ));
    assert_eq!(bytes(store.namespace()), raw);
    let action = Action::ExpireRetained { expired_before: 0 };
    store
        .preview_planned_action(before.revision, "alice", action.clone())
        .unwrap();
    let accepted = store
        .submit_job(before.revision, "alice", "denied", action)
        .unwrap();
    let failed = store
        .execute_job(&accepted.job.id, "alice", |_| Err(Error::Denied))
        .unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    let after = store.inspect().unwrap();
    assert_eq!(
        serde_json::to_value(&after.snapshots).unwrap(),
        serde_json::to_value(&before.snapshots).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&after.history).unwrap(),
        serde_json::to_value(&before.history).unwrap()
    );
    assert_eq!(after.revision, before.revision);
    assert!(matches!(
        store.preview_planned_action(
            after.revision,
            "alice",
            Action::ExpireRetained {
                expired_before: u64::MAX
            }
        ),
        Err(Error::Path)
    ));
}
