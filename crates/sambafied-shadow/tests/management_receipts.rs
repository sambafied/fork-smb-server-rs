use sambafied_shadow::{Action, Config, Error, Identity, JobStatus, Policy, Store};
use std::{fs, sync::Arc};

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
        fs::write(base.join("SAVE.DAT"), b"original").unwrap();
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
                },
            },
            _temp: temp,
        }
    }
    fn open(&self) -> Arc<Store> {
        Store::open(self.config.clone()).unwrap()
    }
}

#[test]
fn reset_receipt_data_history_and_recovery_commit_together_and_retry_once() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"private", "alice").unwrap();
    let before = store.inspect().unwrap();
    let submitted = store
        .submit_job(before.revision, "alice", "reset-once", Action::Reset)
        .unwrap();
    assert!(!submitted.replayed);
    assert_eq!(store.inspect().unwrap().revision, before.revision);
    let completed = store
        .execute_job(&submitted.job.id, "alice", |_| Ok(()))
        .unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    let result = completed.result.as_ref().unwrap();
    assert_eq!(result.revision, before.revision + 1);
    assert_ne!(result.generation, before.generation);
    assert_eq!(store.read("save.dat").unwrap(), b"original");
    let state = store.inspect().unwrap();
    let recovery = &state.snapshots[result.recovery_snapshot_id.as_ref().unwrap()];
    assert_eq!(recovery.view, before.view);
    assert!(recovery.protected_until > recovery.created_at);
    assert_eq!(
        state.history.last().unwrap().job_id.as_deref(),
        Some(completed.id.as_str())
    );
    let bytes = fs::read(store.namespace().join("state.json")).unwrap();
    drop(store);
    let store = lab.open();
    let retry = store
        .submit_job(before.revision, "alice", "reset-once", Action::Reset)
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.job, completed);
    assert_eq!(
        store
            .execute_job(&completed.id, "alice", |_| Ok(()))
            .unwrap(),
        completed
    );
    assert_eq!(
        fs::read(store.namespace().join("state.json")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"original"
    );
}

#[test]
fn changed_input_or_actor_cannot_reuse_or_read_a_receipt() {
    let lab = Lab::new();
    let store = lab.open();
    let job = store
        .submit_job(0, "alice", "key", Action::Snapshot)
        .unwrap()
        .job;
    let bytes = fs::read(store.namespace().join("state.json")).unwrap();
    assert!(matches!(
        store.submit_job(0, "alice", "key", Action::Reset),
        Err(Error::Idempotency)
    ));
    assert!(matches!(
        store.submit_job(1, "alice", "key", Action::Snapshot),
        Err(Error::Idempotency)
    ));
    assert!(matches!(store.job(&job.id, "bob"), Err(Error::NotFound)));
    assert!(matches!(
        store.execute_job(&job.id, "bob", |_| panic!("cross-actor callback")),
        Err(Error::NotFound)
    ));
    assert_eq!(
        fs::read(store.namespace().join("state.json")).unwrap(),
        bytes
    );
    // A key is scoped to the actor and namespace, rather than a global key.
    let other = store
        .submit_job(0, "bob", "key", Action::Snapshot)
        .unwrap()
        .job;
    assert_ne!(other.id, job.id);
}

#[test]
fn revoked_authorization_before_activation_preserves_data_and_recovery_budget() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"private", "alice").unwrap();
    let before = store.inspect().unwrap();
    let job = store
        .submit_job(before.revision, "alice", "key", Action::Reset)
        .unwrap()
        .job;
    let mut calls = 0;
    let failed = store
        .execute_job(&job.id, "alice", |_| {
            calls += 1;
            if calls == 1 {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(failed.status, JobStatus::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("denied"));
    let state = lab.open().inspect().unwrap();
    assert_eq!(state.view, before.view);
    assert_eq!(state.revision, before.revision);
    assert_eq!(state.generation, before.generation);
    assert_eq!(state.snapshots.len(), before.snapshots.len());
    assert_eq!(state.history.len(), before.history.len());
    assert_eq!(store.read("save.dat").unwrap(), b"private");
    // No terminal receipt bypasses current authorization.
    assert!(matches!(
        store.execute_job(&job.id, "alice", |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
}

#[test]
fn stale_dequeue_and_busy_lease_never_force_or_repeat_mutation() {
    let lab = Lab::new();
    let store = lab.open();
    let job = store
        .submit_job(0, "alice", "key", Action::Reset)
        .unwrap()
        .job;
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.execute_job(&job.id, "alice", |_| Ok(())),
        Err(Error::Busy)
    ));
    assert_eq!(
        store.job(&job.id, "alice").unwrap().status,
        JobStatus::Queued
    );
    drop(lease);
    store.write_file("save.dat", b"new-write", "alice").unwrap();
    let failed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("revision-changed"));
    assert_eq!(lab.open().read("save.dat").unwrap(), b"new-write");
    assert_eq!(store.inspect().unwrap().snapshots.len(), 0);
}

#[test]
fn running_receipt_resumes_after_reopen_without_losing_intervening_smb_writes() {
    let lab = Lab::new();
    let store = lab.open();
    let job = store
        .submit_job(0, "alice", "key", Action::Snapshot)
        .unwrap()
        .job;
    // Simulate a process exit after publishing Running, before staging data.
    let path = store.namespace().join("state.json");
    let mut state = store.inspect().unwrap();
    state.jobs.get_mut(&job.id).unwrap().status = JobStatus::Running;
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    drop(store);
    let store = lab.open();
    let completed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    store
        .write_file("save.dat", b"later-smb-write", "alice")
        .unwrap();
    assert_eq!(lab.open().job(&job.id, "alice").unwrap(), completed);
    assert_eq!(
        store
            .inspect()
            .unwrap()
            .history
            .iter()
            .filter(|e| e.job_id.as_deref() == Some(&job.id))
            .count(),
        1
    );
}

#[test]
fn snapshot_rollback_and_trash_jobs_preserve_generation_and_whiteout_rules() {
    let lab = Lab::new();
    let store = lab.open();
    let run = |key: &str, action| {
        let revision = store.inspect().unwrap().revision;
        let job = store
            .submit_job(revision, "alice", key, action)
            .unwrap()
            .job;
        let done = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
        assert_eq!(done.status, JobStatus::Succeeded);
        done.result.unwrap()
    };
    let snap = run("snapshot", Action::Snapshot).snapshot_id.unwrap();
    store.write_file("save.dat", b"private", "alice").unwrap();
    run(
        "rollback",
        Action::Rollback {
            snapshot_id: snap.clone(),
        },
    );
    assert_eq!(store.read("save.dat").unwrap(), b"original");
    run(
        "delete-snapshot",
        Action::DeleteSnapshot { snapshot_id: snap },
    );
    let trash = store.delete("save.dat", "alice").unwrap();
    run("restore", Action::RestoreTrash { trash_id: trash });
    assert_eq!(store.read("save.dat").unwrap(), b"original");
    let trash = store.delete("save.dat", "alice").unwrap();
    run("purge", Action::PurgeTrash { trash_id: trash });
    assert!(matches!(lab.open().read("save.dat"), Err(Error::NotFound)));
}

#[test]
fn migration_requires_quiescence_and_unknown_schema_fields_fail_closed() {
    let lab = Lab::new();
    let store = lab.open();
    let path = store.namespace().join("state.json");
    let mut legacy = serde_json::to_value(store.inspect().unwrap()).unwrap();
    legacy["schema"] = 1.into();
    legacy.as_object_mut().unwrap().remove("jobs");
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let lease = store.lease().unwrap();
    assert!(matches!(Store::open(lab.config.clone()), Err(Error::Busy)));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap()["schema"],
        1
    );
    drop(lease);
    assert_eq!(lab.open().inspect().unwrap().schema, 2);
    let mut future = serde_json::to_value(store.inspect().unwrap()).unwrap();
    future["future_management_records"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(matches!(
        Store::open(lab.config.clone()),
        Err(Error::Json(_))
    ));
}

#[test]
fn recovery_capacity_failure_and_first_authorization_denial_do_not_activate() {
    let mut lab = Lab::new();
    lab.config.policy.snapshot_limit = 1;
    let store = lab.open();
    store.snapshot(0, "alice").unwrap();
    store.write_file("save.dat", b"private", "alice").unwrap();
    let before = store.inspect().unwrap();
    let job = store
        .submit_job(before.revision, "alice", "no-room", Action::Reset)
        .unwrap()
        .job;
    let failed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(failed.error_code.as_deref(), Some("quota"));
    let job = store
        .submit_job(before.revision, "alice", "denied", Action::Reset)
        .unwrap()
        .job;
    let failed = store
        .execute_job(&job.id, "alice", |_| Err(Error::Denied))
        .unwrap();
    assert_eq!(failed.error_code.as_deref(), Some("denied"));
    let after = lab.open().inspect().unwrap();
    assert_eq!(after.view, before.view);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.snapshots.len(), 1);
    assert_eq!(after.history.len(), before.history.len());
}
