use sambafied_shadow::{Action, Config, Error, Identity, JobStatus, Policy, RequestBinding, Store};
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

fn stored_files(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(
        root: &std::path::Path,
        current: &std::path::Path,
        result: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn binding(store: &Store, revision: u64, action: Action) -> RequestBinding {
    RequestBinding {
        plan_id: uuid::Uuid::new_v4().to_string(),
        source_fingerprint: store
            .preview_planned_action(revision, "alice", action)
            .unwrap()
            .fingerprint,
    }
}

#[test]
fn planned_request_survives_restart_and_retries_exactly_once() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let request = binding(&store, revision, Action::Reset);
    let job = store
        .submit_planned_job(
            revision,
            "alice",
            "secret-key",
            Action::Reset,
            request.clone(),
        )
        .unwrap()
        .job;
    assert!(
        !String::from_utf8(fs::read(store.namespace().join("state.json")).unwrap())
            .unwrap()
            .contains("secret-key")
    );
    // A crash after Running is durable must not invalidate its own fingerprint.
    let mut state = store.inspect().unwrap();
    state.jobs.get_mut(&job.id).unwrap().status = JobStatus::Running;
    fs::write(
        store.namespace().join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    drop(store);
    let store = lab.open();
    let done = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(done.status, JobStatus::Succeeded);
    let before = stored_files(store.namespace());
    assert_eq!(
        store
            .planned_submission(
                revision,
                "alice",
                "secret-key",
                &Action::Reset,
                &request.plan_id
            )
            .unwrap(),
        Some(done.clone())
    );
    assert!(
        store
            .submit_planned_job(
                revision,
                "alice",
                "secret-key",
                Action::Reset,
                request.clone()
            )
            .unwrap()
            .replayed
    );
    assert_eq!(
        store.execute_job(&job.id, "alice", |_| Ok(())).unwrap(),
        done
    );
    assert_eq!(stored_files(store.namespace()), before);
    let mut changed = request;
    changed.plan_id = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        store.submit_planned_job(
            revision,
            "alice",
            "secret-key",
            Action::Reset,
            changed.clone()
        ),
        Err(Error::Idempotency)
    ));
    assert!(matches!(
        store.planned_submission(
            revision,
            "alice",
            "secret-key",
            &Action::Reset,
            &changed.plan_id
        ),
        Err(Error::Idempotency)
    ));
    assert_eq!(
        store
            .planned_submission(
                revision,
                "bob",
                "secret-key",
                &Action::Reset,
                &changed.plan_id
            )
            .unwrap(),
        None
    );
}

#[test]
fn planned_admission_detects_journal_changes_without_a_revision_change() {
    let lab = Lab::new();
    let store = lab.open();
    let request = binding(&store, 0, Action::Reset);
    store
        .submit_job(0, "alice", "other", Action::Snapshot)
        .unwrap();
    let before = stored_files(store.namespace());
    assert!(matches!(
        store.submit_planned_job(0, "alice", "new", Action::Reset, request),
        Err(Error::Revision)
    ));
    assert_eq!(stored_files(store.namespace()), before);
}

#[test]
fn planned_execution_rechecks_policy_after_restart_without_activating() {
    let mut lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let before = store.inspect().unwrap();
    let request = binding(&store, before.revision, Action::Reset);
    let job = store
        .submit_planned_job(before.revision, "alice", "policy", Action::Reset, request)
        .unwrap()
        .job;
    drop(store);
    lab.config.policy.retained_bytes -= 1;
    let store = lab.open();
    let failed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("revision-changed"));
    let after = store.inspect().unwrap();
    assert_eq!(after.view, before.view);
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        serde_json::to_value(&after.snapshots).unwrap(),
        serde_json::to_value(&before.snapshots).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&after.history).unwrap(),
        serde_json::to_value(&before.history).unwrap()
    );
}

#[test]
fn planned_trash_restore_retains_protected_recovery_and_matches_preview() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let trash = store.delete("SAVE.DAT", "alice").unwrap();
    let before = store.inspect().unwrap();
    let files = stored_files(store.namespace());
    let action = Action::RestoreTrash { trash_id: trash };
    let impact = store
        .preview_planned_action(before.revision, "alice", action.clone())
        .unwrap();
    assert_eq!(impact.recovery_retention_seconds, Some(300));
    assert_eq!(stored_files(store.namespace()), files);
    let request = RequestBinding {
        plan_id: uuid::Uuid::new_v4().to_string(),
        source_fingerprint: impact.fingerprint,
    };
    let job = store
        .submit_planned_job(before.revision, "alice", "restore", action, request)
        .unwrap()
        .job;
    let done = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(done.status, JobStatus::Succeeded);
    let after = store.inspect().unwrap();
    assert_ne!(after.generation, before.generation);
    assert_eq!(after.snapshots.len(), impact.snapshots_after);
    assert_eq!(after.trash.len(), impact.trash_after);
    let recovery_id = done.result.unwrap().recovery_snapshot_id.unwrap();
    let recovery = &after.snapshots[&recovery_id];
    assert_eq!(recovery.view, before.view);
    assert!(recovery.protected_until > recovery.created_at);
    assert_eq!(
        after.history.last().unwrap().job_id.as_deref(),
        Some(job.id.as_str())
    );
    assert_eq!(store.read("SAVE.DAT").unwrap(), b"private");
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"original"
    );
}

#[test]
fn action_previews_leave_all_files_unchanged_and_report_reset_recovery() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let snapshot = store
        .snapshot(store.inspect().unwrap().revision, "alice")
        .unwrap();
    store.write_file("OLD.DAT", b"deleted", "alice").unwrap();
    let trash = store.delete("OLD.DAT", "alice").unwrap();
    let state = store.inspect().unwrap();
    let before = stored_files(store.namespace());
    for action in [
        Action::Snapshot,
        Action::Reset,
        Action::Rollback {
            snapshot_id: snapshot.clone(),
        },
        Action::RestoreTrash {
            trash_id: trash.clone(),
        },
        Action::PurgeTrash { trash_id: trash },
        Action::DeleteSnapshot {
            snapshot_id: snapshot,
        },
    ] {
        let impact = store
            .preview_action(state.revision, "alice", action.clone())
            .unwrap();
        assert_eq!(impact.action, action);
        assert_eq!(impact.revision, state.revision);
        assert_eq!(impact.generation, state.generation);
        if action == Action::Reset {
            assert_eq!(impact.affected_entries, 1);
            assert_eq!(impact.active_bytes_after, 0);
            assert_eq!(impact.recovery_retention_seconds, Some(300));
        }
        assert_eq!(stored_files(store.namespace()), before);
    }
}

#[test]
fn schema_two_jobs_migrate_unchanged_and_invalid_bindings_fail_closed() {
    let lab = Lab::new();
    let store = lab.open();
    let job = store
        .submit_job(0, "alice", "legacy", Action::Snapshot)
        .unwrap()
        .job;
    let path = store.namespace().join("state.json");
    let mut state = serde_json::to_value(store.inspect().unwrap()).unwrap();
    state["schema"] = 2.into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let lease = store.lease().unwrap();
    assert!(matches!(Store::open(lab.config.clone()), Err(Error::Busy)));
    drop(lease);
    let migrated = lab.open();
    assert_eq!(migrated.inspect().unwrap().schema, 3);
    assert_eq!(migrated.job(&job.id, "alice").unwrap(), job);
    state["jobs"][&job.id]["request_binding"] = serde_json::json!({
        "plan_id": uuid::Uuid::new_v4().to_string(),
        "source_fingerprint": "0".repeat(64)
    });
    // Schema two must never smuggle in confirmation metadata.
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        Store::open(lab.config.clone()),
        Err(Error::Corrupt)
    ));
    state["schema"] = 3.into();
    state["jobs"][&job.id]["request_binding"]["source_fingerprint"] = "Z".repeat(64).into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        Store::open(lab.config.clone()),
        Err(Error::Corrupt)
    ));
    state["schema"] = 4.into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        Store::open(lab.config.clone()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn planned_restore_requires_recovery_capacity_before_any_publication() {
    let mut lab = Lab::new();
    lab.config.policy.snapshot_limit = 1;
    let store = lab.open();
    store.snapshot(0, "alice").unwrap();
    let trash = store.delete("SAVE.DAT", "alice").unwrap();
    let before = stored_files(store.namespace());
    assert!(matches!(
        store.preview_planned_action(
            store.inspect().unwrap().revision,
            "alice",
            Action::RestoreTrash { trash_id: trash }
        ),
        Err(Error::Quota)
    ));
    assert_eq!(stored_files(store.namespace()), before);
    assert!(matches!(store.read("SAVE.DAT"), Err(Error::NotFound)));
}

#[test]
fn base_only_restore_preview_does_not_materialize_a_blob() {
    let lab = Lab::new();
    let store = lab.open();
    let trash = store.delete("SAVE.DAT", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let before = stored_files(store.namespace());
    let action = Action::RestoreTrash { trash_id: trash };
    let impact = store
        .preview_action(revision, "alice", action.clone())
        .unwrap();
    assert_eq!(impact.active_bytes_after, 8);
    assert_eq!(impact.affected_entries, 1);
    assert_eq!(impact.trash_after, 0);
    assert_eq!(stored_files(store.namespace()), before);
    assert!(matches!(store.read("SAVE.DAT"), Err(Error::NotFound)));
    let job = store
        .submit_job(revision, "alice", "restore", action)
        .unwrap()
        .job;
    assert_eq!(
        store
            .execute_job(&job.id, "alice", |_| Ok(()))
            .unwrap()
            .status,
        JobStatus::Succeeded
    );
    assert_eq!(store.read("SAVE.DAT").unwrap(), b"original");
}

#[test]
fn preview_rechecks_busy_revision_conflict_and_protected_source_without_writes() {
    let lab = Lab::new();
    let store = lab.open();
    let state = store.inspect().unwrap();
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.preview_action(state.revision, "alice", Action::Reset),
        Err(Error::Busy)
    ));
    drop(lease);
    store.write_file("SAVE.DAT", b"new", "alice").unwrap();
    assert!(matches!(
        store.preview_action(state.revision, "alice", Action::Reset),
        Err(Error::Revision)
    ));
    let recovery = store
        .reset(store.inspect().unwrap().revision, "alice")
        .unwrap();
    let before = stored_files(store.namespace());
    assert!(matches!(
        store.preview_action(
            store.inspect().unwrap().revision,
            "alice",
            Action::DeleteSnapshot {
                snapshot_id: recovery
            }
        ),
        Err(Error::Retention)
    ));
    assert_eq!(stored_files(store.namespace()), before);
    store.write_file("OLD.DAT", b"old", "alice").unwrap();
    let trash = store.delete("OLD.DAT", "alice").unwrap();
    store
        .write_file("OLD.DAT", b"replacement", "alice")
        .unwrap();
    let before = stored_files(store.namespace());
    assert!(matches!(
        store.preview_action(
            store.inspect().unwrap().revision,
            "alice",
            Action::RestoreTrash { trash_id: trash }
        ),
        Err(Error::Exists)
    ));
    assert_eq!(stored_files(store.namespace()), before);
}

#[test]
fn preview_fingerprint_binds_source_and_policy_and_recovery_quota_is_checked() {
    let mut policy_lab = Lab::new();
    let policy_store = policy_lab.open();
    let policy_before = policy_store
        .preview_action(0, "alice", Action::Snapshot)
        .unwrap();
    drop(policy_store);
    policy_lab.config.policy.retained_bytes -= 1;
    let policy_store = policy_lab.open();
    let policy_after = policy_store
        .preview_action(0, "alice", Action::Snapshot)
        .unwrap();
    assert_ne!(policy_before.fingerprint, policy_after.fingerprint);
    assert_eq!(policy_before.revision, policy_after.revision);
    assert_eq!(policy_before.generation, policy_after.generation);
    let mut lab = Lab::new();
    let store = lab.open();
    let original = store.preview_action(0, "alice", Action::Snapshot).unwrap();
    assert_eq!(
        original,
        store.preview_action(0, "alice", Action::Snapshot).unwrap()
    );
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let current = store
        .preview_action(store.inspect().unwrap().revision, "alice", Action::Snapshot)
        .unwrap();
    assert_ne!(original.fingerprint, current.fingerprint);
    drop(store);
    lab.config.policy.retained_bytes = 4;
    let store = lab.open();
    let before = stored_files(store.namespace());
    assert!(matches!(
        store.preview_action(store.inspect().unwrap().revision, "alice", Action::Reset),
        Err(Error::Quota)
    ));
    assert_eq!(stored_files(store.namespace()), before);
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
    assert_eq!(lab.open().inspect().unwrap().schema, 3);
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
