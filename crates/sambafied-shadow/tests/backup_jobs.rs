use sambafied_shadow::{
    Action, BackupCatalog, BackupDestination, Config, Error, Identity, Job, JobStatus, Policy,
    RequestBinding, Store,
};
use std::{fs, sync::Arc};

struct Lab {
    _temp: tempfile::TempDir,
    config: Config,
    catalog: BackupCatalog,
}
impl Lab {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let root = temp.path().join("upper");
        let backups = temp.path().join("backups");
        for path in [&base, &root, &backups] {
            fs::create_dir(path).unwrap();
        }
        fs::write(base.join("SAVE.DAT"), b"shared").unwrap();
        let destination = BackupDestination {
            id: "local".into(),
            root: backups,
            byte_limit: 32768,
            count_limit: 8,
            ttl_seconds: 86400,
            failure_domain: "same-host".into(),
        };
        Self {
            _temp: temp,
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
                    temporary_bytes: 4096,
                    max_file_bytes: 1024,
                    snapshot_limit: 20,
                    history_limit: 100,
                    snapshot_ttl_seconds: 3600,
                    recovery_protection_seconds: 300,
                    trash_ttl_seconds: 3600,
                },
            },
            catalog: [("local".into(), destination)].into(),
        }
    }
    fn open(&self) -> Arc<Store> {
        Store::open(self.config.clone()).unwrap()
    }
    fn submit(&self, store: &Store, action: Action, key: &str) -> Job {
        let revision = store.inspect().unwrap().revision;
        let preview = store
            .preview_planned_action_with_backups(revision, "alice", action.clone(), &self.catalog)
            .unwrap();
        store
            .submit_planned_job_with_backups(
                revision,
                "alice",
                key,
                action,
                RequestBinding {
                    plan_id: uuid::Uuid::new_v4().to_string(),
                    source_fingerprint: preview.fingerprint,
                },
                &self.catalog,
            )
            .unwrap()
            .job
    }
    fn execute(&self, store: &Store, job: &Job) -> Job {
        let result = store
            .execute_job_with_backups(&job.id, "alice", &self.catalog, |_| Ok(()))
            .unwrap();
        assert_eq!(result.status, JobStatus::Succeeded);
        result
    }
    fn capture(&self, store: &Store) -> String {
        let job = self.submit(
            store,
            Action::Backup {
                destination_id: "local".into(),
            },
            "capture",
        );
        let result = self.execute(store, &job);
        assert_eq!(
            result.result.as_ref().unwrap().backup_id.as_deref(),
            Some(job.id.as_str())
        );
        job.id
    }
}

#[test]
fn pure_capture_preview_and_exact_receipt_survive_restart() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"alice", "alice").unwrap();
    let original = store.inspect().unwrap();
    let state_file = store.namespace().join("state.json");
    let bytes = fs::read(&state_file).unwrap();
    let action = Action::Backup {
        destination_id: "local".into(),
    };
    let preview = store
        .preview_planned_action_with_backups(
            original.revision,
            "alice",
            action.clone(),
            &lab.catalog,
        )
        .unwrap();
    assert_eq!(preview.backups_after, 1);
    assert_eq!(fs::read(&state_file).unwrap(), bytes);
    assert_eq!(fs::read_dir(&lab.catalog["local"].root).unwrap().count(), 0);
    let binding = RequestBinding {
        plan_id: uuid::Uuid::new_v4().to_string(),
        source_fingerprint: preview.fingerprint,
    };
    let accepted = store
        .submit_planned_job_with_backups(
            original.revision,
            "alice",
            "exact",
            action.clone(),
            binding.clone(),
            &lab.catalog,
        )
        .unwrap();
    let completed = lab.execute(&store, &accepted.job);
    assert_eq!(
        completed.result.unwrap().backup_id.as_deref(),
        Some(accepted.job.id.as_str())
    );
    assert_eq!(store.list_backups(&lab.catalog["local"]).unwrap().len(), 1);
    assert!(
        store
            .inspect()
            .unwrap()
            .history
            .iter()
            .any(|e| e.operation == "backup"
                && e.job_id.as_deref() == Some(accepted.job.id.as_str()))
    );
    drop(store);
    let reopened = lab.open();
    let replay = reopened
        .submit_planned_job_with_backups(
            original.revision,
            "alice",
            "exact",
            action,
            binding,
            &lab.catalog,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.job.id, accepted.job.id);
    lab.execute(&reopened, &replay.job);
    assert_eq!(
        reopened.list_backups(&lab.catalog["local"]).unwrap().len(),
        1
    );
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"shared"
    );
}

#[test]
fn planned_backup_restore_is_pure_and_recovers_complete_upper_loss() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    store.delete("gone.dat", "alice").err(); // absent names do not fabricate entries
    let backup_id = lab.capture(&store);
    let namespace = store.namespace().to_path_buf();
    drop(store);
    fs::remove_dir_all(&namespace).unwrap();
    let recovered = lab.open();
    let action = Action::RestoreBackup {
        destination_id: "local".into(),
        backup_id: backup_id.clone(),
    };
    let before = fs::read(recovered.namespace().join("state.json")).unwrap();
    let impact = recovered
        .preview_planned_action_with_backups(0, "alice", action.clone(), &lab.catalog)
        .unwrap();
    assert_eq!(impact.recovery_retention_seconds, Some(300));
    assert_eq!(
        fs::read(recovered.namespace().join("state.json")).unwrap(),
        before
    );
    assert_eq!(
        fs::read_dir(recovered.namespace().join("blobs"))
            .unwrap()
            .count(),
        0
    );
    let job = lab.submit(&recovered, action, "restore");
    let done = lab.execute(&recovered, &job);
    assert!(done.result.unwrap().recovery_snapshot_id.is_some());
    assert_eq!(recovered.read("save.dat").unwrap(), b"saved");
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"shared"
    );
}

#[test]
fn backup_deletion_tombstone_prevents_resurrection_after_upper_loss() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let backup_id = lab.capture(&store);
    let action = Action::DeleteBackup {
        destination_id: "local".into(),
        backup_id: backup_id.clone(),
    };
    let before = store.inspect().unwrap();
    let preview = store
        .preview_planned_action_with_backups(before.revision, "alice", action.clone(), &lab.catalog)
        .unwrap();
    assert!(preview.physical_reclamation_deferred);
    assert_eq!(store.list_backups(&lab.catalog["local"]).unwrap().len(), 1);
    let job = lab.submit(&store, action, "delete");
    lab.execute(&store, &job);
    assert!(
        store
            .list_backups(&lab.catalog["local"])
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.read("save.dat").unwrap(), b"saved");
    let namespace = store.namespace().to_path_buf();
    drop(store);
    fs::remove_dir_all(namespace).unwrap();
    let reopened = lab.open();
    assert!(
        reopened
            .list_backups(&lab.catalog["local"])
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        reopened.preview_planned_action_with_backups(
            0,
            "alice",
            Action::RestoreBackup {
                destination_id: "local".into(),
                backup_id
            },
            &lab.catalog
        ),
        Err(Error::NotFound)
    ));
}

#[test]
fn revoked_authority_and_destination_quota_never_publish_backup() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let job = lab.submit(
        &store,
        Action::Backup {
            destination_id: "local".into(),
        },
        "revoked",
    );
    let mut checks = 0;
    let rejected = store
        .execute_job_with_backups(&job.id, "alice", &lab.catalog, |_| {
            checks += 1;
            if checks == 2 {
                Err(Error::Denied)
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!(rejected.status, JobStatus::Failed);
    assert_eq!(fs::read_dir(&lab.catalog["local"].root).unwrap().count(), 0);
    assert!(store.inspect().unwrap().backups.is_empty());
    let mut limited = lab.catalog.clone();
    limited.get_mut("local").unwrap().byte_limit = 1;
    let revision = store.inspect().unwrap().revision;
    assert!(matches!(
        store.preview_planned_action_with_backups(
            revision,
            "alice",
            Action::Backup {
                destination_id: "local".into()
            },
            &limited
        ),
        Err(Error::Quota)
    ));
    assert_eq!(fs::read_dir(&lab.catalog["local"].root).unwrap().count(), 0);
}

#[test]
fn changed_destination_or_external_manifest_invalidates_bound_plan() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let action = Action::Backup {
        destination_id: "local".into(),
    };
    let revision = store.inspect().unwrap().revision;
    let preview = store
        .preview_planned_action_with_backups(revision, "alice", action.clone(), &lab.catalog)
        .unwrap();
    let mut changed = lab.catalog.clone();
    changed.get_mut("local").unwrap().ttl_seconds += 1;
    assert!(matches!(
        store.submit_planned_job_with_backups(
            revision,
            "alice",
            "changed",
            action,
            RequestBinding {
                plan_id: uuid::Uuid::new_v4().to_string(),
                source_fingerprint: preview.fingerprint
            },
            &changed
        ),
        Err(Error::Revision)
    ));
    let backup_id = lab.capture(&store);
    let action = Action::RestoreBackup {
        destination_id: "local".into(),
        backup_id: backup_id.clone(),
    };
    let revision = store.inspect().unwrap().revision;
    let preview = store
        .preview_planned_action_with_backups(revision, "alice", action.clone(), &lab.catalog)
        .unwrap();
    let manifest = lab.catalog["local"]
        .root
        .join(store.namespace().file_name().unwrap())
        .join(&backup_id)
        .join("manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["failure_domain"] = "changed".into();
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(
        store.submit_planned_job_with_backups(
            revision,
            "alice",
            "external-changed",
            action,
            RequestBinding {
                plan_id: uuid::Uuid::new_v4().to_string(),
                source_fingerprint: preview.fingerprint
            },
            &lab.catalog
        ),
        Err(Error::Revision)
    ));
}

// Make the receipt destination unavailable only after the Running state is
// durable. This exercises external publication followed by a real filesystem
// failure, without relying on an implementation-only fault hook.
fn interrupt_receipt(lab: &Lab, store: &Store, job: &Job) {
    let state = store.namespace().join("state.json");
    let retained = store.namespace().join("interrupted-state.json");
    let mut checks = 0;
    let result = store.execute_job_with_backups(&job.id, "alice", &lab.catalog, |_| {
        checks += 1;
        if checks == 2 {
            fs::rename(&state, &retained).unwrap();
            fs::create_dir(&state).unwrap();
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(checks, 2);
    fs::remove_dir(&state).unwrap();
    fs::rename(&retained, &state).unwrap();
    assert_eq!(
        store.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
}

#[test]
fn published_capture_resumes_after_receipt_failure_and_revoked_retry() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let job = lab.submit(
        &store,
        Action::Backup {
            destination_id: "local".into(),
        },
        "interrupted",
    );
    interrupt_receipt(&lab, &store, &job);
    assert_eq!(store.list_backups(&lab.catalog["local"]).unwrap().len(), 1);
    assert!(store.inspect().unwrap().backups.is_empty());
    drop(store);
    let reopened = lab.open();
    assert!(matches!(
        reopened.execute_job_with_backups(&job.id, "alice", &lab.catalog, |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    assert_eq!(
        reopened.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
    let mut changed = lab.catalog.clone();
    changed.get_mut("local").unwrap().ttl_seconds += 1;
    assert!(matches!(
        reopened.execute_job_with_backups(&job.id, "alice", &changed, |_| Ok(())),
        Err(Error::Revision)
    ));
    assert_eq!(
        reopened.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
    lab.execute(&reopened, &job);
    assert_eq!(
        reopened.list_backups(&lab.catalog["local"]).unwrap().len(),
        1
    );
    assert_eq!(
        reopened
            .inspect()
            .unwrap()
            .history
            .iter()
            .filter(|e| e.job_id.as_deref() == Some(&job.id))
            .count(),
        1
    );
    assert_eq!(reopened.read("save.dat").unwrap(), b"saved");
}

#[test]
fn published_deletion_resumes_without_resurrecting_backup() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let backup_id = lab.capture(&store);
    let job = lab.submit(
        &store,
        Action::DeleteBackup {
            destination_id: "local".into(),
            backup_id: backup_id.clone(),
        },
        "interrupted-delete",
    );
    interrupt_receipt(&lab, &store, &job);
    assert!(
        store
            .list_backups(&lab.catalog["local"])
            .unwrap()
            .is_empty()
    );
    drop(store);
    let reopened = lab.open();
    assert!(matches!(
        reopened.execute_job_with_backups(&job.id, "alice", &lab.catalog, |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    assert_eq!(
        reopened.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
    lab.execute(&reopened, &job);
    assert!(reopened.inspect().unwrap().backups.is_empty());
    assert!(
        reopened
            .list_backups(&lab.catalog["local"])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reopened
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
fn tombstones_keep_count_charged_and_deletion_reserves_storage() {
    let mut lab = Lab::new();
    lab.catalog.get_mut("local").unwrap().count_limit = 1;
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let backup_id = lab.capture(&store);
    let action = Action::DeleteBackup {
        destination_id: "local".into(),
        backup_id,
    };
    let before = fs::read(store.namespace().join("state.json")).unwrap();
    let mut full = lab.catalog.clone();
    full.get_mut("local").unwrap().byte_limit = 1;
    assert!(matches!(
        store.preview_planned_action_with_backups(
            store.inspect().unwrap().revision,
            "alice",
            action.clone(),
            &full
        ),
        Err(Error::Quota)
    ));
    assert_eq!(
        fs::read(store.namespace().join("state.json")).unwrap(),
        before
    );
    assert_eq!(store.list_backups(&lab.catalog["local"]).unwrap().len(), 1);
    let job = lab.submit(&store, action, "delete");
    lab.execute(&store, &job);
    assert!(
        store
            .list_backups(&lab.catalog["local"])
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        store.preview_planned_action_with_backups(
            store.inspect().unwrap().revision,
            "alice",
            Action::Backup {
                destination_id: "local".into()
            },
            &lab.catalog
        ),
        Err(Error::Quota)
    ));
}

#[test]
fn restore_corruption_and_open_handle_gate_do_not_activate() {
    let lab = Lab::new();
    let store = lab.open();
    store.write_file("save.dat", b"saved", "alice").unwrap();
    let backup_id = lab.capture(&store);
    let action = Action::RestoreBackup {
        destination_id: "local".into(),
        backup_id: backup_id.clone(),
    };
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.preview_planned_action_with_backups(
            store.inspect().unwrap().revision,
            "alice",
            action.clone(),
            &lab.catalog
        ),
        Err(Error::Busy)
    ));
    drop(lease);
    let job = lab.submit(&store, action, "restore-corrupt");
    let backup_path = lab.catalog["local"]
        .root
        .join(store.namespace().file_name().unwrap())
        .join(backup_id);
    let blob = fs::read_dir(backup_path.join("blobs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(blob, b"tampered").unwrap();
    let before = store.inspect().unwrap();
    let failed = store
        .execute_job_with_backups(&job.id, "alice", &lab.catalog, |_| Ok(()))
        .unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("corrupt"));
    let after = store.inspect().unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.generation, after.generation);
    assert_eq!(before.history.len(), after.history.len());
    assert_eq!(store.read("save.dat").unwrap(), b"saved");
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"shared"
    );
}
