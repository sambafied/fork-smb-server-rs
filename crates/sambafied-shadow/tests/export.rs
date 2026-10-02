use sambafied_shadow::{
    Action, ArtifactPolicy, Config, Error, ExportManifest, Identity, JobStatus, Policy,
    RequestBinding, Store,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

fn lab() -> (tempfile::TempDir, Config) {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("base");
    let root = temp.path().join("private");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&root).unwrap();
    fs::write(base.join("MASTER.DAT"), b"shared-base-must-not-be-exported").unwrap();
    fs::write(base.join("HIDDEN.DAT"), b"hidden-base").unwrap();
    fs::create_dir(base.join("LEVELS")).unwrap();
    fs::write(base.join("LEVELS/ONE.DAT"), b"shared-level").unwrap();
    let config = Config {
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
            active_files: 32,
            retained_bytes: 8192,
            temporary_bytes: 16384,
            max_file_bytes: 1024,
            snapshot_limit: 16,
            history_limit: 100,
            snapshot_ttl_seconds: 3600,
            recovery_protection_seconds: 300,
            trash_ttl_seconds: 3600,
            artifacts: None,
        },
    };
    (temp, config)
}
fn tree(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(tree(&path));
        } else {
            result.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    result
}

#[test]
fn portable_export_contains_only_consistent_upper_data_and_markers_without_mutating_storage() {
    let (temp, config) = lab();
    let alice = Store::open(config.clone()).unwrap();
    alice
        .write_file("SAVE.DAT", b"private-save", "alice")
        .unwrap();
    alice
        .write_file("DUP.DAT", b"private-save", "alice")
        .unwrap();
    alice.delete("HIDDEN.DAT", "alice").unwrap();
    alice.delete("LEVELS/ONE.DAT", "alice").unwrap();
    alice.delete("LEVELS", "alice").unwrap();
    alice.mkdir("LEVELS", "alice").unwrap();
    let mut bob_config = config.clone();
    bob_config.identity.principal = "bob".into();
    let bob = Store::open(bob_config).unwrap();
    bob.write_file("BOB.DAT", b"bob-private", "bob").unwrap();
    let state = alice.inspect().unwrap();
    let before = tree(temp.path());
    let mut bytes = vec![];
    let summary = alice.export_archive(state.revision, &mut bytes).unwrap();
    assert_eq!(summary.bytes, bytes.len() as u64);
    assert_eq!(summary.sha256, format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(summary.generation, state.generation);
    let mut members = BTreeMap::new();
    for entry in tar::Archive::new(bytes.as_slice()).entries().unwrap() {
        let mut entry = entry.unwrap();
        assert!(entry.header().entry_type().is_file());
        let name = entry.path().unwrap().to_string_lossy().to_string();
        let mut content = vec![];
        entry.read_to_end(&mut content).unwrap();
        assert!(members.insert(name, content).is_none());
    }
    assert_eq!(members.len(), 2); // manifest plus one deduplicated content blob
    let manifest_bytes = members.remove("manifest.json").unwrap();
    let manifest: ExportManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.identity, config.identity);
    assert_eq!(manifest.view, state.view);
    assert!(manifest.view.whiteouts.contains("hidden.dat"));
    assert!(manifest.view.whiteouts.contains("levels"));
    assert!(manifest.view.upper["levels"].directory);
    assert_eq!(members.values().next().unwrap(), b"private-save");
    let json = String::from_utf8(manifest_bytes).unwrap();
    assert!(!json.contains(&config.root.to_string_lossy().to_string()));
    assert!(!json.contains(&config.base.to_string_lossy().to_string()));
    assert!(
        !bytes
            .windows(b"shared-base-must-not-be-exported".len())
            .any(|window| window == b"shared-base-must-not-be-exported")
    );
    assert!(
        !bytes
            .windows(b"bob-private".len())
            .any(|window| window == b"bob-private")
    );
    let mut repeat = vec![];
    assert_eq!(
        alice
            .export_archive(state.revision, &mut repeat)
            .unwrap()
            .sha256,
        summary.sha256
    );
    assert_eq!(bytes, repeat);
    assert_eq!(before, tree(temp.path()));
}

#[test]
fn active_handles_stale_revisions_quota_and_corruption_fail_before_writing_archive() {
    let (_temp, config) = lab();
    let store = Store::open(config.clone()).unwrap();
    store
        .write_file("SAVE.DAT", b"private-save", "alice")
        .unwrap();
    let revision = store.inspect().unwrap().revision;
    let mut bytes = vec![];
    let lease = store.lease().unwrap();
    assert!(matches!(
        store.export_archive(revision, &mut bytes),
        Err(Error::Busy)
    ));
    drop(lease);
    assert!(matches!(
        store.export_archive(revision + 1, &mut bytes),
        Err(Error::Revision)
    ));
    let mut limited = config.clone();
    limited.policy.temporary_bytes = 1024;
    assert!(matches!(
        Store::open(limited)
            .unwrap()
            .export_archive(revision, &mut bytes),
        Err(Error::Quota)
    ));
    let blob = tree(&config.root)
        .keys()
        .find(|path| {
            path.parent()
                .is_some_and(|parent| parent.ends_with("blobs"))
        })
        .unwrap()
        .clone();
    fs::write(blob, b"tampered").unwrap();
    assert!(matches!(
        store.export_archive(revision, &mut bytes),
        Err(Error::Corrupt)
    ));
    assert!(bytes.is_empty());
}

#[test]
fn staging_writer_failure_never_publishes_a_job_snapshot_or_storage_change() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture staging failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (temp, config) = lab();
    let store = Store::open(config).unwrap();
    store
        .write_file("SAVE.DAT", b"private-save", "alice")
        .unwrap();
    let before = tree(temp.path());
    assert!(
        store
            .export_archive(store.inspect().unwrap().revision, Broken)
            .is_err()
    );
    assert_eq!(tree(temp.path()), before);
}

#[test]
fn corrupt_logical_metadata_is_rejected_before_it_can_enter_an_archive() {
    let (_temp, config) = lab();
    let store = Store::open(config.clone()).unwrap();
    store
        .write_file("SAVE.DAT", b"private-save", "alice")
        .unwrap();
    let revision = store.inspect().unwrap().revision;
    let state_path = tree(&config.root)
        .keys()
        .find(|path| path.ends_with("state.json"))
        .unwrap()
        .clone();
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    state["view"]["upper"]["save.dat"]["name"] = serde_json::json!("../../private/key");
    fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let mut bytes = vec![];
    assert!(matches!(
        store.export_archive(revision, &mut bytes),
        Err(Error::Corrupt)
    ));
    assert!(bytes.is_empty());
}

#[test]
fn partial_successful_writes_produce_the_complete_verified_tar_stream() {
    struct Partial(Vec<u8>);
    impl Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = bytes.len().min(3);
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_temp, config) = lab();
    let store = Store::open(config).unwrap();
    store
        .write_file("SAVE.DAT", b"private-save", "alice")
        .unwrap();
    let mut writer = Partial(vec![]);
    let result = store
        .export_archive(store.inspect().unwrap().revision, &mut writer)
        .unwrap();
    assert_eq!(result.bytes, writer.0.len() as u64);
    assert_eq!(result.sha256, format!("{:x}", Sha256::digest(&writer.0)));
    assert_eq!(
        tar::Archive::new(writer.0.as_slice())
            .entries()
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn pure_preflight_matches_archive_size_and_revalidates_stale_or_corrupt_content() {
    let (temp, config) = lab();
    let store = Store::open(config.clone()).unwrap();
    store.write_file("SAVE.DAT", b"save-data", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let before = tree(temp.path());
    let preflight = store.export_preflight(revision).unwrap();
    assert_eq!(before, tree(temp.path()));
    let mut bytes = vec![];
    let summary = store.export_archive(revision, &mut bytes).unwrap();
    assert_eq!(preflight.bytes, summary.bytes);
    assert_eq!(preflight.generation, summary.generation);
    assert_eq!(preflight.revision, summary.revision);
    assert_eq!(before, tree(temp.path()));
    assert!(matches!(
        store.export_preflight(revision + 1),
        Err(Error::Revision)
    ));
    let lease = store.lease().unwrap();
    assert!(matches!(store.export_preflight(revision), Err(Error::Busy)));
    drop(lease);
    let mut limited = config;
    limited.policy.temporary_bytes = 1024;
    assert!(matches!(
        Store::open(limited).unwrap().export_preflight(revision),
        Err(Error::Quota)
    ));
    let blob = before
        .keys()
        .find(|path| {
            path.parent()
                .is_some_and(|parent| parent.ends_with("blobs"))
        })
        .unwrap();
    fs::write(blob, b"tampered").unwrap();
    assert!(matches!(
        store.export_preflight(revision),
        Err(Error::Corrupt)
    ));
}

fn artifact_lab() -> (tempfile::TempDir, Config) {
    let (temp, mut config) = lab();
    config.policy.artifacts = Some(ArtifactPolicy {
        ttl_seconds: 3600,
        count_limit: 4,
        byte_limit: 8192,
    });
    (temp, config)
}

#[test]
fn export_accepts_smb_copy_up_identity_after_rename_and_reopen() {
    let (_temp, config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    let handle = store.open_handle("MASTER.DAT", true).unwrap();
    let base_id = handle.object_id.clone();
    assert!(uuid::Uuid::parse_str(&base_id).is_err());
    store.write_handle(&handle, 0, b"private", "alice").unwrap();
    store
        .rename("MASTER.DAT", "RENAMED.DAT", false, "alice")
        .unwrap();
    drop(handle);
    drop(store);
    let store = Store::open(config.clone()).unwrap();
    let state = store.inspect().unwrap();
    assert_eq!(state.view.upper["renamed.dat"].object_id, base_id);
    let private_bytes = store.read("RENAMED.DAT").unwrap();
    let preflight = store.export_preflight(state.revision).unwrap();
    let mut raw = vec![];
    store.export_archive(state.revision, &mut raw).unwrap();
    assert_eq!(preflight.bytes, raw.len() as u64);
    let preview = store
        .preview_action(state.revision, "alice", Action::Export)
        .unwrap();
    let job = store
        .submit_planned_job(
            state.revision,
            "alice",
            "copy-up-export",
            Action::Export,
            RequestBinding {
                plan_id: uuid::Uuid::new_v4().to_string(),
                source_fingerprint: preview.fingerprint,
            },
        )
        .unwrap()
        .job;
    assert_eq!(
        store
            .execute_job(&job.id, "alice", |_| Ok(()))
            .unwrap()
            .status,
        JobStatus::Succeeded
    );
    let (_, mut file) = store.open_artifact(&job.id, "alice", |_| Ok(())).unwrap();
    let mut published = vec![];
    file.read_to_end(&mut published).unwrap();
    assert_eq!(published, raw);
    assert_eq!(store.inspect().unwrap().view, state.view);
    assert_eq!(store.read("RENAMED.DAT").unwrap(), private_bytes);
    assert_eq!(
        fs::read(config.base.join("MASTER.DAT")).unwrap(),
        b"shared-base-must-not-be-exported"
    );
}

#[test]
fn durable_export_job_and_verified_download_survive_reopen_without_changing_view() {
    let (temp, config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    store.write_file("SAVE.DAT", b"save-data", "alice").unwrap();
    store.delete("HIDDEN.DAT", "alice").unwrap();
    let state = store.inspect().unwrap();
    let before = tree(temp.path());
    let preview = store
        .preview_action(state.revision, "alice", Action::Export)
        .unwrap();
    assert_eq!(before, tree(temp.path()));
    assert_eq!(preview.affected_entries, 0);
    assert_eq!(preview.active_bytes_after, 9);
    assert_eq!(
        preview.retained_bytes_after,
        store.export_preflight(state.revision).unwrap().bytes
    );
    let job = store
        .submit_planned_job(
            state.revision,
            "alice",
            "export",
            Action::Export,
            RequestBinding {
                plan_id: uuid::Uuid::new_v4().to_string(),
                source_fingerprint: preview.fingerprint,
            },
        )
        .unwrap()
        .job;
    let completed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    assert_eq!(
        completed.result.as_ref().unwrap().artifact_id.as_ref(),
        Some(&job.id)
    );
    let artifact = store.artifact(&job.id, "alice").unwrap();
    assert_eq!(artifact.revision, state.revision);
    assert_eq!(artifact.generation, state.generation);
    assert_eq!(store.inspect().unwrap().view, state.view);
    assert_eq!(store.inspect().unwrap().revision, state.revision + 1);
    let archived = tree(&store.namespace().join("artifacts"));
    assert_eq!(archived.len(), 1);
    let mut checks = 0;
    let (record, mut file) = store
        .open_artifact(&job.id, "alice", |_| {
            checks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(checks, 2);
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(record, artifact);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), artifact.sha256);
    assert_eq!(bytes.len() as u64, artifact.bytes);
    drop(store);
    let reopened = Store::open(config.clone()).unwrap();
    assert_eq!(
        reopened.execute_job(&job.id, "alice", |_| Ok(())).unwrap(),
        completed
    );
    assert!(
        reopened
            .submit_planned_job(
                state.revision,
                "alice",
                "export",
                Action::Export,
                job.request_binding.clone().unwrap()
            )
            .unwrap()
            .replayed
    );
    assert_eq!(archived, tree(&reopened.namespace().join("artifacts")));
    assert!(matches!(
        reopened.execute_job(&job.id, "alice", |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    let mut bob_config = config;
    bob_config.identity.principal = "bob".into();
    assert!(matches!(
        Store::open(bob_config).unwrap().artifact(&job.id, "alice"),
        Err(Error::NotFound)
    ));
    assert_eq!(
        reopened
            .inspect()
            .unwrap()
            .history
            .iter()
            .filter(|e| e.job_id.as_ref() == Some(&job.id))
            .count(),
        1
    );
    assert!(matches!(
        reopened.artifact(&job.id, "bob"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        reopened.open_artifact(&job.id, "bob", |_| panic!(
            "foreign actor must not reach authorization"
        )),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        reopened.open_artifact("../state.json", "alice", |_| Ok(())),
        Err(Error::Path)
    ));
    assert!(matches!(
        reopened.open_artifact(&job.id, "alice", |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    let mut checks = 0;
    assert!(matches!(
        reopened.open_artifact(&job.id, "alice", |_| {
            checks += 1;
            if checks == 2 {
                Err(Error::Denied)
            } else {
                Ok(())
            }
        }),
        Err(Error::Denied)
    ));
}

#[test]
fn export_denial_and_disabled_or_exhausted_policy_never_publish() {
    let (temp, mut config) = artifact_lab();
    config.policy.artifacts.as_mut().unwrap().count_limit = 1;
    let store = Store::open(config.clone()).unwrap();
    let revision = store.inspect().unwrap().revision;
    let job = store
        .submit_job(revision, "alice", "denied", Action::Export)
        .unwrap()
        .job;
    let mut checks = 0;
    let failed = store
        .execute_job(&job.id, "alice", |_| {
            checks += 1;
            if checks == 2 {
                Err(Error::Denied)
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("denied"));
    assert!(!store.namespace().join("artifacts").exists());
    assert!(store.inspect().unwrap().artifacts.is_empty());
    let job = store
        .submit_job(revision, "alice", "ok", Action::Export)
        .unwrap()
        .job;
    assert_eq!(
        store
            .execute_job(&job.id, "alice", |_| Ok(()))
            .unwrap()
            .status,
        JobStatus::Succeeded
    );
    let before = tree(temp.path());
    let revision = store.inspect().unwrap().revision;
    assert!(matches!(
        store.preview_action(revision, "alice", Action::Export),
        Err(Error::Quota)
    ));
    assert_eq!(before, tree(temp.path()));
    let mut disabled = config.clone();
    disabled.policy.artifacts = None;
    assert!(matches!(
        Store::open(disabled)
            .unwrap()
            .preview_action(revision, "alice", Action::Export),
        Err(Error::Unsupported)
    ));
    config.policy.artifacts.as_mut().unwrap().ttl_seconds = 0;
    assert!(matches!(Store::open(config), Err(Error::Quota)));
}

#[test]
fn archive_expiry_corruption_and_schema_smuggling_fail_closed() {
    let (_temp, config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    let job = store
        .submit_job(0, "alice", "capture", Action::Export)
        .unwrap()
        .job;
    store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    let path = store.namespace().join("state.json");
    let original = fs::read(&path).unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&original).unwrap();
    state["schema"] = 4.into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(Store::open(config.clone()), Err(Error::Corrupt)));
    state["schema"] = 5.into();
    state["artifacts"][&job.id]["createdAt"] = 0.into();
    state["jobs"][&job.id]["created_at"] = 0.into();
    state["artifacts"][&job.id]["expiresAt"] = 1.into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        store.open_artifact(&job.id, "alice", |_| panic!(
            "expired archive must not reach authorization"
        )),
        Err(Error::Retention)
    ));
    // Expiry does not free count or retained capacity.
    let mut limited = config.clone();
    limited.policy.artifacts.as_mut().unwrap().count_limit = 1;
    assert!(matches!(
        Store::open(limited)
            .unwrap()
            .preview_action(1, "alice", Action::Export),
        Err(Error::Quota)
    ));
    fs::write(&path, &original).unwrap();
    let archive = store
        .namespace()
        .join("artifacts")
        .join(format!("{}.tar", job.id));
    let mut bytes = fs::read(&archive).unwrap();
    bytes[513] ^= 1;
    fs::write(&archive, bytes).unwrap();
    assert!(matches!(
        store.open_artifact(&job.id, "alice", |_| Ok(())),
        Err(Error::Corrupt)
    ));
    state = serde_json::from_slice(&original).unwrap();
    state["jobs"][&job.id]["status"] = "running".into();
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(Store::open(config), Err(Error::Corrupt)));
}

#[test]
fn private_publication_without_receipt_resumes_once_after_reopen() {
    let (_temp, config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    store.write_file("SAVE.DAT", b"save-data", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let preview = store
        .preview_action(revision, "alice", Action::Export)
        .unwrap();
    let job = store
        .submit_planned_job(
            revision,
            "alice",
            "interrupted",
            Action::Export,
            RequestBinding {
                plan_id: uuid::Uuid::new_v4().to_string(),
                source_fingerprint: preview.fingerprint,
            },
        )
        .unwrap()
        .job;
    let state = store.namespace().join("state.json");
    let retained = store.namespace().join("interrupted-state.json");
    let mut checks = 0;
    assert!(
        store
            .execute_job(&job.id, "alice", |_| {
                checks += 1;
                if checks == 2 {
                    fs::rename(&state, &retained).unwrap();
                    fs::create_dir(&state).unwrap();
                }
                Ok(())
            })
            .is_err()
    );
    fs::remove_dir(&state).unwrap();
    fs::rename(&retained, &state).unwrap();
    let archives = tree(&store.namespace().join("artifacts"));
    assert_eq!(archives.len(), 1);
    assert!(store.inspect().unwrap().artifacts.is_empty());
    assert!(matches!(
        store.artifact(&job.id, "alice"),
        Err(Error::NotFound)
    ));
    drop(store);
    let reopened = Store::open(config.clone()).unwrap();
    assert!(matches!(
        reopened.execute_job(&job.id, "alice", |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    assert_eq!(
        reopened.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
    let mut changed = config;
    changed.policy.artifacts.as_mut().unwrap().ttl_seconds += 1;
    let changed_store = Store::open(changed).unwrap();
    assert!(matches!(
        changed_store.execute_job(&job.id, "alice", |_| Ok(())),
        Err(Error::Revision)
    ));
    assert_eq!(
        changed_store.inspect().unwrap().jobs[&job.id].status,
        JobStatus::Running
    );
    drop(changed_store);
    let completed = reopened.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    assert_eq!(completed.status, JobStatus::Succeeded);
    assert_eq!(archives, tree(&reopened.namespace().join("artifacts")));
    assert_eq!(
        reopened
            .inspect()
            .unwrap()
            .history
            .iter()
            .filter(|e| e.job_id.as_ref() == Some(&job.id))
            .count(),
        1
    );
}

#[test]
fn unpublished_archives_and_completed_tar_bytes_remain_charged_to_retained_budget() {
    let (_temp, mut config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    let orphan_dir = store.namespace().join("artifacts");
    fs::create_dir(&orphan_dir).unwrap();
    let orphan = uuid::Uuid::new_v4().to_string();
    fs::write(orphan_dir.join(format!("{orphan}.tar")), vec![0; 8192]).unwrap();
    assert!(matches!(
        store.preview_action(0, "alice", Action::Export),
        Err(Error::Quota)
    ));
    // Even without export enabled, a retained snapshot cannot hide orphan bytes.
    config.policy.artifacts = None;
    let reopened = Store::open(config).unwrap();
    reopened
        .write_file("SAVE.DAT", b"save-data", "alice")
        .unwrap();
    assert!(matches!(reopened.snapshot(1, "alice"), Err(Error::Quota)));
    assert!(reopened.inspect().unwrap().snapshots.is_empty());
    assert!(matches!(
        reopened.artifact(&orphan, "alice"),
        Err(Error::NotFound)
    ));
}

#[test]
fn completed_tar_charges_retained_capacity_without_mutating_saved_data() {
    let (_temp, mut config) = artifact_lab();
    let store = Store::open(config.clone()).unwrap();
    store.write_file("SAVE.DAT", b"save-data", "alice").unwrap();
    let revision = store.inspect().unwrap().revision;
    let bytes = store.export_preflight(revision).unwrap().bytes;
    drop(store);
    config.policy.retained_bytes = bytes;
    config.policy.artifacts.as_mut().unwrap().byte_limit = bytes;
    let store = Store::open(config).unwrap();
    let job = store
        .submit_job(revision, "alice", "capture", Action::Export)
        .unwrap()
        .job;
    assert_eq!(
        store
            .execute_job(&job.id, "alice", |_| Ok(()))
            .unwrap()
            .status,
        JobStatus::Succeeded
    );
    assert!(matches!(
        store.snapshot(revision + 1, "alice"),
        Err(Error::Quota)
    ));
    assert!(store.inspect().unwrap().snapshots.is_empty());
    assert_eq!(store.read("SAVE.DAT").unwrap(), b"save-data");
}

#[test]
fn schema_four_receipts_migrate_only_when_quiescent_and_old_policy_disables_exports() {
    let (_temp, config) = lab();
    let store = Store::open(config.clone()).unwrap();
    let job = store
        .submit_job(0, "alice", "old-snapshot", Action::Snapshot)
        .unwrap()
        .job;
    let completed = store.execute_job(&job.id, "alice", |_| Ok(())).unwrap();
    let before = store.inspect().unwrap();
    let path = store.namespace().join("state.json");
    let mut persisted = serde_json::to_value(&before).unwrap();
    persisted["schema"] = 4.into();
    fs::write(path, serde_json::to_vec(&persisted).unwrap()).unwrap();
    let lease = store.lease().unwrap();
    assert!(matches!(Store::open(config.clone()), Err(Error::Busy)));
    drop(lease);
    let migrated = Store::open(config.clone()).unwrap();
    let after = migrated.inspect().unwrap();
    assert_eq!(after.schema, 5);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.view, before.view);
    assert_eq!(migrated.job(&job.id, "alice").unwrap(), completed);
    let mut old_policy = serde_json::to_value(&config.policy).unwrap();
    old_policy.as_object_mut().unwrap().remove("artifacts");
    let policy: Policy = serde_json::from_value(old_policy).unwrap();
    assert!(policy.artifacts.is_none());
    assert!(matches!(
        migrated.preview_action(after.revision, "alice", Action::Export),
        Err(Error::Unsupported)
    ));
}
