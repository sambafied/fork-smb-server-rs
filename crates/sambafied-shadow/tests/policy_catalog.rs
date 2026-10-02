use sambafied_shadow::{
    Action, Config, Error, Identity, Policy, RequestBinding, SharePolicyCatalog, Store,
};
use std::fs;

fn policy() -> Policy {
    Policy {
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
    }
}

#[test]
fn durable_replace_preserves_scope_and_ignores_startup_defaults_after_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let first = catalog.read().unwrap();
    assert_eq!(first.document().revision, 0);
    let fingerprint = first.fingerprint().unwrap();
    drop(first);
    let mut changed = policy();
    changed.active_bytes = 2048;
    let committed = catalog.replace(0, "issuer-subject-hash", changed).unwrap();
    assert_eq!(committed.revision, 1);
    assert_eq!(committed.changes.len(), 1);
    assert_eq!(committed.changes[0].actor, "issuer-subject-hash");
    let reopened = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let effective = reopened.read().unwrap();
    assert_eq!(effective.document().policy.active_bytes, 2048);
    assert_ne!(effective.fingerprint().unwrap(), fingerprint);
    drop(effective);
    catalog.replace(1, "issuer-subject-hash", policy()).unwrap();
    assert_ne!(catalog.read().unwrap().fingerprint().unwrap(), fingerprint);
    let other = SharePolicyCatalog::open(temp.path(), "other-org", "games", policy()).unwrap();
    assert_eq!(other.read().unwrap().document().revision, 0);
}

#[test]
fn independent_read_lease_and_stale_revision_never_publish_a_change() {
    let temp = tempfile::tempdir().unwrap();
    let writer = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let reader = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let lease = reader.read().unwrap();
    assert!(matches!(
        writer.replace(0, "actor", policy()),
        Err(Error::Busy)
    ));
    assert_eq!(lease.document().revision, 0);
    drop(lease);
    writer.replace(0, "actor", policy()).unwrap();
    let before = tree(temp.path());
    assert!(matches!(
        writer.replace(0, "actor", policy()),
        Err(Error::Revision)
    ));
    assert_eq!(tree(temp.path()), before);
    let mut invalid = policy();
    invalid.recovery_protection_seconds = 0;
    assert!(matches!(
        writer.replace(1, "actor", invalid),
        Err(Error::Quota)
    ));
    assert_eq!(tree(temp.path()), before);
    assert!(matches!(
        writer.replace(1, "actor\nforged", policy()),
        Err(Error::Path)
    ));
    assert_eq!(tree(temp.path()), before);
}

#[cfg(windows)]
#[test]
fn failed_atomic_publication_preserves_prior_policy_and_audit() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let document = fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let initial = fs::read(&document).unwrap();
    // Windows rejects replacement of a read-only destination. This test does
    // not claim Unix fault coverage: Unix rename permits a read-only inode.
    {
        let original_permissions = fs::metadata(&document).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&document, permissions).unwrap();
        assert!(catalog.replace(0, "actor", policy()).is_err());
        assert_eq!(fs::read(&document).unwrap(), initial);
        fs::set_permissions(&document, original_permissions).unwrap();
        assert_eq!(catalog.read().unwrap().document().revision, 0);
    }
}

#[test]
fn unknown_format_scope_or_broken_audit_chain_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    catalog.replace(0, "actor", policy()).unwrap();
    let document = fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let initial = fs::read(&document).unwrap();
    for field in ["schema", "organization", "revision", "policy", "changes"] {
        let mut value: serde_json::Value = serde_json::from_slice(&initial).unwrap();
        match field {
            "schema" => value[field] = 2.into(),
            "organization" => value[field] = "wrong".into(),
            "revision" => value[field] = 0.into(),
            "policy" => value[field]["active_bytes"] = 1.into(),
            "changes" => value[field][0]["policy_digest"] = "f".repeat(64).into(),
            _ => unreachable!(),
        }
        fs::write(&document, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(catalog.read().is_err());
        assert!(SharePolicyCatalog::open(temp.path(), "org", "games", policy()).is_err());
    }
    fs::write(document, initial).unwrap();
    assert_eq!(catalog.read().unwrap().document().revision, 1);
}

fn tree(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut result: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    result.sort();
    result
}

#[test]
fn reader_process_death_releases_policy_gate_without_changing_revision() {
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "policy_reader_child", "--ignored", "--nocapture"])
            .env("SAMBAFIED_POLICY_TEST_ROOT", temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) if line == "POLICY_LEASE_READY" => {
                    let _ = ready_tx.send(());
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("reader did not acquire policy lease");
    assert!(matches!(
        catalog.replace(0, "actor", policy()),
        Err(Error::Busy)
    ));
    assert_eq!(catalog.read().unwrap().document().revision, 0);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(catalog.replace(0, "actor", policy()).unwrap().revision, 1);
}

#[test]
#[ignore = "subprocess fixture helper"]
fn policy_reader_child() {
    use std::io::{Read, Write};
    let root = std::env::var_os("SAMBAFIED_POLICY_TEST_ROOT").expect("parent fixture");
    let catalog =
        SharePolicyCatalog::open(std::path::Path::new(&root), "org", "games", policy()).unwrap();
    let _lease = catalog.read().unwrap();
    println!("POLICY_LEASE_READY");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
}

fn store_config(root: &std::path::Path, principal: &str) -> Config {
    let base = root.join("base");
    let upper = root.join(principal);
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&upper).unwrap();
    if !base.join("SAVE.DAT").exists() {
        fs::write(base.join("SAVE.DAT"), b"base-save").unwrap();
    }
    Config {
        root: upper,
        base,
        identity: Identity {
            organization: "org".into(),
            share: "games".into(),
            principal: principal.into(),
            base_version: "v1".into(),
        },
        policy: policy(),
    }
}

#[test]
fn already_open_store_and_handle_enforce_new_limits_without_hiding_old_data() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let config = store_config(temp.path(), "alice");
    let alice = Store::open_with_policy_catalog(config.clone(), catalog.clone()).unwrap();
    let bob =
        Store::open_with_policy_catalog(store_config(temp.path(), "bob"), catalog.clone()).unwrap();
    alice.write_file("SAVE.DAT", b"alice-old", "alice").unwrap();
    bob.write_file("SAVE.DAT", b"bob", "bob").unwrap();
    let initial = alice.inspect().unwrap();
    let snapshot_id = alice.snapshot(initial.revision, "alice").unwrap();
    let alice_before = serde_json::to_vec(&alice.inspect().unwrap()).unwrap();
    let bob_before = serde_json::to_vec(&bob.inspect().unwrap()).unwrap();
    let handle = alice.open_handle("SAVE.DAT", true).unwrap();
    let mut lower = policy();
    lower.max_file_bytes = 4;
    lower.active_bytes = 4;
    lower.snapshot_ttl_seconds = 600;
    catalog.replace(0, "operator", lower).unwrap();
    let (state, effective, revision) = alice.inspect_with_policy().unwrap();
    assert_eq!(effective.max_file_bytes, 4);
    assert_eq!(revision, Some(1));
    assert_eq!(serde_json::to_vec(&state).unwrap(), alice_before);
    assert!(state.snapshots.contains_key(&snapshot_id));
    assert_eq!(alice.read("SAVE.DAT").unwrap(), b"alice-old");
    assert_eq!(alice.read_handle(&handle, 0, 100).unwrap(), b"alice-old");
    assert!(matches!(
        alice.write_handle(&handle, 0, b"denied", "alice"),
        Err(Error::Quota)
    ));
    assert!(matches!(
        alice.resize_handle(&handle, 5, "alice"),
        Err(Error::Quota)
    ));
    assert_eq!(
        serde_json::to_vec(&alice.inspect().unwrap()).unwrap(),
        alice_before
    );
    assert_eq!(
        serde_json::to_vec(&bob.inspect().unwrap()).unwrap(),
        bob_before
    );
    assert_eq!(
        fs::read(config.base.join("SAVE.DAT")).unwrap(),
        b"base-save"
    );
    drop(handle);
    let reopened = Store::open_with_policy_catalog(config, catalog).unwrap();
    assert_eq!(reopened.inspect_with_policy().unwrap().1.max_file_bytes, 4);
    assert_eq!(reopened.read("SAVE.DAT").unwrap(), b"alice-old");
}

#[test]
fn policy_aba_invalidates_preview_and_queued_action_without_generation_change() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", policy()).unwrap();
    let store =
        Store::open_with_policy_catalog(store_config(temp.path(), "alice"), catalog.clone())
            .unwrap();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let state = store.inspect().unwrap();
    let impact = store
        .preview_planned_action(state.revision, "alice", Action::Snapshot)
        .unwrap();
    let binding = RequestBinding {
        plan_id: uuid::Uuid::new_v4().to_string(),
        source_fingerprint: impact.fingerprint,
    };
    let queued = store
        .submit_planned_job(
            state.revision,
            "alice",
            "queued-before-policy",
            Action::Snapshot,
            binding.clone(),
        )
        .unwrap();
    let mut changed = policy();
    changed.active_bytes = 2048;
    catalog.replace(0, "operator", changed).unwrap();
    catalog.replace(1, "operator", policy()).unwrap();
    assert!(matches!(
        store.submit_planned_job(
            state.revision,
            "alice",
            "stale-plan",
            Action::Snapshot,
            binding
        ),
        Err(Error::Revision)
    ));
    let completed = store
        .execute_job(&queued.job.id, "alice", |_| Ok(()))
        .unwrap();
    assert_eq!(completed.status, sambafied_shadow::JobStatus::Failed);
    let after = store.inspect().unwrap();
    assert_eq!(after.generation, state.generation);
    assert_eq!(after.revision, state.revision);
    assert!(after.snapshots.is_empty());
    assert_eq!(store.read("SAVE.DAT").unwrap(), b"private");
}

#[test]
fn mismatched_policy_authority_is_rejected_before_upper_namespace_creation() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SharePolicyCatalog::open(temp.path(), "other-org", "games", policy()).unwrap();
    let config = store_config(temp.path(), "alice");
    assert!(matches!(
        Store::open_with_policy_catalog(config.clone(), catalog),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read_dir(config.root).unwrap().count(), 0);
}

#[test]
fn export_holds_one_policy_until_the_last_archive_write() {
    use std::io::Write;
    struct Probe {
        catalog: SharePolicyCatalog,
        attempts: usize,
        bytes: Vec<u8>,
    }
    impl Write for Probe {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(matches!(
                self.catalog.replace(0, "operator", policy()),
                Err(Error::Busy)
            ));
            self.attempts += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let mut initial = policy();
    initial.temporary_bytes = 8192;
    let catalog = SharePolicyCatalog::open(temp.path(), "org", "games", initial).unwrap();
    let store =
        Store::open_with_policy_catalog(store_config(temp.path(), "alice"), catalog.clone())
            .unwrap();
    store.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let state = store.inspect().unwrap();
    let mut probe = Probe {
        catalog: catalog.clone(),
        attempts: 0,
        bytes: Vec::new(),
    };
    let summary = store.export_archive(state.revision, &mut probe).unwrap();
    assert!(probe.attempts > 1);
    assert_eq!(probe.bytes.len() as u64, summary.bytes);
    assert_eq!(catalog.read().unwrap().document().revision, 0);
    catalog.replace(0, "operator", policy()).unwrap();
    assert_eq!(store.inspect().unwrap().revision, state.revision);
}
