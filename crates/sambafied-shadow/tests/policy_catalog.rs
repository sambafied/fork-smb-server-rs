use sambafied_shadow::{Error, Policy, SharePolicyCatalog};
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
