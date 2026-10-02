use sambafied_shadow::{Config, Error, ExportManifest, Identity, Policy, Store};
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
