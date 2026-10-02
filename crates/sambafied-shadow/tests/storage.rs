use sambafied_shadow::{BackupDestination, Config, Error, Identity, Policy, Store};
use sambafied_shadow::{OpenAction, OpenDisposition};
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
        fs::write(base.join("SAVE.DAT"), b"base-save").unwrap();
        fs::create_dir(base.join("LEVELS")).unwrap();
        fs::write(base.join("LEVELS/ONE.DAT"), b"level-one").unwrap();
        let config = Config {
            root,
            base,
            identity: Identity {
                organization: "org".into(),
                share: "games".into(),
                principal: "alice-stable-id".into(),
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
        };
        Self {
            _temp: temp,
            config,
        }
    }
    fn alice(&self) -> Arc<Store> {
        Store::open(self.config.clone()).unwrap()
    }
    fn bob(&self) -> Arc<Store> {
        let mut config = self.config.clone();
        config.identity.principal = "bob-stable-id".into();
        Store::open(config).unwrap()
    }
    fn backup_destination(&self) -> BackupDestination {
        let root = self._temp.path().join("backups");
        fs::create_dir_all(&root).unwrap();
        BackupDestination {
            id: "lab-disk".into(),
            root,
            byte_limit: 65536,
            count_limit: 10,
            ttl_seconds: 3600,
            failure_domain: "same-host-test-storage".into(),
        }
    }
}

#[test]
fn private_copy_up_reconnect_and_base_immutability() {
    let lab = Lab::new();
    let alice = lab.alice();
    let bob = lab.bob();
    alice
        .write_file("save.dat", b"alice-save", "alice")
        .unwrap();
    assert_eq!(alice.read("SAVE.DAT").unwrap(), b"alice-save");
    assert_eq!(bob.read("save.dat").unwrap(), b"base-save");
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"base-save"
    );
    assert_ne!(alice.namespace(), bob.namespace());
    drop(alice);
    assert_eq!(lab.alice().read("save.dat").unwrap(), b"alice-save");
}

#[test]
fn deletion_whiteout_trash_restore_and_purge_survive_restart() {
    let lab = Lab::new();
    let alice = lab.alice();
    let trash = alice.delete("SAVE.DAT", "alice").unwrap();
    assert!(matches!(alice.read("save.dat"), Err(Error::NotFound)));
    assert!(!alice.inspect().unwrap().trash[&trash].from_upper);
    drop(alice);
    let alice = lab.alice();
    assert!(
        alice
            .list("")
            .unwrap()
            .iter()
            .all(|e| e.name.to_lowercase() != "save.dat")
    );
    let revision = alice.inspect().unwrap().revision;
    alice.restore_trash(revision, &trash, "alice").unwrap();
    assert_eq!(alice.read("save.dat").unwrap(), b"base-save");
    let trash = alice.delete("save.dat", "alice").unwrap();
    alice
        .purge_trash(alice.inspect().unwrap().revision, &trash, "alice")
        .unwrap();
    assert!(matches!(lab.alice().read("save.dat"), Err(Error::NotFound)));
    assert_eq!(lab.bob().read("save.dat").unwrap(), b"base-save");
}

#[test]
fn deleted_recreated_directory_does_not_reveal_base_children() {
    let lab = Lab::new();
    let alice = lab.alice();
    let child_trash = alice.delete("levels/one.dat", "alice").unwrap();
    alice.delete("levels", "alice").unwrap();
    alice.mkdir("LEVELS", "alice").unwrap();
    assert!(alice.list("levels").unwrap().is_empty());
    alice
        .restore_trash(alice.inspect().unwrap().revision, &child_trash, "alice")
        .unwrap();
    assert_eq!(alice.read("levels/one.dat").unwrap(), b"level-one");
    assert_eq!(alice.list("levels").unwrap().len(), 1);
}

#[test]
fn recovery_retains_history_and_protects_old_generation() {
    let lab = Lab::new();
    let alice = lab.alice();
    alice
        .write_file("SAVE.DAT", b"first-save", "alice")
        .unwrap();
    let snapshot = alice
        .snapshot(alice.inspect().unwrap().revision, "alice")
        .unwrap();
    alice
        .write_file("SAVE.DAT", b"second-save", "alice")
        .unwrap();
    let old = alice.inspect().unwrap();
    let recovery = alice.reset(old.revision, "alice").unwrap();
    let reset = alice.inspect().unwrap();
    assert_ne!(old.generation, reset.generation);
    assert_eq!(alice.read("save.dat").unwrap(), b"base-save");
    assert_eq!(lab.bob().read("save.dat").unwrap(), b"base-save");
    assert!(matches!(
        alice.delete_snapshot(reset.revision, &recovery, "alice"),
        Err(Error::Retention)
    ));
    alice.rollback(reset.revision, &snapshot, "alice").unwrap();
    assert_eq!(alice.read("save.dat").unwrap(), b"first-save");
    assert!(alice.inspect().unwrap().history.len() > old.history.len());
    assert!(alice.inspect().unwrap().snapshots.contains_key(&snapshot));
}

#[test]
fn cross_instance_maintenance_gate_prevents_reset_while_handles_are_open() {
    let lab = Lab::new();
    let first = lab.alice();
    let second = lab.alice();
    let handle = first.open_handle("SAVE.DAT", false).unwrap();
    assert!(matches!(second.reset(0, "alice"), Err(Error::Busy)));
    let alice = first.clone();
    let writer = alice.open_handle("save.dat", true).unwrap();
    first.write_handle(&writer, 0, b"new", "alice").unwrap();
    assert_eq!(first.read_handle(&handle, 0, 100).unwrap(), b"newe-save");
    drop(writer);
    drop(handle);
    second
        .reset(second.inspect().unwrap().revision, "alice")
        .unwrap();
}

#[test]
fn stale_revision_budget_and_corruption_do_not_activate_changes() {
    let lab = Lab::new();
    let alice = lab.alice();
    alice.write_file("SAVE.DAT", b"private", "alice").unwrap();
    let before = alice.inspect().unwrap();
    assert!(matches!(alice.reset(0, "alice"), Err(Error::Revision)));
    assert!(matches!(
        alice.write_file("save.dat", &vec![0; 2049], "alice"),
        Err(Error::Quota)
    ));
    assert_eq!(alice.inspect().unwrap().revision, before.revision);
    assert_eq!(alice.read("save.dat").unwrap(), b"private");
    let snapshot = alice.snapshot(before.revision, "alice").unwrap();
    let state = alice.inspect().unwrap();
    let hash = state.view.upper["save.dat"].digest.as_ref().unwrap();
    fs::write(alice.namespace().join("blobs").join(hash), b"corrupt").unwrap();
    assert!(matches!(
        alice.rollback(state.revision, &snapshot, "alice"),
        Err(Error::Corrupt)
    ));
    assert_eq!(alice.inspect().unwrap().generation, state.generation);
}

#[test]
fn paths_and_pinned_base_changes_are_rejected() {
    let lab = Lab::new();
    let alice = lab.alice();
    for path in [
        "../SAVE.DAT",
        "/SAVE.DAT",
        "a/../../b",
        "C:\\SAVE.DAT",
        "save.dat:stream",
        "con",
        "save.dat.",
    ] {
        assert!(matches!(alice.read(path), Err(Error::Path)), "{path}");
    }
    fs::write(lab.config.base.join("SAVE.DAT"), b"base-changed").unwrap();
    assert!(matches!(alice.read("save.dat"), Err(Error::Corrupt)));
    assert!(matches!(
        Store::open(lab.config.clone()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn file_rename_is_private_and_directory_rename_is_explicitly_unsupported() {
    let lab = Lab::new();
    let alice = lab.alice();
    alice
        .rename("SAVE.DAT", "renamed.dat", false, "alice")
        .unwrap();
    assert!(matches!(alice.read("save.dat"), Err(Error::NotFound)));
    assert_eq!(alice.read("renamed.dat").unwrap(), b"base-save");
    assert_eq!(lab.bob().read("save.dat").unwrap(), b"base-save");
    assert!(matches!(
        alice.rename("levels", "other", false, "alice"),
        Err(Error::Unsupported)
    ));
}

#[test]
fn verified_backup_restores_after_complete_upper_storage_loss() {
    let lab = Lab::new();
    let alice = lab.alice();
    let destination = lab.backup_destination();
    alice
        .write_file("SAVE.DAT", b"backup-save", "alice")
        .unwrap();
    alice.delete("levels/one.dat", "alice").unwrap();
    let backup = alice
        .backup(alice.inspect().unwrap().revision, &destination, "alice")
        .unwrap();
    let namespace = alice.namespace().to_path_buf();
    drop(alice);
    // This directory belongs solely to this tempfile fixture.
    assert!(namespace.starts_with(fs::canonicalize(lab._temp.path()).unwrap()));
    fs::remove_dir_all(&namespace).unwrap();
    let alice = lab.alice();
    assert_eq!(alice.read("save.dat").unwrap(), b"base-save");
    assert_eq!(alice.list_backups(&destination).unwrap().len(), 1);
    alice
        .restore_backup(0, &destination, &backup, "alice")
        .unwrap();
    assert_eq!(alice.read("save.dat").unwrap(), b"backup-save");
    assert!(matches!(alice.read("levels/one.dat"), Err(Error::NotFound)));
    assert_eq!(lab.bob().read("levels/one.dat").unwrap(), b"level-one");
    assert_eq!(
        alice.inspect().unwrap().history[0].operation,
        "restore-backup"
    );
}

#[test]
fn corrupt_backup_and_wrong_owner_fail_before_generation_switch() {
    let lab = Lab::new();
    let alice = lab.alice();
    let destination = lab.backup_destination();
    alice
        .write_file("SAVE.DAT", b"backup-save", "alice")
        .unwrap();
    let backup = alice
        .backup(alice.inspect().unwrap().revision, &destination, "alice")
        .unwrap();
    let state = alice.inspect().unwrap();
    let hash = state.view.upper["save.dat"].digest.as_ref().unwrap();
    let namespace = destination
        .root
        .join(alice.namespace().file_name().unwrap());
    fs::write(namespace.join(&backup).join("blobs").join(hash), b"corrupt").unwrap();
    assert!(matches!(
        alice.restore_backup(state.revision, &destination, &backup, "alice"),
        Err(Error::Corrupt)
    ));
    assert_eq!(alice.inspect().unwrap().generation, state.generation);
    // Inject a foreign manifest in Bob's namespace; identity remains checked.
    let bob = lab.bob();
    let bob_ns = destination
        .root
        .join(bob.namespace().file_name().unwrap())
        .join(&backup);
    fs::create_dir_all(&bob_ns).unwrap();
    fs::copy(
        namespace.join(&backup).join("manifest.json"),
        bob_ns.join("manifest.json"),
    )
    .unwrap();
    assert!(matches!(
        bob.restore_backup(0, &destination, &backup, "bob"),
        Err(Error::Corrupt)
    ));
}

#[test]
fn handle_identity_survives_copy_up_and_rename_without_cross_user_access() {
    let lab = Lab::new();
    let alice = lab.alice();
    let bob = lab.bob();
    let reader = alice.open_handle("SAVE.DAT", false).unwrap();
    alice.write_file("save.dat", b"new-save", "alice").unwrap();
    alice
        .rename("save.dat", "renamed.dat", false, "alice")
        .unwrap();
    assert_eq!(alice.read_handle(&reader, 0, 100).unwrap(), b"new-save");
    assert!(matches!(
        bob.read_handle(&reader, 0, 100),
        Err(Error::Corrupt)
    ));
}

#[test]
fn reclaim_only_unreferenced_blobs_and_preserve_snapshot_content() {
    let lab = Lab::new();
    let alice = lab.alice();
    alice
        .write_file("save.dat", b"first-save", "alice")
        .unwrap();
    let snapshot = alice
        .snapshot(alice.inspect().unwrap().revision, "alice")
        .unwrap();
    alice
        .write_file("save.dat", b"second-save", "alice")
        .unwrap();
    alice
        .write_file("save.dat", b"third-save", "alice")
        .unwrap();
    assert_eq!(
        fs::read_dir(alice.namespace().join("blobs"))
            .unwrap()
            .count(),
        2
    );
    alice
        .rollback(alice.inspect().unwrap().revision, &snapshot, "alice")
        .unwrap();
    assert_eq!(alice.read("save.dat").unwrap(), b"first-save");
}

#[test]
fn rename_does_not_need_twice_the_active_file_budget() {
    let mut lab = Lab::new();
    lab.config.policy.active_files = 1;
    let alice = lab.alice();
    alice.write_file("save.dat", b"private", "alice").unwrap();
    alice.rename("save.dat", "new.dat", false, "alice").unwrap();
    assert_eq!(alice.read("new.dat").unwrap(), b"private");
}

#[test]
fn atomic_open_dispositions_preserve_private_handle_identity() {
    let lab = Lab::new();
    let alice = lab.alice();
    let reader = alice.open_handle("save.dat", false).unwrap();
    let revision = alice.inspect().unwrap().revision;
    let (_, _, action) = alice
        .create_handle("save.dat", false, false, OpenDisposition::OpenIf, "alice")
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert!(matches!(
        alice.create_handle("save.dat", false, true, OpenDisposition::Create, "alice"),
        Err(Error::Exists)
    ));
    assert!(matches!(
        alice.create_handle(
            "missing.dat",
            false,
            true,
            OpenDisposition::Overwrite,
            "alice"
        ),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        alice.create_handle(
            "save.dat",
            false,
            false,
            OpenDisposition::OverwriteIf,
            "alice"
        ),
        Err(Error::Unsupported)
    ));
    let (writer, entry, action) = alice
        .create_handle("save.dat", false, true, OpenDisposition::Overwrite, "alice")
        .unwrap();
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(entry.object_id, reader.object_id);
    assert!(alice.read_handle(&reader, 0, 64).unwrap().is_empty());
    alice.write_handle(&writer, 0, b"save", "alice").unwrap();
    alice.resize_handle(&writer, 8, "alice").unwrap();
    assert_eq!(alice.read_handle(&reader, 0, 64).unwrap(), b"save\0\0\0\0");
    alice
        .rename("save.dat", "renamed.dat", false, "alice")
        .unwrap();
    assert_eq!(alice.stat_handle(&writer).unwrap().name, "renamed.dat");
    alice.resize_handle(&writer, 2, "alice").unwrap();
    assert_eq!(alice.read("renamed.dat").unwrap(), b"sa");
    assert_eq!(lab.bob().read("save.dat").unwrap(), b"base-save");
    assert_eq!(
        fs::read(lab.config.base.join("SAVE.DAT")).unwrap(),
        b"base-save"
    );
    assert!(matches!(
        lab.bob().resize_handle(&writer, 0, "bob"),
        Err(Error::Corrupt)
    ));
}

#[test]
fn simultaneous_exclusive_creates_have_one_winner() {
    let lab = Lab::new();
    let alice = lab.alice();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let store = Store::open(lab.config.clone()).unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.create_handle("new.dat", false, true, OpenDisposition::Create, "alice")
            })
        })
        .collect();
    let mut winners = 0;
    for worker in workers {
        match worker.join().unwrap() {
            Ok((_, _, action)) => {
                assert_eq!(action, OpenAction::Created);
                winners += 1;
            }
            Err(Error::Exists) => {}
            other => panic!("unexpected create result: {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(alice.inspect().unwrap().history.len(), 1);
}

#[test]
fn directory_create_handles_gate_reset_and_budget() {
    let mut lab = Lab::new();
    lab.config.policy.active_files = 1;
    let alice = lab.alice();
    let (directory, entry, action) = alice
        .create_handle("private", true, true, OpenDisposition::Create, "alice")
        .unwrap();
    assert!(entry.directory);
    assert_eq!(action, OpenAction::Created);
    let revision = alice.inspect().unwrap().revision;
    assert!(matches!(alice.reset(revision, "alice"), Err(Error::Busy)));
    assert!(matches!(
        alice.create_handle("second", true, true, OpenDisposition::Create, "alice"),
        Err(Error::Quota)
    ));
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert!(matches!(alice.stat("second"), Err(Error::NotFound)));
    drop(directory);
    alice.reset(revision, "alice").unwrap();
}

#[test]
fn direct_file_writes_enforce_per_file_limit_before_publication() {
    let lab = Lab::new();
    let alice = lab.alice();
    let revision = alice.inspect().unwrap().revision;
    let oversized = vec![1; lab.config.policy.max_file_bytes as usize + 1];
    assert!(matches!(
        alice.write_file("save.dat", &oversized, "alice"),
        Err(Error::Quota)
    ));
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert_eq!(alice.read("save.dat").unwrap(), b"base-save");
    assert!(matches!(
        alice.write_file("oversized.dat", &oversized, "alice"),
        Err(Error::Quota)
    ));
    assert!(matches!(alice.stat("oversized.dat"), Err(Error::NotFound)));
    assert_eq!(
        fs::read_dir(alice.namespace().join("blobs"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn direct_directory_creation_enforces_namespace_entry_budget() {
    let mut lab = Lab::new();
    lab.config.policy.active_files = 1;
    let alice = lab.alice();
    alice.mkdir("first", "alice").unwrap();
    let revision = alice.inspect().unwrap().revision;
    assert!(matches!(alice.mkdir("second", "alice"), Err(Error::Quota)));
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert!(matches!(alice.stat("second"), Err(Error::NotFound)));
    assert!(alice.stat("first").unwrap().directory);
}

#[test]
fn handle_rename_and_delete_never_target_a_reused_path() {
    let lab = Lab::new();
    let alice = lab.alice();
    let handle = alice.open_handle("save.dat", false).unwrap();
    alice
        .rename_handle(&handle, "moved.dat", false, "alice")
        .unwrap();
    alice
        .write_file("save.dat", b"replacement", "alice")
        .unwrap();
    alice
        .rename_handle(&handle, "again.dat", false, "alice")
        .unwrap();
    assert_eq!(alice.read("save.dat").unwrap(), b"replacement");
    assert_eq!(alice.read_handle(&handle, 0, 64).unwrap(), b"base-save");
    alice.delete_handle(&handle, "alice").unwrap();
    alice
        .write_file("again.dat", b"new-object", "alice")
        .unwrap();
    assert!(matches!(
        alice.delete_handle(&handle, "alice"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        alice.rename_handle(&handle, "lost.dat", false, "alice"),
        Err(Error::NotFound)
    ));
    assert_eq!(alice.read("again.dat").unwrap(), b"new-object");
    assert!(matches!(
        lab.bob().delete_handle(&handle, "bob"),
        Err(Error::Corrupt)
    ));
}

#[test]
fn deletion_enforces_retained_budget_and_object_kind_atomically() {
    let mut lab = Lab::new();
    lab.config.policy.retained_bytes = 2;
    let alice = lab.alice();
    alice.write_file("save.dat", b"private", "alice").unwrap();
    let revision = alice.inspect().unwrap().revision;
    assert!(matches!(
        alice.delete("save.dat", "alice"),
        Err(Error::Quota)
    ));
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert_eq!(alice.read("save.dat").unwrap(), b"private");
    assert!(alice.inspect().unwrap().trash.is_empty());
    assert!(matches!(
        alice.delete_typed("levels", false, "alice"),
        Err(Error::Unsupported)
    ));
    assert!(matches!(
        alice.delete_typed("save.dat", true, "alice"),
        Err(Error::Unsupported)
    ));
    assert!(matches!(
        alice.delete_typed("levels", true, "alice"),
        Err(Error::NotEmpty)
    ));
    assert_eq!(alice.inspect().unwrap().revision, revision);
}

#[test]
fn protocol_open_reservation_precedes_truncation_and_creation() {
    use sambafied_shadow::OpenRequest;
    let lab = Lab::new();
    let alice = lab.alice();
    let revision = alice.inspect().unwrap().revision;
    for path in ["save.dat", "new.dat"] {
        let result = alice.create_handle_checked(
            OpenRequest {
                path,
                directory: false,
                writable: true,
                disposition: OpenDisposition::OverwriteIf,
                actor: "alice",
            },
            |_| false,
        );
        assert!(matches!(result, Err(Error::Busy)));
    }
    assert_eq!(alice.inspect().unwrap().revision, revision);
    assert_eq!(alice.read("save.dat").unwrap(), b"base-save");
    assert!(matches!(alice.stat("new.dat"), Err(Error::NotFound)));
    let mut reserved = String::new();
    let (handle, entry, _) = alice
        .create_handle_checked(
            OpenRequest {
                path: "new.dat",
                directory: false,
                writable: true,
                disposition: OpenDisposition::Create,
                actor: "alice",
            },
            |entry| {
                reserved = entry.object_id.clone();
                true
            },
        )
        .unwrap();
    assert_eq!(reserved, entry.object_id);
    assert_eq!(reserved, handle.object_id);
}
