//! Behavioral tests for private protocol storage, cleanup and reservations.
use sambafied_shadow::{Config, Identity, Policy, Store};
use smb_server_backend_shadow::{ShadowVfs, UnmappedVfs};
use smb_server_vfs::{CreateArgs, SetOp, Vfs, VfsError};
use std::{
    fs,
    sync::{Arc, Mutex},
};

const READ: u32 = 0x8000_0000;
const WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;

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
        fs::write(base.join("BASE.TXT"), b"immutable base").unwrap();
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
                    temporary_bytes: 2048,
                    max_file_bytes: 1024,
                    snapshot_limit: 20,
                    history_limit: 100,
                    snapshot_ttl_seconds: 3600,
                    recovery_protection_seconds: 300,
                    trash_ttl_seconds: 3600,
                },
            },
        }
    }
    fn alice(&self) -> ShadowVfs {
        ShadowVfs::new(self.config.clone()).unwrap()
    }
    fn bob(&self) -> ShadowVfs {
        let mut config = self.config.clone();
        config.identity.principal = "bob".into();
        ShadowVfs::new(config).unwrap()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn private_saves_survive_backend_reconnect_and_preserve_base() {
    let lab = Lab::new();
    let alice = lab.alice();
    let bob = lab.bob();
    let (mut old_reader, _, _) = alice
        .create("base.txt", false, READ, 1, 0x40, 0x80)
        .await
        .unwrap();
    let (mut writer, _, action) = alice
        .create("BASE.TXT", false, READ | WRITE, 5, 0x40, 0x80)
        .await
        .unwrap();
    assert_eq!(action, 3);
    alice
        .write(&mut writer, 0, b"private save", true)
        .await
        .unwrap();
    assert_eq!(
        alice.read(&mut old_reader, 0, 128).await.unwrap(),
        b"private save"
    );
    let (mut bob_file, _, _) = bob
        .create("base.txt", false, READ, 1, 0x40, 0x80)
        .await
        .unwrap();
    assert_ne!(writer.path, bob_file.path);
    assert_eq!(
        bob.read(&mut bob_file, 0, 128).await.unwrap(),
        b"immutable base"
    );
    assert!(matches!(
        bob.read(&mut writer, 0, 128).await,
        Err(VfsError::AccessDenied)
    ));
    alice.flush(&mut writer).await.unwrap();
    alice.close(writer).await.unwrap();
    alice.close(old_reader).await.unwrap();
    bob.close(bob_file).await.unwrap();
    drop(alice);
    let reopened = lab.alice();
    let (mut save, _, _) = reopened
        .create("base.txt", false, READ, 1, 0x40, 0x80)
        .await
        .unwrap();
    assert_eq!(
        reopened.read(&mut save, 0, 128).await.unwrap(),
        b"private save"
    );
    reopened.close(save).await.unwrap();
    assert_eq!(
        fs::read(lab.config.base.join("BASE.TXT")).unwrap(),
        b"immutable base"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn denied_reservations_do_not_truncate_and_use_actual_object_key() {
    let lab = Lab::new();
    let alice = lab.alice();
    let args = CreateArgs {
        rel: "base.txt",
        is_dir: false,
        access: WRITE,
        disposition: 5,
        options: 0x40,
        attrs: 0x80,
    };
    assert!(matches!(
        alice
            .create_checked(args, Arc::new(|_| Err(VfsError::SharingViolation)))
            .await,
        Err(VfsError::SharingViolation)
    ));
    assert_eq!(
        Store::open(lab.config.clone())
            .unwrap()
            .read("base.txt")
            .unwrap(),
        b"immutable base"
    );
    let captured = Arc::new(Mutex::new(String::new()));
    let output = captured.clone();
    let (file, _, _) = alice
        .create_checked(
            args,
            Arc::new(move |key| {
                *output.lock().unwrap() = key.to_string();
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert_eq!(file.path, *captured.lock().unwrap());
    alice.close(file).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rename_keeps_private_handle_key_and_delete_waits_for_last_close() {
    let lab = Lab::new();
    let alice = lab.alice();
    let (mut writer, _, _) = alice
        .create("base.txt", false, READ | DELETE, 1, 0x40, 0x80)
        .await
        .unwrap();
    let (mut reader, _, _) = alice
        .create("base.txt", false, READ, 1, 0x40, 0x80)
        .await
        .unwrap();
    let key = writer.path.clone();
    assert!(matches!(
        alice
            .set_info_open(
                &mut writer,
                &SetOp::Rename {
                    replace_if_exists: true,
                    name: "base.txt".into(),
                }
            )
            .await,
        Err(VfsError::NotSupported)
    ));
    assert_eq!(
        alice.read(&mut reader, 0, 128).await.unwrap(),
        b"immutable base"
    );
    alice
        .set_info_open(
            &mut writer,
            &SetOp::Rename {
                replace_if_exists: false,
                name: "moved.txt".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(writer.path, key);
    assert_eq!(alice.stat(&reader.path).await.unwrap().eof, 14);
    alice
        .set_info_open(&mut writer, &SetOp::Disposition { delete: true })
        .await
        .unwrap();
    assert!(matches!(
        alice.create("moved.txt", false, READ, 1, 0x40, 0x80).await,
        Err(VfsError::AccessDenied)
    ));
    alice.close(writer).await.unwrap();
    assert_eq!(
        alice.read(&mut reader, 0, 128).await.unwrap(),
        b"immutable base"
    );
    alice.close(reader).await.unwrap();
    assert!(matches!(
        alice.stat("moved.txt").await,
        Err(VfsError::NotFound)
    ));
    let manager = Store::open(lab.config.clone()).unwrap();
    assert_eq!(manager.inspect().unwrap().trash.len(), 1);
    assert!(matches!(
        manager.read("base.txt"),
        Err(sambafied_shadow::Error::NotFound)
    ));
    let bob = lab.bob();
    assert_eq!(bob.stat("base.txt").await.unwrap().eof, 14);
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_handles_apply_pending_delete_and_release_maintenance_lease() {
    let lab = Lab::new();
    let alice = lab.alice();
    let manager = Store::open(lab.config.clone()).unwrap();
    let (mut file, _, _) = alice
        .create("base.txt", false, READ | DELETE, 1, 0x40, 0x80)
        .await
        .unwrap();
    assert!(matches!(
        manager.reset(manager.inspect().unwrap().revision, "alice"),
        Err(sambafied_shadow::Error::Busy)
    ));
    alice
        .set_info_open(&mut file, &SetOp::Disposition { delete: true })
        .await
        .unwrap();
    drop(file); // A disconnected connection can drop an OpenFile without CLOSE.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if matches!(
            manager.read("base.txt"),
            Err(sambafied_shadow::Error::NotFound)
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "disconnect cleanup did not complete"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    manager
        .reset(manager.inspect().unwrap().revision, "alice")
        .unwrap();
    assert_eq!(manager.read("base.txt").unwrap(), b"immutable base");
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_open_still_cleans_delete_intent_and_maintenance_lease() {
    let lab = Lab::new();
    let alice = Arc::new(lab.alice());
    let manager = Store::open(lab.config.clone()).unwrap();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let entered = Mutex::new(Some(entered_tx));
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let release = Mutex::new(release_rx);
            let task = tokio::task::spawn_local(async move {
                alice
                    .create_checked(
                        CreateArgs {
                            rel: "base.txt",
                            is_dir: false,
                            access: READ | DELETE,
                            disposition: 1,
                            options: 0x1040,
                            attrs: 0x80,
                        },
                        Arc::new(move |_| {
                            entered.lock().unwrap().take().unwrap().send(()).unwrap();
                            release.lock().unwrap().recv().unwrap();
                            Ok(())
                        }),
                    )
                    .await
            });
            entered_rx.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            release_tx.send(()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if matches!(
                    manager.read("base.txt"),
                    Err(sambafied_shadow::Error::NotFound)
                ) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "cancelled open leaked cleanup"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            manager
                .reset(manager.inspect().unwrap().revision, "alice")
                .unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_only_root_opens_and_unsupported_operations_are_explicit() {
    let lab = Lab::new();
    let alice = lab.alice();
    let (directory, meta, _) = alice.create("", false, READ, 1, 0, 0x80).await.unwrap();
    assert!(directory.is_dir && meta.is_dir);
    alice.close(directory).await.unwrap();
    let (mut file, _, _) = alice
        .create("base.txt", false, READ, 1, 0x40, 0x80)
        .await
        .unwrap();
    assert!(matches!(
        alice.write(&mut file, 0, b"forbidden", false).await,
        Err(VfsError::AccessDenied)
    ));
    assert!(matches!(
        alice
            .set_info_open(
                &mut file,
                &SetOp::Basic {
                    access: None,
                    write: None
                }
            )
            .await,
        Err(VfsError::NotSupported)
    ));
    assert!(matches!(
        alice.set_security("base.txt", b"acl").await,
        Err(VfsError::NotSupported)
    ));
    assert!(matches!(
        alice
            .create("base.txt:stream", false, WRITE, 5, 0x40, 0x80)
            .await,
        Err(VfsError::InvalidArgument)
    ));
    alice.close(file).await.unwrap();
    let denied = UnmappedVfs;
    assert!(matches!(
        denied.create("base.txt", false, WRITE, 5, 0x40, 0x80).await,
        Err(VfsError::AccessDenied)
    ));
    assert!(matches!(denied.list("").await, Err(VfsError::AccessDenied)));
}
