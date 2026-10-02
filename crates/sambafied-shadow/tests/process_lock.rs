//! Exercises the management/SMB maintenance boundary across real processes.
use sambafied_shadow::{Config, Error, Identity, Policy, Store};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Fixture {
    root: PathBuf,
    base: PathBuf,
    identity: Identity,
    policy: Policy,
}
impl Fixture {
    fn config(self) -> Config {
        Config {
            root: self.root,
            base: self.base,
            identity: self.identity,
            policy: self.policy,
        }
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn killed_smb_process_releases_maintenance_lease() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    let base = temp.path().join("base");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&base).unwrap();
    fs::write(base.join("SAVE.DAT"), b"base").unwrap();
    let fixture = Fixture {
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
    };
    let config_file = temp.path().join("fixture.json");
    fs::write(&config_file, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let manager = Store::open(fixture.config()).unwrap();
    manager.write_file("save.dat", b"private", "alice").unwrap();
    let revision = manager.inspect().unwrap().revision;
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lease_child", "--ignored", "--nocapture"])
            .env("SAMBAFIED_TEST_LEASE_FIXTURE", &config_file)
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
                Ok(line) if line == "LEASE_READY" => {
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
        .expect("child did not acquire lease");
    assert!(matches!(manager.reset(revision, "alice"), Err(Error::Busy)));
    assert_eq!(manager.inspect().unwrap().revision, revision);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    manager.reset(revision, "alice").unwrap();
    assert_eq!(manager.read("save.dat").unwrap(), b"base");
}

/// Invoked by the parent test only; ordinary suite execution skips this helper.
#[test]
#[ignore = "subprocess fixture helper"]
fn lease_child() {
    let config_file = std::env::var_os("SAMBAFIED_TEST_LEASE_FIXTURE").expect("parent fixture");
    let fixture: Fixture = serde_json::from_slice(&fs::read(config_file).unwrap()).unwrap();
    let store = Store::open(fixture.config()).unwrap();
    let _handle = store.open_handle("save.dat", false).unwrap();
    println!("LEASE_READY");
    std::io::stdout().flush().unwrap();
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
}
