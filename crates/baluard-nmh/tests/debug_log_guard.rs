//! C9: the NMH debug tee must never write through a pre-planted symlink,
//! must stay off unless BALUARD_DEBUG=1, and must land in log_dir (0600).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// Unique dir under the system temp dir for this test run.
fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "baluard-nmh-c9-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn spawn_nmh(log_dir: &std::path::Path) {
    Command::new(env!("CARGO_BIN_EXE_baluard-nmh"))
        .env("BALUARD_DEBUG", "1")
        .env("BALUARD_LOG_DIR", log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn baluard-nmh");
}

#[test]
fn debug_tee_never_follows_preplanted_symlink() {
    let dir = fresh_dir("symlink");
    let victim = dir.join("victim.txt");
    fs::write(&victim, "original").unwrap();

    let log_path = dir.join("baluard-nmh.debug.log");
    std::os::unix::fs::symlink(&victim, &log_path).unwrap();

    spawn_nmh(&dir);

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"original",
        "symlink target must be untouched"
    );
    assert!(
        log_path.is_symlink(),
        "the symlink itself must not be replaced"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn debug_tee_disabled_without_env_and_0600_when_enabled() {
    // Without BALUARD_DEBUG: no log file anywhere in the dir.
    let dir = fresh_dir("off");
    Command::new(env!("CARGO_BIN_EXE_baluard-nmh"))
        .env_remove("BALUARD_DEBUG")
        .env("BALUARD_LOG_DIR", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
    assert!(
        entries.iter().all(|e| !e.as_ref().unwrap().file_name().to_string_lossy().contains("nmh")),
        "no NMH log may exist without BALUARD_DEBUG=1"
    );
    let _ = fs::remove_dir_all(&dir);

    // With BALUARD_DEBUG=1: log lands in log_dir with 0600.
    let dir = fresh_dir("on");
    spawn_nmh(&dir);
    let log = dir.join("baluard-nmh.debug.log");
    assert!(log.is_file(), "log file must exist in log_dir when enabled");
    let mode = fs::metadata(&log).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "NMH debug log must be owner-only");
    let _ = fs::remove_dir_all(&dir);
}
