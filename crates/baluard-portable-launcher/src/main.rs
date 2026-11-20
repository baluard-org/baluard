//! Portable-build entry point (Windows). Sets the portable environment:
//! all state on the drive next to the executable, a per-copy IPC pipe so
//! an installed Baluard (or a second portable copy) is never touched, and
//! the bundled WebView2 runtime when one ships in the zip. With no
//! arguments it launches the desktop app; any arguments forward to the
//! CLI, so one executable serves both entry points. `--apply-update <dir>`
//! is an internal mode: the desktop app extracts a verified release zip to
//! a staging folder and re-runs the launcher with it, and this process
//! swaps the files in place (old files renamed aside, `data\` untouched)
//! before relaunching the app. `BALUARD_PORTABLE`
//! also gates browser-bridge registration, self-update,
//! and the SSH agent listener in baluard-core, baluard-cli, and
//! baluard-daemon; in-app updates use the portable flow instead.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

const DESKTOP_EXE: &str = "baluard-desktop.exe";
const CLI_EXE: &str = "baluard.exe";
const WEBVIEW2_DIR: &str = "WebView2";
const DATA_DIR_NAME: &str = "data";

/// Environment the launcher removes from its own process before applying
/// the portable values, so a parent shell carrying stale BALUARD_* or
/// WebView2 overrides cannot leak into the child.
const INHERITED_KEYS: &[&str] = &[
    "BALUARD_PORTABLE",
    "BALUARD_DATA_DIR",
    "BALUARD_SOCKET",
    "BALUARD_LOG_DIR",
    "BALUARD_CACHE_DIR",
    "BALUARD_DISABLE_KEYRING",
    "BALUARD_NO_UPDATE_CHECK",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
];

/// Which program to start for this invocation.
#[derive(Debug, PartialEq)]
enum EntryMode {
    Desktop,
    Cli,
    ApplyUpdate(PathBuf),
}

/// clap requires a subcommand, so an argument-less CLI run is only a help
/// message: no-args is free to mean "open the app". A bare --apply-update
/// without a path falls through to the CLI, which rejects the unknown
/// argument with a clear usage error.
fn entry_mode(args: &[String]) -> EntryMode {
    match args.first() {
        None => EntryMode::Desktop,
        Some(arg) if arg == update::UPDATE_ARG => match args.get(1) {
            Some(dir) => EntryMode::ApplyUpdate(PathBuf::from(dir)),
            None => EntryMode::Cli,
        },
        Some(_) => EntryMode::Cli,
    }
}

/// Pipe name derived from the install folder: two copies of the zip on one
/// machine must never adopt each other's daemon (the daemon adoption check
/// only compares versions, so a shared name would show copy A's vault in
/// copy B). Sanitized to pipe-safe characters and version-stable; the
/// daemon's user-DACL keeps other local users out regardless.
fn pipe_name(exe_dir: &Path) -> String {
    format!(r"\\.\pipe\baluard-portable-{}", instance_tail(exe_dir))
}

/// Per-copy discriminator: sanitized tail of the install folder, shared by
/// the IPC pipe and the update-swap mutex so both scope to one copy.
fn instance_tail(exe_dir: &Path) -> String {
    let sanitized: String = exe_dir
        .to_string_lossy()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // Tail of the path: drives differ at the front (D:\ vs E:\), which is
    // exactly what must NOT collide; short shared suffixes stay readable.
    let start = sanitized.len().saturating_sub(64);
    sanitized[start..].to_string()
}

/// Environment applied to this process before spawning anything, so every
/// child inherits the portable posture: state on the drive, per-copy pipe,
/// keyring off (tokens fall back to a file in data\), CLI update checks
/// off, and the bundled WebView2 runtime when present. The browser-executable
/// override is set only when the bundled runtime folder exists: pointing it
/// at a missing folder would defeat the Evergreen fallback.
fn env_pairs(exe_dir: &Path, has_webview: bool) -> Vec<(&'static str, String)> {
    let data_dir = exe_dir.join("data");
    let mut pairs = vec![
        ("BALUARD_PORTABLE", "1".to_string()),
        (
            "BALUARD_DATA_DIR",
            data_dir.to_string_lossy().into_owned(),
        ),
        ("BALUARD_SOCKET", pipe_name(exe_dir)),
        (
            "BALUARD_LOG_DIR",
            data_dir.join("logs").to_string_lossy().into_owned(),
        ),
        (
            "BALUARD_CACHE_DIR",
            data_dir.join("cache").to_string_lossy().into_owned(),
        ),
        ("BALUARD_DISABLE_KEYRING", "1".to_string()),
        ("BALUARD_NO_UPDATE_CHECK", "1".to_string()),
        (
            "WEBVIEW2_USER_DATA_FOLDER",
            data_dir.join("webview").to_string_lossy().into_owned(),
        ),
    ];
    if has_webview {
        pairs.push((
            "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
            exe_dir.join(WEBVIEW2_DIR).to_string_lossy().into_owned(),
        ));
    }
    pairs
}

fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "executable has no parent directory".to_string())
}

/// In-place update swap. On Windows a running executable can be RENAMED
/// but not overwritten, so every replacement goes rename-aside first; the
/// retry window covers the seconds the old desktop and its webview
/// processes need to exit.
/// In-place update swap. On Windows a running executable can be RENAMED
/// but not overwritten, so every replacement is two renames: old file into
/// update-backup\, staged file into place. Renames are same-volume and
/// O(1), so no copies, no extra disk, and a rollback is two renames back.
mod update {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    pub const UPDATE_ARG: &str = "--apply-update";
    const BACKUP_DIR: &str = "update-backup";
    const STAGING_DIR: &str = "update-staging";
    const JOURNAL: &str = "journal.txt";
    /// Per-operation retry window: renames wait out the old desktop and
    /// its webview processes exiting. Each operation gets its OWN window:
    /// a shared deadline would be spent before later entries run.
    const OP_DEADLINE: Duration = Duration::from_secs(20);
    const RETRY_PAUSE: Duration = Duration::from_millis(500);

    fn fs_retry<F, T>(what: &str, op: F) -> Result<T, String>
    where
        F: Fn() -> std::io::Result<T>,
    {
        let deadline = Instant::now() + OP_DEADLINE;
        let mut last: Option<std::io::Error> = None;
        loop {
            match op() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last = Some(e);
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "{what}: {}",
                            last.map(|e| e.to_string()).unwrap_or_else(|| "timed out".into())
                        ));
                    }
                    std::thread::sleep(RETRY_PAUSE);
                }
            }
        }
    }

    fn remove_any(path: &Path) -> std::io::Result<()> {
        if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        }
    }

    fn backup_path(install: &Path, name: &std::ffi::OsStr) -> PathBuf {
        install.join(BACKUP_DIR).join(name)
    }

    /// Swap every staging entry into the install folder. `data` is skipped
    /// defensively even though a release zip never carries it: a user
    /// staging from a live folder must not be able to clobber vaults
    /// (case-insensitive: NTFS and exFAT are).
    ///
    /// The desktop exe goes LAST so an early failure still leaves a
    /// launchable install behind. A journal (target/backup pairs) written
    /// before the first rename lets cleanup_previous restore the exact old
    /// tree if this process dies mid-swap.
    pub fn apply_update(staging: &Path, install: &Path) -> Result<(), String> {
        if !staging.join(super::DESKTOP_EXE).is_file() {
            return Err("update package is incomplete (no desktop app inside)".into());
        }
        let backup_dir = install.join(BACKUP_DIR);
        std::fs::create_dir_all(&backup_dir).map_err(|e| format!("create backup dir: {e}"))?;
        let mut entries: Vec<PathBuf> = std::fs::read_dir(staging)
            .map_err(|e| format!("read staging: {e}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().is_some_and(|n| n != JOURNAL))
            .collect();
        entries.sort();
        entries.sort_by_key(|p| p.file_name() == Some(std::ffi::OsStr::new(super::DESKTOP_EXE)));
        let mut applied: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
        let journal = staging.join(JOURNAL);
        let write_journal = |applied: &[(PathBuf, Option<PathBuf>)]| -> std::io::Result<()> {
            use std::io::Write;
            let mut out = std::io::BufWriter::new(std::fs::File::create(&journal)?);
            for (target, backup) in applied {
                let backup_text = backup
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                writeln!(out, "{}\t{}", target.display(), backup_text)?;
            }
            out.flush()
        };
        let result = (|| -> Result<(), String> {
            for entry in &entries {
                let Some(name) = entry.file_name() else { continue };
                if name.eq_ignore_ascii_case(super::DATA_DIR_NAME) {
                    continue;
                }
                let target = install.join(name);
                if target.symlink_metadata().is_ok() {
                    let backup = backup_path(install, name);
                    let _ = remove_any(&backup);
                    fs_retry("move old file aside", || std::fs::rename(&target, &backup))
                        .map_err(|e| {
                            rollback(install, &applied);
                            e
                        })?;
                    applied.push((target.clone(), Some(backup.clone())));
                } else {
                    applied.push((target.clone(), None));
                }
                write_journal(&applied).map_err(|e| {
                    rollback(install, &applied);
                    format!("write journal: {e}")
                })?;
                if let Err(e) =
                    fs_retry("move update into place", || std::fs::rename(entry, &target))
                {
                    rollback(install, &applied);
                    return Err(e);
                }
            }
            Ok(())
        })();
        if result.is_ok() {
            let _ = std::fs::remove_file(&journal);
            let _ = std::fs::remove_dir_all(&backup_dir);
            let _ = std::fs::remove_dir_all(staging);
            Ok(())
        } else {
            result
        }
    }

    /// Restore the exact old tree: renamed-aside files go back over their
    /// targets; pure new copies (no old file existed) are removed.
    fn rollback(install: &Path, applied: &[(PathBuf, Option<PathBuf>)]) {
        for (target, backup) in applied.iter().rev() {
            if let Some(backup) = backup {
                if backup.exists() {
                    let _ = remove_any(target);
                    let _ = std::fs::rename(backup, target);
                }
            } else {
                let _ = remove_any(target);
            }
        }
        // Empty backup dir from the rolled-back renames; a failed restore
        // leaves files behind, so only an empty dir is ever removed.
        let _ = std::fs::remove_dir(install.join(BACKUP_DIR));
    }

    /// Crash recovery + leftover sweep on normal launches. A journal from
    /// a swap that died mid-way restores the old tree INSTEAD of sweeping;
    /// otherwise the backup dir and staging folder are leftovers from a
    /// completed swap or a rolled-back failure. Only those two launcher-
    /// owned paths are ever touched.
    pub fn cleanup_previous(install: &Path) {
        let staging = install.join(STAGING_DIR);
        let journal = staging.join(JOURNAL);
        if journal.is_file() {
            restore_from_journal(install, &journal);
            let _ = std::fs::remove_dir_all(&staging);
            return;
        }
        let _ = remove_any(&install.join(BACKUP_DIR));
        let _ = std::fs::remove_dir_all(&staging);
    }

    fn restore_from_journal(install: &Path, journal: &Path) {
        let Ok(text) = std::fs::read_to_string(journal) else {
            return;
        };
        for line in text.lines().rev() {
            let Some((target, backup)) = line.split_once('\t') else {
                continue;
            };
            let target = PathBuf::from(target);
            if backup.is_empty() {
                let _ = remove_any(&target);
            } else {
                let backup = PathBuf::from(backup);
                if backup.exists() {
                    let _ = remove_any(&target);
                    let _ = std::fs::rename(&backup, &target);
                }
            }
        }
        let _ = remove_any(&install.join(BACKUP_DIR));
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_SETFOREGROUND, MB_TOPMOST, MB_OK,
    };

    fn message_box(text: &str) {
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide(text).as_ptr(),
                wide("Baluard portable").as_ptr(),
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST,
            );
        }
    }

    fn fatal_gui(text: &str) -> ! {
        message_box(text);
        std::process::exit(1);
    }

    fn spawn_desktop(exe_dir: &Path) -> Result<(), String> {
        let desktop = exe_dir.join(DESKTOP_EXE);
        if !desktop.is_file() {
            return Err(format!("{DESKTOP_EXE} not found next to the launcher"));
        }
        Command::new(&desktop)
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to start {DESKTOP_EXE}: {e}"))
    }

    /// Named per-copy mutex scoping the update swap: a second launcher run
    /// during the swap must not sweep backups/staging mid-flight (B3).
    /// Returns the raw handle; the OS releases it if this process dies.
    fn acquire_update_lock(exe_dir: &Path, wait_ms: u32) -> Result<HANDLE, &'static str> {
        use windows_sys::Win32::Foundation::{
            GetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
        let name = format!(
            "Local\\baluard-portable-apply-{}",
            super::instance_tail(exe_dir)
        );
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide.as_ptr()) };
        if handle.is_null() {
            return Err("could not create the update lock");
        }
        // ERROR_ALREADY_EXISTS (183) means another run owns it: wait for
        // the swap to finish. WAIT_ABANDONED is safe to accept: the previous
        // holder died, and cleanup_previous recovers from the journal.
        let _ = unsafe { GetLastError() };
        let wait = unsafe { WaitForSingleObject(handle, wait_ms) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            Ok(handle)
        } else if wait == WAIT_TIMEOUT {
            Err("update-in-progress-timeout")
        } else {
            Err("update lock wait failed")
        }
    }

    fn release_update_lock(handle: HANDLE) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        unsafe {
            ReleaseMutex(handle);
            CloseHandle(handle);
        }
    }

    fn update_in_progress_box() {
        message_box("Baluard is updating. Try again in a minute.");
    }

    pub fn run() -> ! {
        let exe_dir = match super::exe_dir() {
            Ok(dir) => dir,
            Err(e) => fatal_gui(&e),
        };
        for key in INHERITED_KEYS {
            unsafe { std::env::remove_var(key) };
        }
        let has_webview = exe_dir.join(WEBVIEW2_DIR).is_dir();
        for (key, value) in env_pairs(&exe_dir, has_webview) {
            // SAFETY: single-threaded startup, before any child spawns.
            unsafe { std::env::set_var(key, value) };
        }
        let data_dir = exe_dir.join(DATA_DIR_NAME);
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            fatal_gui(&format!("cannot create data folder: {e}"));
        }

        let args: Vec<String> = std::env::args().skip(1).collect();
        match entry_mode(&args) {
            EntryMode::Desktop => {
                // Wait out a running swap (up to 60 s), then sweep
                // leftovers. A held lock past the wait means a big stick
                // is still swapping: tell the user instead of racing it.
                const SWAP_WAIT_MS: u32 = 60_000;
                match acquire_update_lock(&exe_dir, SWAP_WAIT_MS) {
                    Ok(handle) => {
                        super::update::cleanup_previous(&exe_dir);
                        release_update_lock(handle);
                    }
                    Err("update-in-progress-timeout") => update_in_progress_box(),
                    Err(e) => fatal_gui(e),
                }
                if let Err(e) = spawn_desktop(&exe_dir) {
                    fatal_gui(&e);
                }
                std::process::exit(0);
            }
            EntryMode::ApplyUpdate(staging) => {
                // Hold the lock for the whole swap; the OS releases it on
                // exit, so a killed launcher cannot strand it.
                let lock = match acquire_update_lock(&exe_dir, 0) {
                    Ok(handle) => handle,
                    Err("update-in-progress-timeout") => {
                        update_in_progress_box();
                        std::process::exit(1);
                    }
                    Err(e) => fatal_gui(e),
                };
                if let Err(e) = super::update::apply_update(&staging, &exe_dir) {
                    // The swap rolled back to the old tree: relaunch it so
                    // the user keeps a working app instead of a dead stick.
                    let _ = std::fs::remove_dir_all(&staging);
                    message_box(&format!(
                        "Update failed. The previous version was restored.\n\n{e}"
                    ));
                    let _ = spawn_desktop(&exe_dir);
                    std::process::exit(1);
                }
                let _ = lock; // held until process exit
                if let Err(e) = spawn_desktop(&exe_dir) {
                    fatal_gui(&e);
                }
                std::process::exit(0);
            }
            EntryMode::Cli => {
                let cli = exe_dir.join(CLI_EXE);
                if !cli.is_file() {
                    eprintln!("{CLI_EXE} not found next to the launcher");
                    std::process::exit(1);
                }
                // Errors below stay on stderr: CLI mode serves scripts, and a
                // modal dialog would hang them.
                unsafe {
                    // The launcher must not die on Ctrl-C before the child:
                    // the console signal would orphan the CLI mid-operation.
                    SetConsoleCtrlHandler(None, 1);
                }
                let status = Command::new(&cli).args(&args).status();
                let code = match status {
                    Ok(s) => s.code().unwrap_or(1),
                    Err(e) => {
                        eprintln!("failed to start {CLI_EXE}: {e}");
                        1
                    }
                };
                std::process::exit(code);
            }
        }
    }
}

#[cfg(not(windows))]
fn run() -> ! {
    eprintln!("baluard-portable is the Windows portable-build launcher");
    std::process::exit(1)
}

fn main() {
    #[cfg(windows)]
    win::run();
    #[cfg(not(windows))]
    run();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        PathBuf::from(format!(r"C:\Baluard\{name}"))
    }

    #[test]
    fn desktop_mode_without_args() {
        assert_eq!(entry_mode(&[]), EntryMode::Desktop);
        assert_eq!(entry_mode(&["vault".into(), "list".into()]), EntryMode::Cli);
    }

    #[test]
    fn env_points_at_the_drive() {
        let pairs = env_pairs(&dir("one"), false);
        let get = |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone());
        assert_eq!(get("BALUARD_PORTABLE").as_deref(), Some("1"));
        assert_eq!(get("BALUARD_DATA_DIR"), Some(dir("one").join("data").to_string_lossy().into_owned()));
        assert_eq!(get("BALUARD_DISABLE_KEYRING").as_deref(), Some("1"));
        assert_eq!(get("BALUARD_NO_UPDATE_CHECK").as_deref(), Some("1"));
        assert_eq!(get("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"), None);
        for key in ["BALUARD_LOG_DIR", "BALUARD_CACHE_DIR", "WEBVIEW2_USER_DATA_FOLDER"] {
            let v = get(key).expect(key);
            assert!(v.contains("data"), "{key}={v} must live under data\\");
        }
    }

    #[test]
    fn webview_override_only_when_bundled() {
        let pairs = env_pairs(&dir("one"), true);
        let webview = pairs
            .iter()
            .find(|(k, _)| *k == "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER")
            .map(|(_, v)| v.clone())
            .expect("webview override when bundled");
        assert!(webview.ends_with("WebView2"));
    }

    #[test]
    fn pipe_name_is_per_copy_and_stable() {
        let a = pipe_name(&dir("one"));
        let a_again = pipe_name(&dir("one"));
        let b = pipe_name(&dir("two"));
        assert_eq!(a, a_again, "same folder must derive the same pipe name");
        assert_ne!(a, b, "different folders must not share a pipe");
        assert!(a.starts_with(r"\\.\pipe\baluard-portable-"));
        assert!(a.chars().skip(r"\\.\pipe\baluard-portable-".len()).all(|c| c.is_ascii_alphanumeric()));
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "baluard-launcher-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn apply_update_flag_routes_to_the_swap_mode() {
        assert_eq!(
            entry_mode(&["--apply-update".into(), "C:\\stage".into()]),
            EntryMode::ApplyUpdate(PathBuf::from("C:\\stage"))
        );
        assert_eq!(entry_mode(&["--apply-update".into()]), EntryMode::Cli);
    }

    #[test]
    fn apply_update_swaps_files_and_keeps_data() {
        let staging = tempdir("stage");
        let install = tempdir("install");
        write_file(&staging.join("baluard-desktop.exe"), "new-desktop");
        write_file(&staging.join("baluard.exe"), "new-cli");
        write_file(&staging.join("WebView2/msedgewebview2.exe"), "new-webview");
        write_file(&install.join("baluard-desktop.exe"), "old-desktop");
        write_file(&install.join("baluard.exe"), "old-cli");
        write_file(&install.join("WebView2/msedgewebview2.exe"), "old-webview");
        write_file(&install.join("data/vault.txt"), "keep-me");
        write_file(&install.join("DATA/other.txt"), "keep-me-too");

        update::apply_update(&staging, &install).expect("swap succeeds");

        assert_eq!(
            std::fs::read_to_string(install.join("baluard-desktop.exe")).unwrap(),
            "new-desktop"
        );
        assert_eq!(std::fs::read_to_string(install.join("baluard.exe")).unwrap(), "new-cli");
        assert_eq!(
            std::fs::read_to_string(install.join("WebView2/msedgewebview2.exe")).unwrap(),
            "new-webview"
        );
        assert_eq!(
            std::fs::read_to_string(install.join("data/vault.txt")).unwrap(),
            "keep-me"
        );
        assert_eq!(
            std::fs::read_to_string(install.join("DATA/other.txt")).unwrap(),
            "keep-me-too",
            "the data skip is case-insensitive (NTFS/exFAT)"
        );
        assert!(!install.join("update-backup").exists(), "backup dir cleaned on success");
        assert!(!install.join("update-staging").exists(), "staging removed on success");
    }

    #[test]
    fn apply_update_rejects_incomplete_staging() {
        let staging = tempdir("stage-bad");
        let install = tempdir("install-bad");
        write_file(&staging.join("baluard.exe"), "cli-only");
        assert!(update::apply_update(&staging, &install).is_err());
        assert!(
            !install.join("baluard.exe").exists(),
            "rejected swap must not touch the install"
        );
    }

    #[test]
    fn apply_update_accepts_a_fresh_install_dir() {
        let staging = tempdir("stage-fresh");
        let install = tempdir("install-fresh");
        write_file(&staging.join("baluard-desktop.exe"), "desktop");
        update::apply_update(&staging, &install).expect("first-time swap succeeds");
        assert_eq!(
            std::fs::read_to_string(install.join("baluard-desktop.exe")).unwrap(),
            "desktop"
        );
    }

    #[test]
    fn cleanup_sweeps_only_launcher_owned_paths() {
        let install = tempdir("sweep");
        std::fs::create_dir_all(install.join("update-backup")).unwrap();
        write_file(&install.join("update-backup/baluard-desktop.exe"), "stale");
        std::fs::create_dir_all(install.join("update-staging")).unwrap();
        // User files that merely LOOK like leftovers must survive.
        write_file(&install.join("data.old/vault.txt"), "user-backup");
        write_file(&install.join("old-notes.txt"), "user-file");
        write_file(&install.join("baluard-desktop.exe"), "live");
        write_file(&install.join("data/vault.txt"), "keep");

        update::cleanup_previous(&install);

        assert!(install.join("baluard-desktop.exe").exists());
        assert!(install.join("data/vault.txt").exists());
        assert_eq!(
            std::fs::read_to_string(install.join("data.old/vault.txt")).unwrap(),
            "user-backup",
            "a user backup named data.old must never be swept (B1)"
        );
        assert!(install.join("old-notes.txt").exists());
        assert!(!install.join("update-backup").exists());
        assert!(!install.join("update-staging").exists());
    }

    #[test]
    fn journal_from_a_dead_swap_restores_the_old_tree() {
        let _staging = tempdir("journal-stage");
        let install = tempdir("journal-install");
        // Half-swapped state: desktop moved to backup + journal says so.
        std::fs::create_dir_all(install.join("update-backup")).unwrap();
        std::fs::create_dir_all(install.join("update-staging")).unwrap();
        std::fs::write(install.join("update-backup/baluard-desktop.exe"), "old-desktop").unwrap();
        std::fs::write(install.join("baluard.exe"), "new-cli").unwrap(); // pure-new copy in flight
        std::fs::write(
            install.join("update-staging/journal.txt"),
            format!(
                "{}\t{}\n{}\t\n",
                install.join("baluard-desktop.exe").display(),
                install.join("update-backup/baluard-desktop.exe").display(),
                install.join("baluard.exe").display()
            ),
        )
        .unwrap();

        update::cleanup_previous(&install);

        assert_eq!(
            std::fs::read_to_string(install.join("baluard-desktop.exe")).unwrap(),
            "old-desktop",
            "the journal restores the renamed-aside old file"
        );
        assert!(
            !install.join("baluard.exe").exists(),
            "a pure-new copy without a backup is removed by the journal"
        );
        assert!(!install.join("update-staging").exists());
        assert!(!install.join("update-backup").exists());
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "baluard-launcher-rollback-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A read-only staging dir fails the journal write right after the
    /// first entry was renamed aside: the swap must roll the whole install
    /// back to the exact old tree instead of leaving a mix (B2).
    #[test]
    fn failed_swap_rolls_back_to_the_exact_old_tree() {
        use std::os::unix::fs::PermissionsExt;
        let staging = tempdir("stage");
        let install = tempdir("install");
        std::fs::write(staging.join("baluard-desktop.exe"), "new-desktop").unwrap();
        std::fs::write(staging.join("baluard.exe"), "new-cli").unwrap();
        std::fs::write(install.join("baluard-desktop.exe"), "old-desktop").unwrap();
        std::fs::write(install.join("baluard.exe"), "old-cli").unwrap();
        let mut perms = std::fs::metadata(&staging).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&staging, perms).unwrap();

        let result = update::apply_update(&staging, &install);
        let mut perms = std::fs::metadata(&staging).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staging, perms).unwrap();
        assert!(result.is_err(), "read-only staging must fail the swap");

        assert_eq!(
            std::fs::read_to_string(install.join("baluard-desktop.exe")).unwrap(),
            "old-desktop",
            "entry renamed aside must be rolled back"
        );
        assert_eq!(
            std::fs::read_to_string(install.join("baluard.exe")).unwrap(),
            "old-cli",
            "unprocessed entries stay untouched"
        );
        assert!(
            !install.join("update-backup").exists(),
            "rollback restores renamed-aside files and clears the backup dir"
        );
    }
}
