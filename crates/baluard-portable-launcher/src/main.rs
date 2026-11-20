//! Portable-build entry point (Windows). Sets the portable environment:
//! all state on the drive next to the executable, a per-copy IPC pipe so
//! an installed Baluard (or a second portable copy) is never touched, and
//! the bundled WebView2 runtime when one ships in the zip. With no
//! arguments it launches the desktop app; any arguments forward to the
//! CLI, so one executable serves both entry points. `BALUARD_PORTABLE`
//! also gates browser-bridge registration, in-app updates, self-update,
//! and the SSH agent listener in baluard-core, baluard-cli, and
//! baluard-daemon.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};

const DESKTOP_EXE: &str = "baluard-desktop.exe";
const CLI_EXE: &str = "baluard.exe";
const WEBVIEW2_DIR: &str = "WebView2";

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
}

/// clap requires a subcommand, so an argument-less CLI run is only a help
/// message: no-args is free to mean "open the app".
fn entry_mode(args: &[String]) -> EntryMode {
    if args.is_empty() {
        EntryMode::Desktop
    } else {
        EntryMode::Cli
    }
}

/// Pipe name derived from the install folder: two copies of the zip on one
/// machine must never adopt each other's daemon (the daemon adoption check
/// only compares versions, so a shared name would show copy A's vault in
/// copy B). Sanitized to pipe-safe characters and version-stable; the
/// daemon's user-DACL keeps other local users out regardless.
fn pipe_name(exe_dir: &Path) -> String {
    let sanitized: String = exe_dir
        .to_string_lossy()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // Tail of the path: drives differ at the front (D:\ vs E:\), which is
    // exactly what must NOT collide; short shared suffixes stay readable.
    let start = sanitized.len().saturating_sub(64);
    let tail = &sanitized[start..];
    format!(r"\\.\pipe\baluard-portable-{tail}")
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
        let data_dir = exe_dir.join("data");
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            fatal_gui(&format!("cannot create data folder: {e}"));
        }

        let args: Vec<String> = std::env::args().skip(1).collect();
        match entry_mode(&args) {
            EntryMode::Desktop => {
                let desktop = exe_dir.join(DESKTOP_EXE);
                if !desktop.is_file() {
                    fatal_gui(&format!("{DESKTOP_EXE} not found next to the launcher"));
                }
                let child = Command::new(&desktop)
                    .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
                    .spawn();
                match child {
                    Ok(_) => std::process::exit(0),
                    Err(e) => fatal_gui(&format!("failed to start {DESKTOP_EXE}: {e}")),
                }
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
