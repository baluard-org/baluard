//! Platform-correct base directories for Baluard.
//!
//! | Data type    | Linux                              | macOS                                    | Windows                  |
//! |--------------|------------------------------------|------------------------------------------|--------------------------|
//! | Data (vault) | `$XDG_DATA_HOME/baluard/`            | `~/Library/Application Support/baluard/`   | `%LOCALAPPDATA%\baluard\`  |
//! | Cache        | `$XDG_CACHE_HOME/baluard/`           | `~/Library/Caches/baluard/`                | `%LOCALAPPDATA%\baluard\`  |
//! | Socket       | `$XDG_RUNTIME_DIR/baluard/baluard.sock`| data_dir `/baluard.sock`                   | Named Pipe               |
//! | Logs         | `$XDG_STATE_HOME/baluard/`           | `~/Library/Logs/baluard/`                  | `%LOCALAPPDATA%\baluard\logs\` |

use std::path::PathBuf;

const APP_NAME: &str = "baluard";

/// Vault data + git repo directory.
///
/// Linux: `$XDG_DATA_HOME/baluard/` or `~/.local/share/baluard/`
/// macOS: `~/Library/Application Support/baluard/`
/// Windows: `%LOCALAPPDATA%\baluard\`
///
/// Respects `BALUARD_DATA_DIR` env override. Used by tests to point
/// at a sandboxed data dir without polluting the real platform path.
/// Production callers should leave the env var unset.
///
/// Use this for the vault, git repo, and all encrypted blobs.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BALUARD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_NAME)
}

/// Directory containing all managed vaults.
///
/// `<data_dir>/vaults/`
///
/// Each vault lives in a subdirectory named by its slug.
pub fn vaults_dir() -> PathBuf {
    data_dir().join("vaults")
}

/// IPC socket path.
///
/// Linux: `$XDG_RUNTIME_DIR/baluard/baluard.sock` (falls back to data dir)
/// macOS: `~/Library/Application Support/baluard/baluard.sock`
/// Windows: `\\.\pipe\baluard-<USERNAME>` (Named Pipe, no filesystem path;
/// per-user suffix because pipe names are machine-global and a second
/// Windows session must not collide with or squat this one)
pub fn socket_path() -> PathBuf {
    // Test escape hatch: an explicit socket beats platform defaults
    // (same trust class as BALUARD_DATA_DIR / BALUARD_LOG_DIR; the NMH
    // has no flag surface and must reach a test daemon).
    if let Ok(path) = std::env::var("BALUARD_SOCKET") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    #[cfg(target_os = "linux")]
    {
        dirs::runtime_dir()
            .map(|d| d.join(APP_NAME).join("baluard.sock"))
            .unwrap_or_else(|| data_dir().join("baluard.sock"))
    }
    #[cfg(target_os = "macos")]
    {
        data_dir().join("baluard.sock")
    }
    #[cfg(windows)]
    {
        // Segment by SID, not USERNAME: the env var is spoofable per
        // process and non-ASCII names collide after sanitizing. SID
        // strings are pure "S-1-5-..." so they need no escaping.
        let suffix = crate::ipc::windows_pipe_user_suffix();
        PathBuf::from(format!(r"\\.\pipe\baluard-{suffix}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        data_dir().join("baluard.sock")
    }
}

/// Session token file path.
///
/// Non-Windows: alongside the socket (`<socket>.tok`).
/// Windows: inside data_dir (Named Pipe has no filesystem parent).
pub fn token_path() -> PathBuf {
    #[cfg(windows)]
    {
        data_dir().join("baluard.tok")
    }
    #[cfg(not(windows))]
    {
        socket_path().with_extension("tok")
    }
}

/// Log directory.
///
/// Linux: `$XDG_STATE_HOME/baluard/` or `~/.local/state/baluard/`
/// macOS: `~/Library/Logs/baluard/`
/// Windows: `%LOCALAPPDATA%\baluard\logs\`
///
/// Respects `BALUARD_LOG_DIR` env override.
///
/// Use this for daemon and desktop logs.
pub fn log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BALUARD_LOG_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(target_os = "linux")]
    {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(APP_NAME)
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join("Library").join("Logs").join(APP_NAME))
            .unwrap_or_else(data_dir)
    }
    #[cfg(windows)]
    {
        dirs::data_local_dir()
            .map(|d| d.join(APP_NAME).join("logs"))
            .unwrap_or_else(|| PathBuf::from("."))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        data_dir()
    }
}

/// Debug log file path (`daemon.log` inside log_dir).
pub fn debug_log_path() -> PathBuf {
    log_dir().join("daemon.log")
}

/// Cache directory for disposable client state (update checks).
///
/// Linux: `$XDG_CACHE_HOME/baluard/` or `~/.cache/baluard/`
/// macOS: `~/Library/Caches/baluard/`
/// Windows: `%LOCALAPPDATA%\baluard\`
///
/// Respects `BALUARD_CACHE_DIR` env override (same test escape-hatch class
/// as `BALUARD_DATA_DIR` / `BALUARD_LOG_DIR`). Safe to delete at any time;
/// callers must tolerate absence.
pub fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BALUARD_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::cache_dir()
        .map(|d| d.join(APP_NAME))
        .unwrap_or_else(data_dir)
}

/// Update-check state file (last check time + latest seen version).
pub fn update_state_path() -> PathBuf {
    cache_dir().join("update-check.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex serialises tests that mutate process-wide env vars.
    /// `cargo test` runs unit tests in parallel; concurrent `set_var` on
    /// the same key is a data race (Rust 1.85 makes `set_var` `unsafe`
    /// for this reason). Holding this lock for the duration of each
    /// env-mutating test prevents flakes.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn paths_are_consistent() {
        let data = data_dir();
        let logs = log_dir();

        assert!(data.to_string_lossy().contains("baluard"));
        assert!(logs.to_string_lossy().contains("baluard"));
    }

    #[test]
    fn data_dir_is_under_local_data() {
        let data = data_dir();
        assert!(data.to_string_lossy().contains("baluard"));
        assert!(data.is_absolute() || data.starts_with("."));
    }

    /// RAII guard for a process-wide env var. Restores the previous value
    /// (or removes the var) on drop — exception-safe, so a panic in the
    /// test body cannot leak the test's env state to subsequent tests.
    /// Holds `ENV_LOCK` for its lifetime so concurrent env-mutating tests
    /// are serialised.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var(key).ok();
            // SAFETY: serialised by ENV_LOCK (held for the guard's lifetime).
            unsafe { std::env::set_var(key, value) };
            EnvGuard {
                key,
                prev,
                _lock: lock,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: serialised by ENV_LOCK (released after this Drop).
            match self.prev.take() {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn log_dir_respects_env_override() {
        let _g = EnvGuard::set("BALUARD_LOG_DIR", "/tmp/baluard-test-logs");
        assert_eq!(log_dir(), PathBuf::from("/tmp/baluard-test-logs"));
    }

    #[test]
    fn data_dir_respects_env_override() {
        let _g = EnvGuard::set("BALUARD_DATA_DIR", "/tmp/baluard-test-data");
        assert_eq!(data_dir(), PathBuf::from("/tmp/baluard-test-data"));
    }

    #[test]
    fn debug_log_path_is_inside_log_dir() {
        // Hold the env lock so a concurrent env-mutating test cannot leave a
        // BALUARD_LOG_DIR / BALUARD_DATA_DIR override in flight that would
        // make log_dir() here return a different path than debug_log_path()
        // expects. The lock is harmless when no env is set (read-only access).
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(debug_log_path(), log_dir().join("daemon.log"));
    }

    #[test]
    fn cache_dir_respects_env_override() {
        let _g = EnvGuard::set("BALUARD_CACHE_DIR", "/tmp/baluard-test-cache");
        assert_eq!(cache_dir(), PathBuf::from("/tmp/baluard-test-cache"));
        assert_eq!(
            update_state_path(),
            PathBuf::from("/tmp/baluard-test-cache/update-check.json")
        );
    }

    #[test]
    fn update_state_path_is_inside_cache_dir() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(update_state_path().starts_with(&cache_dir()));
        assert!(update_state_path().to_string_lossy().contains("baluard"));
    }

    #[cfg(not(windows))]
    #[test]
    fn socket_path_has_sock_extension() {
        assert_eq!(
            socket_path()
                .extension()
                .map(|e| e.to_string_lossy().into_owned()),
            Some("sock".to_string())
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn token_path_is_alongside_socket() {
        let tok = token_path();
        let sock = socket_path();
        assert_eq!(tok.parent(), sock.parent());
        assert_eq!(
            tok.extension().map(|e| e.to_string_lossy().into_owned()),
            Some("tok".to_string())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_socket_is_named_pipe() {
        assert!(socket_path().to_string_lossy().starts_with(r"\\.\pipe\"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_token_is_in_data_dir() {
        assert_eq!(token_path(), data_dir().join("baluard.tok"));
    }
}
