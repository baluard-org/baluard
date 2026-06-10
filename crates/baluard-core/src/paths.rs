//! Platform-correct base directories for Baluard.
//!
//! | Data type    | Linux                              | macOS                                    | Windows                  |
//! |--------------|------------------------------------|------------------------------------------|--------------------------|
//! | Data (vault) | `$XDG_DATA_HOME/baluard/`            | `~/Library/Application Support/baluard/`   | `%LOCALAPPDATA%\baluard\`  |
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
/// Use this for the vault, git repo, and all encrypted blobs.
pub fn data_dir() -> PathBuf {
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
/// Windows: `\\.\pipe\baluard` (Named Pipe, no filesystem path)
pub fn socket_path() -> PathBuf {
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
        PathBuf::from(r"\\.\pipe\baluard")
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn log_dir_respects_env_override() {
        // Save and restore
        let orig = std::env::var("BALUARD_LOG_DIR").ok();
        unsafe { std::env::set_var("BALUARD_LOG_DIR", "/tmp/baluard-test-logs") };
        assert_eq!(log_dir(), PathBuf::from("/tmp/baluard-test-logs"));
        match orig {
            Some(v) => unsafe { std::env::set_var("BALUARD_LOG_DIR", v) },
            None => unsafe { std::env::remove_var("BALUARD_LOG_DIR") },
        }
    }

    #[test]
    fn debug_log_path_is_inside_log_dir() {
        assert_eq!(debug_log_path(), log_dir().join("daemon.log"));
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
