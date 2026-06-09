//! Platform-correct base directories for IDtty.
//!
//! | Data type    | Linux                              | macOS                                    | Windows                  |
//! |--------------|------------------------------------|------------------------------------------|--------------------------|
//! | Data (vault) | `$XDG_DATA_HOME/idtty/`            | `~/Library/Application Support/idtty/`   | `%LOCALAPPDATA%\idtty\`  |
//! | Socket       | `$XDG_RUNTIME_DIR/idtty/idtty.sock`| data_dir `/idtty.sock`                   | Named Pipe               |
//! | Logs         | `$XDG_STATE_HOME/idtty/`           | `~/Library/Logs/idtty/`                  | `%LOCALAPPDATA%\idtty\logs\` |

use std::path::PathBuf;

const APP_NAME: &str = "idtty";

/// Vault data + git repo directory.
///
/// Linux: `$XDG_DATA_HOME/idtty/` or `~/.local/share/idtty/`
/// macOS: `~/Library/Application Support/idtty/`
/// Windows: `%LOCALAPPDATA%\idtty\`
///
/// Use this for the vault, git repo, and all encrypted blobs.
pub fn data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_NAME)
}

/// IPC socket path.
///
/// Linux: `$XDG_RUNTIME_DIR/idtty/idtty.sock` (falls back to data dir)
/// macOS: `~/Library/Application Support/idtty/idtty.sock`
/// Windows: `\\.\pipe\idtty` (Named Pipe, no filesystem path)
pub fn socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        dirs::runtime_dir()
            .map(|d| d.join(APP_NAME).join("idtty.sock"))
            .unwrap_or_else(|| data_dir().join("idtty.sock"))
    }
    #[cfg(target_os = "macos")]
    {
        data_dir().join("idtty.sock")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\idtty")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        data_dir().join("idtty.sock")
    }
}

/// Session token file path.
///
/// Non-Windows: alongside the socket (`<socket>.tok`).
/// Windows: inside data_dir (Named Pipe has no filesystem parent).
pub fn token_path() -> PathBuf {
    #[cfg(windows)]
    {
        data_dir().join("idtty.tok")
    }
    #[cfg(not(windows))]
    {
        socket_path().with_extension("tok")
    }
}

/// Log directory.
///
/// Linux: `$XDG_STATE_HOME/idtty/` or `~/.local/state/idtty/`
/// macOS: `~/Library/Logs/idtty/`
/// Windows: `%LOCALAPPDATA%\idtty\logs\`
///
/// Respects `IDTTY_LOG_DIR` env override.
pub fn log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("IDTTY_LOG_DIR") {
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

        assert!(data.to_string_lossy().contains("idtty"));
        assert!(logs.to_string_lossy().contains("idtty"));
    }

    #[test]
    fn data_dir_is_under_local_data() {
        let data = data_dir();
        assert!(data.to_string_lossy().contains("idtty"));
        assert!(data.is_absolute() || data.starts_with("."));
    }

    #[test]
    fn log_dir_respects_env_override() {
        // Save and restore
        let orig = std::env::var("IDTTY_LOG_DIR").ok();
        unsafe { std::env::set_var("IDTTY_LOG_DIR", "/tmp/idtty-test-logs") };
        assert_eq!(log_dir(), PathBuf::from("/tmp/idtty-test-logs"));
        match orig {
            Some(v) => unsafe { std::env::set_var("IDTTY_LOG_DIR", v) },
            None => unsafe { std::env::remove_var("IDTTY_LOG_DIR") },
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
        assert_eq!(token_path(), data_dir().join("idtty.tok"));
    }
}
