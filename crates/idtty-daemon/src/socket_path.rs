//! Socket path discovery for idtty IPC.
//!
//! Config/vault base: ~/.config/idtty/ (Unix), %APPDATA%\idtty\ (Windows)
//! Socket: idtty.sock in config dir (Unix), Named Pipe (Windows)

use std::path::PathBuf;

/// Default socket filename.
const SOCKET_NAME: &str = "idtty.sock";

/// Get the base config directory.
/// Unix: ~/.config/idtty/
/// Windows: %APPDATA%\idtty\
pub fn config_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".config").join("idtty");
        }
        PathBuf::from("/tmp").join("idtty")
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("idtty");
        }
        PathBuf::from("C:\\ProgramData").join("idtty")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("/tmp").join("idtty")
    }
}

/// Get the default socket path for this platform.
pub fn default_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        config_dir().join(SOCKET_NAME)
    }
    #[cfg(windows)]
    {
        // Windows: Named Pipes live in a virtual filesystem
        PathBuf::from(r"\\.\pipe\idtty")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }
}

/// Resolve socket path: explicit override or platform default.
pub fn resolve_socket_path(explicit: Option<&str>) -> PathBuf {
    match explicit {
        Some(p) => PathBuf::from(p),
        None => default_socket_path(),
    }
}
