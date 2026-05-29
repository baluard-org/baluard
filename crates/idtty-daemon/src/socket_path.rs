//! Socket path discovery for idtty IPC.
//!
//! All platforms use ~/.config/idtty/ for socket and config.
//! - Unix: ~/.config/idtty/idtty.sock
//! - Windows: \\.\pipe\idtty (Named Pipes)

use std::path::PathBuf;

/// Default socket filename.
const SOCKET_NAME: &str = "idtty.sock";

/// Get the base config directory: ~/.config/idtty/
pub fn config_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("idtty");
    }
    PathBuf::from("/tmp").join("idtty")
}

/// Get the default socket path for this platform.
pub fn default_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        config_dir().join(SOCKET_NAME)
    }

    #[cfg(windows)]
    {
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
