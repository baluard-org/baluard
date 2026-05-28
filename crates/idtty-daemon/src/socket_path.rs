//! Socket path discovery for idtty IPC.
//!
//! Platform-aware default socket path:
//! - Linux: $XDG_RUNTIME_DIR/idtty.sock or /tmp/idtty.sock
//! - macOS: $HOME/Library/Application Support/idtty/idtty.sock
//! - Windows: \\.\pipe\idtty (Named Pipes)

use std::path::PathBuf;

/// Default socket filename.
const SOCKET_NAME: &str = "idtty.sock";

/// Get the default socket path for this platform.
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        // XDG_RUNTIME_DIR is the canonical location (e.g. /run/user/1000)
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let dir = PathBuf::from(xdg);
            if dir.is_dir() {
                return dir.join(SOCKET_NAME);
            }
        }
        // Fallback to /tmp (exists on all Linux systems)
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: ~/Library/Application Support/idtty/
        if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("idtty");
            return dir.join(SOCKET_NAME);
        }
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }

    #[cfg(target_os = "windows")]
    {
        // Windows Named Pipes live in a virtual filesystem
        PathBuf::from(r"\\.\pipe\idtty")
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
