//! Socket path discovery for idtty IPC.
//!
//! Delegates to `idtty_core::paths` for platform-correct resolution.
//! Socket: `$XDG_RUNTIME_DIR/idtty/idtty.sock` (Linux),
//!         `~/Library/Application Support/idtty/idtty.sock` (macOS),
//!         Named Pipe `\\.\pipe\idtty` (Windows).

/// Default IPC socket path for this platform.
pub fn default_socket_path() -> std::path::PathBuf {
    idtty_core::paths::socket_path()
}

/// Resolve socket path: explicit override or platform default.
pub fn resolve_socket_path(explicit: Option<&str>) -> std::path::PathBuf {
    match explicit {
        Some(p) => std::path::PathBuf::from(p),
        None => default_socket_path(),
    }
}
