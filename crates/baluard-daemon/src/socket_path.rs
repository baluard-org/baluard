//! Socket path discovery for baluard IPC.
//!
//! Delegates to `baluard_core::paths` for platform-correct resolution.
//! Socket: `$XDG_RUNTIME_DIR/baluard/baluard.sock` (Linux),
//!         `~/Library/Application Support/baluard/baluard.sock` (macOS),
//!         Named Pipe `\\.\pipe\baluard` (Windows).

/// Default IPC socket path for this platform.
pub fn default_socket_path() -> std::path::PathBuf {
    baluard_core::paths::socket_path()
}

/// Resolve socket path: explicit override or platform default.
pub fn resolve_socket_path(explicit: Option<&str>) -> std::path::PathBuf {
    match explicit {
        Some(p) => std::path::PathBuf::from(p),
        None => default_socket_path(),
    }
}
