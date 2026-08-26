//! System dependency hints for components Baluard needs but does not ship.
//!
//! Rule (AGENTS.md UX PRINCIPLES): the app prints commands, the user runs
//! them. Baluard never installs system packages itself and never asks for
//! the sudo password.

/// D-Bus error fragments that mean "no Secret Service provider is reachable
/// on the session bus". Matched against `keyring::Error` Display output;
/// zbus wording varies a little between versions.
const SECRET_SERVICE_ABSENT_MARKERS: &[&str] = &[
    "ServiceUnknown",
    "org.freedesktop.secrets",
    "not provided by any .service files",
    "Failed to connect to socket",
];

/// True when a keyring error text means the Secret Service provider is
/// missing entirely (as opposed to a locked collection or a missing entry).
pub fn secret_service_absent(err_text: &str) -> bool {
    SECRET_SERVICE_ABSENT_MARKERS
        .iter()
        .any(|m| err_text.contains(m))
}

/// Map an os-release `ID` / `ID_LIKE` pair to the Secret Service install
/// command. Pure so tests can drive it without touching `/etc`.
fn distro_secret_service_hint(id: &str, id_like: &str) -> Option<&'static str> {
    match id {
        "ubuntu" | "debian" | "pop" | "mint" => Some("sudo apt install gnome-keyring"),
        "fedora" | "rhel" | "rocky" | "almalinux" | "nobara" => {
            Some("sudo dnf install gnome-keyring")
        }
        "arch" | "manjaro" | "endeavouros" | "garuda" | "cachyos" => {
            Some("sudo pacman -S gnome-keyring")
        }
        _ => {
            if id_like.contains("debian") || id_like.contains("ubuntu") {
                Some("sudo apt install gnome-keyring")
            } else if id_like.contains("fedora") || id_like.contains("rhel") {
                Some("sudo dnf install gnome-keyring")
            } else if id_like.contains("arch") {
                Some("sudo pacman -S gnome-keyring")
            } else {
                None
            }
        }
    }
}

/// Install command for the Linux Secret Service provider (gnome-keyring).
/// `None` off-Linux or on unknown distros.
pub fn secret_service_install_hint() -> Option<&'static str> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    distro_secret_service_hint(&os_release_field("ID"), &os_release_field("ID_LIKE"))
}

/// Read a single field from `/etc/os-release` (value unquoted). Empty string
/// when the file or field is missing.
fn os_release_field(field: &str) -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|l| {
                l.strip_prefix(&format!("{field}="))
                    .map(|v| v.trim_matches('"').trim().to_string())
            })
        })
        .unwrap_or_default()
}

/// Friendly replacement for a keyring error caused by a missing Secret
/// Service. Returns the original text unchanged for unrelated errors.
pub fn keyring_error_hint(err_text: &str) -> String {
    if !secret_service_absent(err_text) {
        return err_text.to_string();
    }
    match secret_service_install_hint() {
        Some(cmd) => format!(
            "The system keyring service is not running. Baluard needs it to store credentials. Install it with: {cmd}"
        ),
        None => "The system keyring service is not running. Baluard needs it to store credentials. Install gnome-keyring or a compatible Secret Service provider.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_missing_secret_service() {
        assert!(secret_service_absent(
            "Zbus error: ServiceUnknown: The name org.freedesktop.secrets was not provided by any .service files"
        ));
        assert!(secret_service_absent(
            "Failed to connect to socket /run/user/1000/bus: No such file or directory"
        ));
        // Locked collections and plain missing entries are NOT an absent service.
        assert!(!secret_service_absent("Collection is locked"));
        assert!(!secret_service_absent("NoEntry"));
        assert!(!secret_service_absent(""));
    }

    #[test]
    fn maps_distro_hints() {
        assert_eq!(
            distro_secret_service_hint("ubuntu", ""),
            Some("sudo apt install gnome-keyring")
        );
        assert_eq!(
            distro_secret_service_hint("fedora", ""),
            Some("sudo dnf install gnome-keyring")
        );
        assert_eq!(
            distro_secret_service_hint("arch", ""),
            Some("sudo pacman -S gnome-keyring")
        );
        // Derivative distros resolve through ID_LIKE.
        assert_eq!(
            distro_secret_service_hint("somebody\u{2019}s linux", "arch"),
            Some("sudo pacman -S gnome-keyring")
        );
        // Unknown families get no command (caller prints generic text).
        assert_eq!(
            distro_secret_service_hint("opensuse-tumbleweed", "opensuse"),
            None
        );
        assert_eq!(distro_secret_service_hint("", ""), None);
    }

    #[test]
    fn hint_replaces_only_absent_errors() {
        assert!(
            keyring_error_hint("ServiceUnknown: org.freedesktop.secrets missing")
                .starts_with("The system keyring service is not running.")
        );
        assert_eq!(
            keyring_error_hint("Collection is locked"),
            "Collection is locked"
        );
    }
}
