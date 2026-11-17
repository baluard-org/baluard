//! `baluard ssh`: set up the OpenSSH agent endpoint the daemon serves for
//! this machine. The endpoint itself lives in the daemon (bound whenever
//! the daemon runs); these commands report it, start the daemon on
//! demand, and manage an opt-in systemd user unit. SSH config is never
//! edited — the exact lines to add are printed instead.

use crate::SshAction;
use crate::client;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub(super) fn deny(reason: &str) -> ! {
    eprintln!("{}", serde_json::json!({"error": reason}));
    std::process::exit(1)
}

pub fn handle(
    action: crate::SshAction,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        SshAction::Status => status(socket),
        SshAction::Serve => serve(socket),
        SshAction::Install => install(socket),
        SshAction::Uninstall => uninstall(socket),
    }
}

fn ipc_socket(socket: Option<&str>) -> PathBuf {
    socket
        .map(PathBuf::from)
        .unwrap_or_else(baluard_core::paths::socket_path)
}

fn agent_endpoint(ipc: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        // Windows OpenSSH clients hardcode the canonical pipe; the daemon
        // serves it whenever it runs.
        let _ = ipc;
        PathBuf::from(r"\\.\pipe\openssh-ssh-agent")
    }
    #[cfg(not(windows))]
    {
        baluard_core::paths::agent_socket_path(&ipc.to_string_lossy())
    }
}

fn endpoint_listening(endpoint: &Path) -> bool {
    #[cfg(windows)]
    {
        let _ = endpoint;
        false
    }
    #[cfg(not(windows))]
    {
        std::os::unix::net::UnixStream::connect(endpoint).is_ok()
    }
}

fn ping(socket: Option<&str>) -> bool {
    client::request_to("ping", "", socket)
        .map(|resp| resp.success)
        .unwrap_or(false)
}

fn daemon_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("baluard"));
    exe.with_file_name(if cfg!(windows) {
        "baluard-daemon.exe"
    } else {
        "baluard-daemon"
    })
}

fn print_setup(agent: &Path) {
    println!();
    println!("Point OpenSSH at the agent for one shell:");
    println!("  export SSH_AUTH_SOCK=\"{}\"", agent.display());
    println!("or persistently in ~/.ssh/config, per host:");
    println!("  IdentityAgent {}", agent.display());
}

fn status(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let ipc = ipc_socket(socket);
    let agent = agent_endpoint(&ipc);
    let running = ping(socket);
    if running {
        println!("Daemon:       running (socket {})", ipc.display());
    } else {
        println!("Daemon:       not running");
    }
    let endpoint = if endpoint_listening(&agent) {
        format!("{} (listening)", agent.display())
    } else {
        format!("{} (not listening)", agent.display())
    };
    println!("Agent socket: {endpoint}");
    if running {
        let counts = vault_presence_counts(socket);
        println!("Vaults:       {counts}");
    }
    print_setup(&agent);
    Ok(())
}

fn vault_presence_counts(socket: Option<&str>) -> String {
    let Ok(resp) = client::request_to("vaults.list", "", socket) else {
        return "unknown".into();
    };
    if !resp.success {
        return "unknown".into();
    }
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&resp.payload) else {
        return "unknown".into();
    };
    let mut unlocked = 0;
    let mut locked = 0;
    let mut closed = 0;
    for row in data["vaults"].as_array().unwrap_or(&Vec::new()) {
        match row["presence"].as_str().unwrap_or("closed") {
            "unlocked" => unlocked += 1,
            "locked" => locked += 1,
            _ => closed += 1,
        }
    }
    if unlocked + locked + closed == 0 {
        return "none".into();
    }
    format!("{unlocked} unlocked, {locked} locked, {closed} closed")
}

/// Wait until the daemon answers on the default socket, so serve/install
/// can report a usable endpoint instead of a hopeful one.
fn wait_until_running(socket: Option<&str>, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ping(socket) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    ping(socket)
}

fn start_detached(bin: &Path, ipc: &Path) -> std::io::Result<()> {
    let log = baluard_core::paths::log_dir().join("daemon.log");
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    let out = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log)?
    };
    #[cfg(not(unix))]
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    let err = out.try_clone()?;
    let mut cmd = Command::new(bin);
    cmd.arg("--socket")
        .arg(ipc)
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err);
    // Own process group: the terminal's SIGHUP on close must not reach it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().map(|_| ())
}

fn serve(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if socket.is_some() {
        deny("ssh serve launches the machine daemon; drop --socket");
    }
    if ping(None) {
        println!("Daemon already running.");
        return status(None);
    }
    let ipc = ipc_socket(None);
    let bin = daemon_bin();
    if !bin.exists() {
        deny(&format!(
            "baluard-daemon not found next to the CLI (looked at {})",
            bin.display()
        ));
    }
    #[cfg(target_os = "linux")]
    let via_systemd = {
        // Distinct from the installed unit's name: systemd-run fails on a
        // loaded unit name and its stderr is muted here.
        let mut sr = Command::new("systemd-run");
        sr.args(["--user", "--unit=baluard-daemon-serve", "--collect"]);
        // A service unit starts with a clean environment, so carry the
        // overrides the caller set or the daemon lands somewhere else and
        // the readiness ping waits on the wrong socket.
        for var in ["BALUARD_SOCKET", "BALUARD_DATA_DIR", "BALUARD_LOG_DIR"] {
            if let Ok(val) = std::env::var(var) {
                sr.arg(format!("--setenv={var}={val}"));
            }
        }
        sr.arg(&bin)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|st| st.success())
            .unwrap_or(false)
    };
    #[cfg(not(target_os = "linux"))]
    let via_systemd = false;
    if !via_systemd {
        start_detached(&bin, &ipc)?;
    }
    if !wait_until_running(None, 8) {
        deny("daemon did not come up within 8s; check the daemon log");
    }
    println!(
        "Daemon started{}. Agent socket: {}",
        if via_systemd {
            " (systemd user unit baluard-daemon)"
        } else {
            ""
        },
        agent_endpoint(&ipc).display()
    );
    status(None)
}

/// The opt-in systemd user unit. Content lives in one function so the
/// test can pin what we ship. ExecStart is quoted with % and $ doubled:
/// install paths can carry spaces, and systemd would otherwise expand
/// specifiers and environment variables in them.
fn systemd_unit_content(bin: &Path) -> String {
    let exec = bin
        .to_string_lossy()
        .replace('%', "%%")
        .replace('$', "$$")
        .replace('"', "\\\"");
    format!(
        "[Unit]\n\
         Description=Baluard daemon (vault + SSH agent)\n\
         \n\
         [Service]\n\
         ExecStart=\"{exec}\"\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exec = exec
    )
}

fn systemd_user_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        });
    base.join("systemd").join("user")
}

fn install(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if socket.is_some() {
        deny("ssh install manages the machine daemon; drop --socket");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        eprintln!("ssh install is Linux (systemd) only. On this platform use: baluard ssh serve");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    {
        let unit_path = systemd_user_dir().join("baluard-daemon.service");
        let bin = daemon_bin();
        if !bin.exists() {
            deny(&format!(
                "baluard-daemon not found next to the CLI (looked at {})",
                bin.display()
            ));
        }
        let content = systemd_unit_content(&bin);
        match std::fs::read_to_string(&unit_path) {
            Ok(existing) => {
                if existing != content {
                    deny(&format!(
                        "{} already exists with different content; review it first",
                        unit_path.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = unit_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&unit_path, &content)?;
            }
            // An unreadable or non-UTF-8 unit is not ours to overwrite.
            Err(e) => {
                deny(&format!(
                    "cannot read {} ({}); remove or fix it first",
                    unit_path.display(),
                    e
                ));
            }
        }
        let already_running = ping(None);
        let reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        if !reload.success() {
            deny("systemctl --user daemon-reload failed; is systemd running for this user?");
        }
        let enable = Command::new("systemctl")
            .args(["--user", "enable"])
            .args(if already_running {
                Vec::<&str>::new()
            } else {
                vec!["--now"]
            })
            .arg("baluard-daemon.service")
            .status()?;
        if !enable.success() {
            deny(if already_running {
                "systemctl --user enable failed"
            } else {
                "systemctl --user enable --now failed"
            });
        }
        if already_running {
            println!("Daemon already running; unit installed and enabled for next boot.");
        } else if !wait_until_running(None, 10) {
            deny(
                "unit enabled but the daemon did not come up within 10s; check journalctl --user -u baluard-daemon",
            );
        } else {
            println!("Installed and started: {}", unit_path.display());
        }
        let ipc = ipc_socket(None);
        println!("Agent socket: {}", agent_endpoint(&ipc).display());
        print_setup(&agent_endpoint(&ipc));
        Ok(())
    }
}

fn uninstall(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if socket.is_some() {
        deny("ssh uninstall manages the machine daemon; drop --socket");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        eprintln!("ssh uninstall is Linux (systemd) only.");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "baluard-daemon.service"])
            .status();
        let unit_path = systemd_user_dir().join("baluard-daemon.service");
        // Only delete what we ship: the marker line identifies the unit
        // as ours, so a hand-written file at the same path survives.
        let ours = std::fs::read_to_string(&unit_path)
            .map(|c| c.contains("Description=Baluard daemon"))
            .unwrap_or(false);
        if !ours {
            if unit_path.exists() {
                deny(&format!(
                    "{} was not written by baluard; not touching it",
                    unit_path.display()
                ));
            }
            println!("No installed unit at {}.", unit_path.display());
        } else {
            match std::fs::remove_file(&unit_path) {
                Ok(()) => {
                    let _ = Command::new("systemctl")
                        .args(["--user", "daemon-reload"])
                        .status();
                    println!("Removed {}", unit_path.display());
                }
                Err(e) => return Err(e.into()),
            }
        }
        if ping(None) {
            println!(
                "A daemon is still running (started another way); it keeps serving until stopped."
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_pins_binary_and_user_target() {
        let content = systemd_unit_content(Path::new("/usr/bin/baluard-daemon"));
        assert!(content.contains("ExecStart=\"/usr/bin/baluard-daemon\""));
        assert!(content.contains("WantedBy=default.target"));
        assert!(content.contains("Restart=on-failure"));
        // No secrets in the unit: the daemon needs none to bind.
        assert!(!content.contains("token"));
        assert!(!content.to_lowercase().contains("password"));
    }

    #[test]
    fn unit_escapes_specifier_and_variable_characters() {
        // systemd would expand %n/%t specifiers and $VARS in ExecStart and
        // split on spaces; quote and double them instead.
        let content = systemd_unit_content(Path::new("/opt/my tools/baluard %n $dir"));
        assert!(content.contains("ExecStart=\"/opt/my tools/baluard %%n $$dir\""));
    }
}
