//! Daemon process lifecycle for the desktop app (D79).
//!
//! Three jobs the stock "spawn and hope" setup did not cover:
//! - Adopt-or-replace at startup: a healthy same-version daemon (possibly
//!   started by the CLI or the browser extension) is adopted instead of
//!   killed; only an unresponsive or version-mismatched daemon is replaced.
//! - A clean stop that WAITS for process exit: `update` must never replace
//!   binaries under a running daemon, and `RunEvent::Exit` must not leave
//!   the old Drop-only "SIGTERM + 200ms prayer" behavior in the update path.
//! - A respawn suppression flag so nothing restarts the daemon between
//!   "stopped for install" and "the new app version takes over" (and the
//!   rollback path clears it and brings the daemon back).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;

use crate::{default_socket_path, send_request};

/// Set while the desktop is about to stop the daemon for an update install.
/// Nothing in this crate may start a daemon while this is set; the rollback
/// path clears it before bringing the daemon back.
static RESPAWN_SUPPRESSED: AtomicBool = AtomicBool::new(false);

/// After a daemon crash mid-session the app degraded into permanent
/// "Daemon is not running" until a manual restart (2026-11-04 field
/// report): launch was the only spawn site. The request error path now
/// brings the daemon back, gated by a cooldown so the ~3s pollers
/// cannot spawn-storm while the daemon is genuinely gone.
const RESPAWN_COOLDOWN: Duration = Duration::from_secs(15);
static RESPAWN_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static LAST_RESPAWN_ATTEMPT: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);

fn respawn_permitted(
    now: Instant,
    last_attempt: Option<Instant>,
    in_flight: bool,
    cooldown: Duration,
) -> bool {
    if in_flight {
        return false;
    }
    match last_attempt {
        Some(at) => now.duration_since(at) >= cooldown,
        None => true,
    }
}

/// Called from the daemon_request error path on a socket-level connect
/// failure. Fire-and-forget: the failed request returns immediately and
/// the next poll rides the fresh daemon (whose session tokens are new,
/// so unlocked vaults surface as locked and re-unlock normally).
pub(crate) fn ensure_daemon_running(app: &AppHandle) -> bool {
    if respawn_suppressed() {
        return false;
    }
    let now = Instant::now();
    {
        let mut guard = match LAST_RESPAWN_ATTEMPT.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let in_flight = RESPAWN_IN_FLIGHT.load(Ordering::SeqCst);
        if !respawn_permitted(now, *guard, in_flight, RESPAWN_COOLDOWN) {
            return false;
        }
        if RESPAWN_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        *guard = Some(now);
    }
    let outcome = start_daemon(app);
    RESPAWN_IN_FLIGHT.store(false, Ordering::SeqCst);
    match outcome {
        Ok(()) => {
            log::info!("daemon respawned after connect failure");
            true
        }
        Err(e) => {
            log::warn!("daemon respawn failed: {e}");
            false
        }
    }
}

/// True when startup adopted an already-running daemon instead of spawning
/// one. The adopted daemon is not our child, so exit only locks its vaults
/// (via `vaults.lock_all`) and leaves the process for its original owner.
static ADOPTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn respawn_suppressed() -> bool {
    RESPAWN_SUPPRESSED.load(Ordering::SeqCst)
}

/// The daemon build version this app shipped with, injected by build.rs from
/// crates/baluard-daemon/Cargo.toml. A running daemon reporting anything
/// else is stale sidecar code and gets replaced, never trusted.
fn expected_daemon_version() -> &'static str {
    env!("BALUARD_DAEMON_VERSION")
}

/// Ping the socket and return the daemon's build version, if one answers
/// with the D79 handshake shape. `Ok(None)`-shaped: no daemon, or a
/// pre-handshake daemon (older than the handshake).
fn live_daemon_version() -> Option<String> {
    let payload = send_request("ping", "").ok()?;
    let v: serde_json::Value = serde_json::from_str(&payload).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

/// Parse the payload the desktop's ping returns into a version string.
pub(crate) fn version_from_ping_payload(payload: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

#[cfg(unix)]
fn terminate_stale_daemon() {
    // Reached only when no same-version daemon answered the ping, so this
    // can never kill a healthy CLI/NMH-started daemon — that is the whole
    // point of replacing the old unconditional pgrep sweep.
    let mut pids: Vec<i32> = Vec::new();
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-x", "baluard-daemon"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for pid in stdout.split_whitespace() {
            if let Ok(p) = pid.parse::<i32>() {
                unsafe {
                    libc::kill(p, libc::SIGTERM);
                }
                pids.push(p);
                log::info!("Stopped stale daemon pid={p}");
            }
        }
    }
    // SIGTERM should be enough (the daemon zeroizes and exits on it), but a
    // wedged daemon must not survive into the new socket's lifetime: poll,
    // then escalate. kill(pid, 0) works even for pids that are not our
    // children (no waitpid possible here).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !pids.is_empty() && std::time::Instant::now() < deadline {
        pids.retain(|p| unsafe { libc::kill(*p, 0) } == 0);
        if pids.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for p in &pids {
        unsafe {
            libc::kill(*p, libc::SIGKILL);
        }
        log::warn!("stale daemon pid={p} ignored SIGTERM; sent SIGKILL");
    }
    std::thread::sleep(Duration::from_millis(200));
}

/// Poll `waitpid` until `pid` exits, is reaped elsewhere, or the deadline
/// passes. Returns true when the process is gone. Used instead of trusting
/// a fixed sleep: the update path replaces binaries the moment this returns.
#[cfg(unix)]
fn wait_for_pid_exit(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        // pid: we reaped it. -1/EINVAL: not our child or already reaped
        // (the shell-event loop may get there first) — either way it is not
        // running our code anymore. 0: still running.
        if ret == pid
            || (ret == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Gracefully stop the daemon we spawned: SIGTERM (the daemon's handler
/// zeroizes keys and locks vaults), wait for real exit, escalate to SIGKILL.
#[cfg(unix)]
pub(crate) fn stop_daemon_and_wait(
    state: &std::sync::Mutex<Option<crate::Daemon>>,
) -> Result<(), String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    let Some(mut daemon) = guard.take() else {
        return Ok(()); // nothing we spawned is running (adopted or absent)
    };
    // Option::take, not a field move: Daemon implements Drop.
    let Some(child) = daemon.0.take() else {
        return Ok(());
    };
    let pid = child.pid() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    if wait_for_pid_exit(pid, Duration::from_secs(8)) {
        log::info!("daemon exited cleanly after SIGTERM");
        return Ok(());
    }
    log::warn!("daemon ignored SIGTERM for 8s; sending SIGKILL");
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let exited = wait_for_pid_exit(pid, Duration::from_secs(2));
    // The child is out of the Daemon wrapper, so its Drop has nothing to
    // signal; CommandChild itself has no auto-kill Drop.
    if exited {
        Ok(())
    } else {
        Err("daemon did not exit after SIGKILL".into())
    }
}

/// Windows has no SIGTERM: lock vaults over IPC first (the graceful half),
/// then TerminateProcess via CommandChild::kill and poll the pid to death.
#[cfg(not(unix))]
pub(crate) fn stop_daemon_and_wait(
    state: &std::sync::Mutex<Option<crate::Daemon>>,
) -> Result<(), String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    let Some(mut daemon) = guard.take() else {
        return Ok(()); // nothing we spawned is running (adopted or absent)
    };
    let Some(child) = daemon.0.take() else {
        return Ok(());
    };
    let pid = child.pid();
    let _ = send_request("vaults.lock_all", "");
    child.kill().map_err(|e| format!("daemon kill: {e}"))?;
    if wait_for_pid_exit(pid, Duration::from_secs(5)) {
        log::info!("daemon exited after kill");
        Ok(())
    } else {
        Err("daemon did not exit after kill".into())
    }
}

#[cfg(not(unix))]
fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };

    let deadline = Instant::now() + timeout;
    loop {
        unsafe {
            // SYNCHRONIZE (in FILE_ACCESS_RIGHTS) lets us wait on the process.
            let handle =
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, pid);
            if handle.is_null() {
                return true; // gone: no process object left to wait on
            }
            let r = WaitForSingleObject(handle, 200);
            CloseHandle(handle);
            if r == WAIT_OBJECT_0 {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
}

/// D79 exit path: an adopted daemon is not ours to kill — lock its vaults
/// over the socket so no keys outlive the app, and leave the process for
/// whoever started it. Our own daemon goes through the full wait-stop.
pub(crate) fn on_app_exit(state: &std::sync::Mutex<Option<crate::Daemon>>) {
    if ADOPTED.load(Ordering::SeqCst) {
        let _ = send_request("vaults.lock_all", "");
        return;
    }
    if let Err(e) = stop_daemon_and_wait(state) {
        log::error!("daemon stop on exit: {e}");
    }
}

/// Start (or adopt) the daemon. Shared by app setup and the update-install
/// rollback path.
pub(crate) fn start_daemon(app: &AppHandle) -> Result<(), String> {
    if respawn_suppressed() {
        return Err("daemon respawn is suppressed (update in progress)".into());
    }
    let socket = default_socket_path();

    match live_daemon_version() {
        Some(v) if v == expected_daemon_version() => {
            ADOPTED.store(true, Ordering::SeqCst);
            log::info!("Adopted running daemon (version {v})");
            return Ok(());
        }
        Some(v) => {
            log::warn!(
                "Running daemon reports version {v}, expected {}: replacing it",
                expected_daemon_version()
            );
            // Unix kills the stale process; Windows cannot kill a process
            // it may not have spawned, and the pipe dies with its owner —
            // the new daemon's create failure names the conflict instead.
            #[cfg(unix)]
            terminate_stale_daemon();
            #[cfg(not(unix))]
            log::warn!("quit the running Baluard daemon before updating");
        }
        None => {
            // No answer: either nothing is running or a hung daemon is
            // squatting on the socket path. Clear both possibilities.
            #[cfg(unix)]
            terminate_stale_daemon();
        }
    }
    ADOPTED.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    let _ = std::fs::remove_file(&socket);

    spawn_sidecar(app, &socket)?;
    wait_for_ready()
}

fn spawn_sidecar(app: &AppHandle, socket: &std::path::Path) -> Result<(), String> {
    log::info!("Starting daemon with --socket {}", socket.display());
    let sidecar_command = app
        .shell()
        .sidecar("baluard-daemon")
        .map_err(|e| format!("Sidecar not found: {e}"))?;
    let sidecar_command =
        sidecar_command.args(["--socket", socket.to_string_lossy().as_ref()]);

    // We MUST keep the stdout/stderr receiver alive — dropping it closes the
    // pipe and we lose the daemon's startup error output.
    let (mut rx, child) = sidecar_command
        .spawn()
        .map_err(|e| format!("Failed to start daemon: {e}"))?;

    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(b) => {
                    log::info!("[daemon] {}", String::from_utf8_lossy(&b).trim_end());
                }
                CommandEvent::Stderr(b) => {
                    log::warn!("[daemon] {}", String::from_utf8_lossy(&b).trim_end());
                }
                CommandEvent::Error(e) => log::error!("[daemon] {e}"),
                CommandEvent::Terminated(t) => {
                    log::warn!(
                        "[daemon] terminated code={:?} signal={:?}",
                        t.code,
                        t.signal
                    );
                    break;
                }
                _ => {}
            }
        }
    });

    let state = app.state::<std::sync::Mutex<Option<crate::Daemon>>>();
    *state.lock().unwrap() = Some(crate::Daemon(Some(child)));
    log::info!("Daemon started via sidecar");
    Ok(())
}

/// Wait for daemon readiness AND the version handshake: a daemon that
/// answers with the wrong version is stale sidecar code from before an
/// update and must fail loudly, not serve old protocol behavior.
fn wait_for_ready() -> Result<(), String> {
    for attempt in 0..50 {
        match send_request("ping", "") {
            Ok(payload) => match version_from_ping_payload(&payload) {
                Some(v) if v == expected_daemon_version() => {
                    log::info!("Daemon ready after {}ms", attempt * 100);
                    return Ok(());
                }
                Some(v) => {
                    return Err(format!(
                        "Daemon version mismatch: running {v}, expected {}. Reinstall Baluard.",
                        expected_daemon_version()
                    ));
                }
                None => {
                    return Err(
                        "Daemon did not report a version (stale sidecar?). Reinstall Baluard."
                            .into(),
                    );
                }
            },
            Err(_) => {
                if attempt == 49 {
                    return Err("Daemon failed to start within 5s. Check logs/daemon.log and logs/desktop.log for the daemon's error output.".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    unreachable!("loop returns on every branch")
}

/// Update-rollback: bring a daemon back after a failed install. Clears the
/// suppression flag first — start_daemon refuses while it is set.
pub(crate) fn restart_daemon(app: &AppHandle) -> Result<(), String> {
    RESPAWN_SUPPRESSED.store(false, Ordering::SeqCst);
    start_daemon(app)
}

/// Lift the respawn gate without spawning anything: used when an update
/// fails before the daemon is gone, so normal lifecycle rules keep applying.
pub(crate) fn clear_respawn_suppression() {
    RESPAWN_SUPPRESSED.store(false, Ordering::SeqCst);
}

/// Suppress daemon respawn ahead of stopping it for an install. Cleared by
/// `restart_daemon` (rollback) or the new app version's normal startup.
pub(crate) fn suppress_respawn() {
    RESPAWN_SUPPRESSED.store(true, Ordering::SeqCst);
}

/// Whether startup adopted an already-running daemon instead of spawning
/// one; update rollback must not kill a daemon owned by a CLI session.
pub(crate) fn daemon_is_adopted() -> bool {
    ADOPTED.load(Ordering::SeqCst)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn wait_for_pid_exit_detects_a_terminated_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        assert!(wait_for_pid_exit(pid, Duration::from_secs(5)));
        let _ = child.wait();
    }

    #[test]
    fn wait_for_pid_exit_times_out_on_a_live_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        assert!(!wait_for_pid_exit(pid, Duration::from_millis(250)));
        child.kill().expect("kill sleep");
        let _ = child.wait();
    }

    #[test]
    fn version_from_ping_payload_reads_the_handshake_shape() {
        let payload = serde_json::json!({"version": "0.1.0", "proto_version": 1}).to_string();
        assert_eq!(
            version_from_ping_payload(&payload).as_deref(),
            Some("0.1.0")
        );
        assert_eq!(version_from_ping_payload("pong"), None);
        assert_eq!(version_from_ping_payload("not json"), None);
    }

    #[test]
    fn first_respawn_failure_is_permitted() {
        assert!(respawn_permitted(Instant::now(), None, false, RESPAWN_COOLDOWN));
    }

    #[test]
    fn a_recent_attempt_blocks_the_next() {
        assert!(!respawn_permitted(
            Instant::now(),
            Some(Instant::now() - Duration::from_secs(1)),
            false,
            RESPAWN_COOLDOWN
        ));
    }

    #[test]
    fn the_cooldown_expires() {
        assert!(respawn_permitted(
            Instant::now(),
            Some(Instant::now() - Duration::from_secs(RESPAWN_COOLDOWN.as_secs() + 1)),
            false,
            RESPAWN_COOLDOWN
        ));
    }

    #[test]
    fn an_in_flight_attempt_blocks_new_ones_even_when_cold() {
        assert!(!respawn_permitted(Instant::now(), None, true, RESPAWN_COOLDOWN));
    }
}
