//! E2E harness for Phase 1 (CLI + daemon).
//!
//! Distinct from the direct-mode suites in `tests/*.rs`: every flow here
//! spawns the real `baluard-daemon` binary on a scratch socket with its own
//! `BALUARD_DATA_DIR`, then drives the real `baluard` binary in its default
//! daemon-first mode. Nothing is mocked; assertions read process exit codes
//! and stdout.
//!
//! Run via `just test-e2e` (builds the daemon with the e2e-hooks feature and
//! sets BALUARD_E2E=1). Specs that need feature-gated behavior skip loudly
//! when run outside that recipe, so a plain `cargo test` stays green.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command as CliCommand;
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test-passw0rd-12chars";

/// A running daemon bound to a scratch socket, killed on drop.
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    _tmp: TempDir,
}

impl DaemonGuard {
    fn vault(&self) -> PathBuf {
        self._tmp.path().join("vault")
    }

    fn path(&self) -> &Path {
        self._tmp.path()
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resolve the daemon binary the way `just test-e2e` builds it: workspace
/// target dir next to this crate's manifest.
fn daemon_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("target/debug/baluard-daemon");
    assert!(
        p.exists(),
        "baluard-daemon binary not found at {} - run `just test-e2e`",
        p.display()
    );
    p
}

/// Create a vault in direct mode via `init --json` (E9) and return the parsed
/// output (vault_id, recovery_phrase, path, slug).
fn init_vault_json(tmp: &TempDir, slug: &str) -> serde_json::Value {
    let out = baluard_direct(&tmp.path().join("vault"), tmp)
        .arg("init")
        .arg("--name")
        .arg("E2E Vault")
        .arg("--slug")
        .arg(slug)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    // init prints a couple of human progress lines first; the JSON object is
    // its own line (scripts take the last/only { line).
    let json_line = text
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("init --json prints a JSON object line");
    let v: serde_json::Value = serde_json::from_str(json_line).expect("valid init JSON");
    assert_eq!(v["slug"], slug, "init --json echoes the slug");
    assert_eq!(
        v["recovery_phrase"]
            .as_str()
            .expect("phrase")
            .split_whitespace()
            .count(),
        24,
        "recovery phrase is 24 words"
    );
    v
}

fn baluard_direct(vault_path: &Path, tmp: &TempDir) -> CliCommand {
    let mut cmd = base_cmd(tmp);
    cmd.arg("--direct").arg("--vault-path").arg(vault_path);
    cmd
}

/// CLI in daemon-first mode against the scratch socket. BALUARD_PASSWORD
/// rides on every invocation so the E2 shared helper resolves unlocks.
fn baluard_daemon(guard: &DaemonGuard) -> CliCommand {
    let mut cmd = base_cmd(&guard._tmp);
    cmd.arg("--socket").arg(&guard.socket);
    cmd
}

/// Shared environment scrubbing for every spawned binary (E11): fresh data
/// dir, keyring off, prompts resolved from BALUARD_PASSWORD, autosync off
/// (E10) so explicit sync commands never race a background push.
fn base_cmd(tmp: &TempDir) -> CliCommand {
    let mut cmd = CliCommand::cargo_bin("baluard").expect("baluard binary not found");
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD)
        .env("BALUARD_DATA_DIR", tmp.path().join("data"))
        .env("BALUARD_DISABLE_KEYRING", "1")
        .env("BALUARD_NO_PROMPT", "1")
        .env("BALUARD_AUTOSYNC", "0")
        .current_dir(tmp.path())
        .env_remove("BALUARD_SOCKET");
    cmd
}

/// Spawn the daemon on a socket inside `tmp` and wait for it to accept
/// connections. Takes ownership of `tmp` so daemon, CLI, and vault share one
/// lifetime. The guard is built before the wait loop: a timeout or an early
/// daemon crash drops the guard, which kills the child (no orphans).
fn spawn_daemon(tmp: TempDir) -> DaemonGuard {
    spawn_daemon_with(tmp, None)
}

/// `home` redirects $HOME for the daemon so $HOME/.ssh/known_hosts lands in
/// a scratch dir (the SSH hostkey-trust flow must not touch the runner's
/// real file).
fn spawn_daemon_with(tmp: TempDir, home: Option<&std::path::Path>) -> DaemonGuard {
    let vault = tmp.path().join("vault");
    let socket = tmp.path().join("d.sock");
    std::fs::create_dir_all(tmp.path().join("data")).expect("data dir");
    let mut cmd = Command::new(daemon_bin());
    cmd.arg("--socket")
        .arg(&socket)
        .arg("--vault-path")
        .arg(&vault)
        .env("BALUARD_DATA_DIR", tmp.path().join("data"))
        .env("BALUARD_DISABLE_KEYRING", "1")
        .env("BALUARD_AUTOSYNC", "0")
        // Kernel kills the daemon if this test process dies first.
        .env("BALUARD_DAEMON_DIE_WITH_PARENT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(tmp.path());
    if let Some(home) = home {
        cmd.env("HOME", home);
    }
    let child = cmd.spawn().expect("spawn baluard-daemon");

    let mut guard = DaemonGuard {
        child,
        socket,
        _tmp: tmp,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // bind() creates the socket file before the listener serves; a real
        // connect is the readiness signal.
        if std::os::unix::net::UnixStream::connect(&guard.socket).is_ok() {
            return guard;
        }
        if let Ok(Some(status)) = guard.child.try_wait() {
            panic!("daemon exited early with {status}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not accept connections in 10s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// First whitespace token on the row mentioning `name`. Both list rows
/// (`{fav} {id}  [{type}]  {name}`) and trash rows (`{id}  [{type}]  {name}`)
/// carry the id as token 0; the empty favorite renders as a leading space.
fn row_id(stdout: &[u8], name: &str) -> String {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no row for {name} in:\n{text}"))
        .to_string()
}

// ── Flows ──

/// init --json (E9) -> daemon spawn -> unlock -> lock, all through the real
/// binaries and the real socket.
#[test]
fn e2e_init_unlock_lock_roundtrip() {
    let tmp = TempDir::new().expect("tmp");
    let created = init_vault_json(&tmp, "baluard-e2e-a");
    let guard = spawn_daemon(tmp);

    baluard_daemon(&guard)
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault unlocked (daemon)."));

    baluard_daemon(&guard)
        .arg("lock")
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault locked."));

    // Lock must actually end the session: reads after it fail.
    baluard_daemon(&guard).arg("list").assert().failure();

    // The init phrase is real enrollment material for multi-device flows.
    assert!(created["recovery_phrase"].as_str().unwrap().len() > 100);
    assert!(guard.vault().join(".baluard").exists(), "vault marker");
}

/// Cipher CRUD entirely in daemon mode: add, list, get, rename, delete.
#[test]
fn e2e_cipher_crud_via_daemon() {
    let tmp = TempDir::new().expect("tmp");
    init_vault_json(&tmp, "baluard-e2e-b");
    let guard = spawn_daemon(tmp);

    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "Bank",
            "--username",
            "me",
            "--password",
            "s3cret!pw",
        ])
        .assert()
        .success();

    let list_out = baluard_daemon(&guard)
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains("Bank"))
        .get_output()
        .stdout
        .clone();
    let id = row_id(&list_out, "Bank");

    // Daemon-mode get has no name lookup; use the UUID. Default get masks
    // the secret; --decrypt reveals it.
    baluard_daemon(&guard)
        .args(["get", &id])
        .assert()
        .success()
        .stdout(predicates::str::contains("s3cret!pw").not());
    baluard_daemon(&guard)
        .args(["get", &id, "--decrypt", "--output=text"])
        .assert()
        .success()
        .stdout(predicates::str::contains("s3cret!pw"));

    // CLI edit has no password knob; rename via --name.
    baluard_daemon(&guard)
        .args(["edit", &id, "--name", "BankRenamed"])
        .assert()
        .success();

    baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("BankRenamed"));

    baluard_daemon(&guard)
        .args(["delete", &id])
        .assert()
        .success();

    baluard_daemon(&guard)
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains("BankRenamed").not());
}

/// Trash surface (G14): delete lands in trash, restore brings it back,
/// purge --days 0 empties everything.
#[test]
fn e2e_trash_roundtrip() {
    let tmp = TempDir::new().expect("tmp");
    init_vault_json(&tmp, "baluard-e2e-c");
    let guard = spawn_daemon(tmp);

    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "TrashMe",
            "--username",
            "u",
            "--password",
            "pw123456",
        ])
        .assert()
        .success();
    let list_out = baluard_daemon(&guard)
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let id = row_id(&list_out, "TrashMe");
    baluard_daemon(&guard)
        .args(["delete", &id])
        .assert()
        .success();

    let trash_out = baluard_daemon(&guard)
        .args(["trash", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TrashMe"))
        .get_output()
        .stdout
        .clone();
    let trash_id = row_id(&trash_out, "TrashMe");

    baluard_daemon(&guard)
        .args(["trash", "restore", &trash_id])
        .assert()
        .success();

    baluard_daemon(&guard)
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains("TrashMe"));

    baluard_daemon(&guard)
        .args(["delete", &id])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["trash", "purge", "--days", "0"])
        .assert()
        .success()
        .stdout(predicates::str::contains("entire trash"));
    baluard_daemon(&guard)
        .args(["trash", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TrashMe").not());
}

/// Space knobs over the socket (G1): set then read back through the daemon.
#[test]
fn e2e_space_settings_set_get() {
    let tmp = TempDir::new().expect("tmp");
    init_vault_json(&tmp, "baluard-e2e-d");
    let guard = spawn_daemon(tmp);

    baluard_daemon(&guard)
        .args(["settings", "space-set", "guest_enabled=true"])
        .assert()
        .success();

    baluard_daemon(&guard)
        .args(["settings", "space-get"])
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""guest_enabled":true"#));

    // The CLI validates the value vocabulary before any round trip.
    baluard_daemon(&guard)
        .args(["settings", "space-set", "quorum_admin_ops=9"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("between 1 and 5"));
}

/// G11 phase 2: the full CLI org-admin surface against a family vault.
/// Groups, policies, space lifecycle/kit, the D61 claim surface, the
/// leave journey, member bookkeeping, activity, and the destructive
/// gate (no --yes refuses in non-interactive runs).
#[test]
fn e2e_cli_org_admin_surface() {
    let guard = spawn_daemon(TempDir::new().expect("tmp"));

    // Family vault (kit auto-enabled, Shared collection, Guardians group).
    baluard_daemon(&guard)
        .args([
            "init",
            "--name",
            "Admin Surface",
            "--slug",
            "baluard-adminsurf",
            "--family",
            "--json",
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-adminsurf"])
        .assert()
        .success();
    baluard_daemon(&guard).args(["unlock"]).assert().success();

    // Groups: create, list, member add, rename.
    let create_out = baluard_daemon(&guard)
        .args(["groups", "create", "Sitters"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let create_text = String::from_utf8(create_out).expect("utf8");
    let sitters_id = create_text
        .lines()
        .find(|l| l.contains("Group created:"))
        .and_then(|l| l.split("Group created: ").nth(1))
        .map(|s| s.trim_end_matches('.').to_string())
        .expect("group id from create output");
    baluard_daemon(&guard)
        .args(["groups", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Guardians"))
        .stdout(predicates::str::contains("Sitters"));

    // Policies: set + read back.
    // Policies mirror the space-knob vocabulary (validate_value is the
    // same table space-settings uses).
    baluard_daemon(&guard)
        .args(["policies", "set", r#"{"join_approval":"code"}"#])
        .assert()
        .success()
        .stdout(predicates::str::contains("Policies updated."));
    baluard_daemon(&guard)
        .args(["policies", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("join_approval"));
    baluard_daemon(&guard)
        .args(["policies", "set", r#"{"bogus_key":1}"#])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not a policy"));

    // Member bookkeeping: set-email shows in the roster; the owner row
    // refuses the minor flag; a bogus id refuses loudly.
    let out = baluard_daemon(&guard)
        .args(["members", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    let self_id = text
        .lines()
        .find(|l| l.starts_with('*'))
        .expect("self row")
        .split_whitespace()
        .nth(1)
        .expect("member id token")
        .to_string();
    baluard_daemon(&guard)
        .args([
            "members",
            "set-email",
            &self_id,
            "--email",
            "owner@e2e.test",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Email updated."));
    baluard_daemon(&guard)
        .args(["members", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("owner@e2e.test"));
    baluard_daemon(&guard)
        .args(["members", "set-minor", &self_id, "--minor"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be flagged"));
    baluard_daemon(&guard)
        .args([
            "members",
            "set-minor",
            "00000000-0000-0000-0000-000000000000",
            "--minor",
        ])
        .assert()
        .failure();

    // D61 claim surface: nothing pending; the owner row refuses a
    // self-departure until ownership moves.
    baluard_daemon(&guard)
        .args(["members", "contest-status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("No ownership claim is pending."));
    baluard_daemon(&guard)
        .args(["members", "leave"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("transfer ownership"));

    // Space lifecycle: family creation leaves the kit enabled and the
    // vault flipped.
    baluard_daemon(&guard)
        .args(["space", "kit-status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("enabled."));
    baluard_daemon(&guard)
        .args(["space", "status"])
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""flipped":true"#));

    // Destructive gate: no --yes in a non-interactive run refuses
    // before any request is sent.
    baluard_daemon(&guard)
        .args(["members", "reset", &self_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing without confirmation"));

    // Activity: the timeline endpoint answers with rows or an empty list.
    baluard_daemon(&guard)
        .args(["activity", "--limit", "5"])
        .assert()
        .success();

    // Destructive executions on a fixture member (minimal live Editor
    // row per the G26 recipe). Reset with --yes issues a code; the
    // member leaves and the admin approves the departure; a re-invited
    // style row is removed with --yes. set-email --clear rounds out
    // the email surface.
    let member_id = "11111111-2222-3333-4444-555555555555";
    let member_path = guard
        .path()
        .join("data")
        .join("vaults")
        .join("baluard-adminsurf")
        .join("meta")
        .join("members")
        .join(format!("{member_id}.json"));
    std::fs::create_dir_all(member_path.parent().unwrap()).expect("members dir");
    std::fs::write(
        &member_path,
        format!(
            r#"{{"id":"{member_id}","display_name":"Fixture Member","role":"editor","trust":"channel"}}"#
        ),
    )
    .expect("write member row");

    baluard_daemon(&guard)
        .args(["members", "reset", member_id, "--yes"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Member reset. Successor row:"))
        .stdout(predicates::str::contains("Reset code"));
    // The fixture row is now tombstoned; removal of a reset row refuses.
    baluard_daemon(&guard)
        .args(["members", "remove", member_id, "--yes"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already tombstoned"));

    // A live row: removal executes the full ceremony.
    let member2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    // Group keys wrap to the member's share key, so the fixture row
    // needs the identity wrap/signing keys; the founder row carries a
    // usable pair to copy.
    let founder_row: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            guard
                .path()
                .join("data")
                .join("vaults")
                .join("baluard-adminsurf")
                .join("meta")
                .join("members")
                .join(format!("{self_id}.json")),
        )
        .expect("read founder row"),
    )
    .expect("parse founder row");
    let identity_keys = format!(
        r#","identity_signing_pubkey":"{}","identity_wrap_pubkey":"{}""#,
        founder_row["identity_signing_pubkey"]
            .as_str()
            .unwrap_or(""),
        founder_row["identity_wrap_pubkey"].as_str().unwrap_or("")
    );
    let member2_row = |name: &str| {
        format!(
            r#"{{"id":"{member2}","display_name":"{name}","role":"viewer","trust":"channel"{identity_keys}}}"#
        )
    };
    std::fs::write(
        guard
            .path()
            .join("data")
            .join("vaults")
            .join("baluard-adminsurf")
            .join("meta")
            .join("members")
            .join(format!("{member2}.json")),
        member2_row("Fixture Two"),
    )
    .expect("write member row 2");
    baluard_daemon(&guard)
        .args(["groups", "add-member", &sitters_id, member2])
        .assert()
        .success()
        .stdout(predicates::str::contains("Member added"));
    baluard_daemon(&guard)
        .args(["groups", "rename", &sitters_id, "Sitters2"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Group renamed."));
    baluard_daemon(&guard)
        .args(["groups", "delete", &sitters_id, "--yes"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Group deleted."));
    baluard_daemon(&guard)
        .args(["groups", "delete", &sitters_id, "--yes"])
        .assert()
        .failure();
    baluard_daemon(&guard)
        .args(["members", "remove", member2, "--yes"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Removed 1 member(s)."));

    // set-email --clear clears the owner's address.
    baluard_daemon(&guard)
        .args(["members", "set-email", &self_id, "--clear"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Email cleared."));
    baluard_daemon(&guard)
        .args(["members", "set-email", &self_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("pass --email"));

    // Leave journey: the fixture re-joins (fresh row), files a
    // departure, and the admin approves it with --yes.
    std::fs::write(
        guard
            .path()
            .join("data")
            .join("vaults")
            .join("baluard-adminsurf")
            .join("meta")
            .join("members")
            .join(format!("{member2}.json")),
        member2_row("Fixture Two"),
    )
    .expect("rewrite member row 2");
    baluard_daemon(&guard)
        .args(["members", "leaves"])
        .assert()
        .success()
        .stdout(predicates::str::contains("No pending departures."));
    let leave_dir = guard
        .path()
        .join("data")
        .join("vaults")
        .join("baluard-adminsurf")
        .join("meta")
        .join("members")
        .join(member2)
        .join("leave.json");
    std::fs::create_dir_all(leave_dir.parent().unwrap()).expect("leave dir");
    std::fs::write(
        &leave_dir,
        r#"{"format":"baluard.leave.v1","requested_at":1}"#,
    )
    .expect("write leave record");
    baluard_daemon(&guard)
        .args(["members", "leaves"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Fixture Two"));
    baluard_daemon(&guard)
        .args(["members", "approve-leave", member2, "--yes"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Departure executed"))
        .stdout(predicates::str::contains("Collections rotated: 0."));
}

/// Parse daemon-mode `init --json`: the JSON object is its own stdout line
/// after human progress lines.
fn daemon_init_json(guard: &DaemonGuard, slug: &str) -> serde_json::Value {
    let out = baluard_daemon(guard)
        .args(["init", "--name", "Multi Device", "--slug", slug, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    let json_line = text
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("init --json prints a JSON object line");
    let v: serde_json::Value = serde_json::from_str(json_line).expect("valid init JSON");
    assert_eq!(v["slug"], slug, "init --json echoes the slug");
    v
}

/// Multi-device join over a file:// bare remote (the e2e-hooks transport).
///
/// Device A creates + pushes. Device B clones (the clone verifies A's full
/// signed history — P2), phrase-enrolls while STILL LOCKED (a fresh clone
/// has no device key, so the host-level enrollment route is the only way
/// in), unlocks with the master password, adds an entry, and signs its own
/// commit.
///
/// Pinned boundary: device A's pull REFUSES B's commit ("commit signature
/// verification failed"). Rosters resolve from each commit's first-parent
/// tree, and B's key only exists in B's own tree — no mechanism yet
/// propagates a phrase-enrollment to the other devices' verified history.
/// Multi-device join: B phrase-enrolls the LOCKED clone (chicken-and-egg
/// regression guard), signs its first commit, and — via the self-proving
/// enrollment proof (meta/enrollments/<device_id>.proof, Root-Key-derived
/// signature) — A's pull accepts the commit that its first-parent roster
/// cannot yet vouch for. The old refusal boundary flipped deliberately
/// when enrollment propagation shipped.
// ── Custom-remote HTTPS fixture: a real TLS + basic-auth git server ──

struct GitServerGuard {
    child: std::process::Child,
    port: u16,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

impl Drop for GitServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct SshServerGuard {
    child: std::process::Child,
    dir: tempfile::TempDir,
}

impl Drop for SshServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A user-mode sshd on loopback serving one bare repo. sshd cannot switch
/// users without root, so sessions run as the invoking user; the URL carries
/// that username explicitly. Returns (guard, url, client key path).
fn spawn_ssh_server() -> (SshServerGuard, String, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("ssh server tmp");
    for name in ["hostkey", "clientkey"] {
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(dir.path().join(name))
            .status()
            .expect("ssh-keygen must be on PATH");
        assert!(ok.success(), "{name} generation failed");
    }
    std::fs::copy(
        dir.path().join("clientkey.pub"),
        dir.path().join("authorized_keys"),
    )
    .expect("pub key copy");

    let repo = dir.path().join("repo.git");
    let ok = std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&repo)
        .status()
        .expect("git must be on PATH");
    assert!(ok.success(), "bare repo init failed");

    // Parallel flows in one test binary share the pid-derived base, so each
    // server takes its own slot in the band.
    static SSH_PORT_SEQ: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    let seq = SSH_PORT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let port = 21000 + ((std::process::id() as u16) % 7000) + (seq as u16 % 10) * 100;
    std::fs::write(
        dir.path().join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nStrictModes no\nLogLevel QUIET\n",
            dir.path().join("hostkey").display(),
            dir.path().join("authorized_keys").display(),
            dir.path().join("sshd.pid").display(),
        ),
    )
    .expect("sshd config write");

    let child = std::process::Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(dir.path().join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("/usr/sbin/sshd must exist");
    let mut up = false;
    for _ in 0..40 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(up, "sshd never listened on {port}");

    let user = std::env::var("USER").unwrap_or_else(|_| {
        String::from_utf8(
            std::process::Command::new("id")
                .arg("-un")
                .output()
                .expect("id")
                .stdout,
        )
        .expect("utf8")
        .trim()
        .to_string()
    });
    let url = format!("ssh://{user}@127.0.0.1:{port}{}", repo.display());
    let client_key = dir.path().join("clientkey");
    (SshServerGuard { child, dir }, url, client_key)
}

/// The SSH trust lifecycle against a live sshd: untrusted-host probe names
/// the fingerprint and the trust command, trusting by attempt id writes the
/// host entry, and a key-authenticated push/pull completes the journey.
#[test]
fn e2e_ssh_custom_remote_trust_push() {
    let (server, url, client_key) = spawn_ssh_server();
    let tmp = tempfile::tempdir().expect("tmp");
    let home = tempfile::tempdir().expect("home tmp");
    let guard = spawn_daemon_with(tmp, Some(home.path()));
    let home_path = home.path().to_path_buf();

    // Base CLI env plus the scratch HOME (known_hosts must not touch the
    // runner's real ~/.ssh).
    let mut cmd = |args: &[&str]| {
        baluard_daemon(&guard)
            .env("HOME", &home_path)
            .args(args)
            .output()
            .expect("run baluard")
    };

    std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(guard._tmp.path().join("vault"))
        .status()
        .expect("git init");

    let out = cmd(&["init", "--slug", "ssht", "--json"]);
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = cmd(&["vaults", "switch", "baluard-ssht"]);
    assert!(
        out.status.success(),
        "switch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = cmd(&["unlock"]);
    assert!(
        out.status.success(),
        "unlock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 1) First contact is refused with the fingerprint + trust command.
    let url_for_probe = url.clone();
    let out = baluard_daemon(&guard)
        .env("HOME", &home_path)
        .args(["git-probe", &url_for_probe, "--key-file"])
        .arg(&client_key)
        .output()
        .expect("probe");
    let probe_out = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "probe should fail untrusted: {probe_out}"
    );
    assert!(
        probe_out.contains("Fingerprint: SHA256:"),
        "no fingerprint: {probe_out}"
    );
    let aid: String = probe_out
        .split("git-trust ")
        .nth(1)
        .map(|rest| rest.trim().to_string())
        .expect("trust command printed");
    assert!(!aid.is_empty(), "empty attempt id");

    // 2) Trusting the observed key succeeds and names the host.
    let out = cmd(&["git-trust", &aid]);
    let trust_out = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "trust failed: {trust_out}");
    assert!(
        trust_out.contains("Host key trusted: 127.0.0.1"),
        "{trust_out}"
    );

    // 3) The trusted host accepts the key: store credentials, wire the
    // remote, push, pull.
    let out = baluard_daemon(&guard)
        .env("HOME", &home_path)
        .args(["credentials", "set", "--host", "127.0.0.1", "--key-file"])
        .arg(&client_key)
        .output()
        .expect("credentials set");
    assert!(
        out.status.success(),
        "credentials set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = cmd(&["sync", "remote", &url]);
    assert!(
        out.status.success(),
        "sync remote failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = cmd(&["sync", "push"]);
    assert!(
        out.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("pushed to origin"),
        "no push confirmation"
    );

    let out = cmd(&["sync", "pull"]);
    assert!(
        out.status.success(),
        "pull failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 4) The trust entry landed in the scratch HOME, never the runner's.
    let kh =
        std::fs::read_to_string(home.path().join(".ssh/known_hosts")).expect("known_hosts written");
    assert!(kh.contains("127.0.0.1"), "{kh}");
}

/// The MITM half of the trust lifecycle: after a trusted journey, the
/// operator regenerates the host key and sshd reloads it. The next probe
/// must refuse as host-changed, offer NO attempt id (a changed key can
/// never be blessed one-click), and the trust route must still refuse a
/// stale id.
#[test]
fn e2e_ssh_changed_hostkey_refused() {
    let (mut server, url, _client_key) = spawn_ssh_server();
    let tmp = tempfile::tempdir().expect("tmp");
    let home = tempfile::tempdir().expect("home tmp");
    let guard = spawn_daemon_with(tmp, Some(home.path()));
    let home_path = home.path().to_path_buf();

    let mut cmd = |args: &[&str]| {
        baluard_daemon(&guard)
            .env("HOME", &home_path)
            .args(args)
            .output()
            .expect("run baluard")
    };

    std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(guard._tmp.path().join("vault"))
        .status()
        .expect("git init");
    let out = cmd(&["init", "--slug", "sshk", "--json"]);
    assert!(out.status.success(), "init failed");
    let out = cmd(&["vaults", "switch", "baluard-sshk"]);
    assert!(out.status.success(), "switch failed");
    let out = cmd(&["unlock"]);
    assert!(out.status.success(), "unlock failed");

    // Trusted first contact, exactly as the happy-path flow proves it.
    let out = baluard_daemon(&guard)
        .env("HOME", &home_path)
        .args(["git-probe", &url, "--key-file"])
        .arg(&_client_key)
        .output()
        .expect("probe");
    let probe_out = String::from_utf8_lossy(&out.stdout);
    let aid: String = probe_out
        .split("git-trust ")
        .nth(1)
        .map(|rest| rest.trim().to_string())
        .expect("trust command printed");
    let out = cmd(&["git-trust", &aid]);
    assert!(out.status.success(), "trust failed");

    // The operator rotates the host key; sshd reloads it in place.
    let port: u16 = url
        .split("127.0.0.1:")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|p| p.parse().ok())
        .expect("port in url");
    let _ = server.child.kill();
    let _ = server.child.wait();
    // ssh-keygen prompts on an existing file, which would hang the flow.
    let _ = std::fs::remove_file(server.dir.path().join("hostkey"));
    let _ = std::fs::remove_file(server.dir.path().join("hostkey.pub"));
    let ok = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(server.dir.path().join("hostkey"))
        .status()
        .expect("ssh-keygen");
    assert!(ok.success(), "host key regeneration failed");
    server.child = std::process::Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(server.dir.path().join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sshd restart");
    let mut up = false;
    for _ in 0..40 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(up, "sshd never came back on {port}");

    // The probe now refuses as host-changed and offers NO trust command.
    let out = baluard_daemon(&guard)
        .env("HOME", &home_path)
        .args(["git-probe", &url, "--key-file"])
        .arg(&_client_key)
        .output()
        .expect("probe after rotation");
    let rotated = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "probe must fail after rotation: {rotated}"
    );
    assert!(
        rotated.contains("host key changed"),
        "expected the changed-key message: {rotated}"
    );
    assert!(
        !rotated.contains("git-trust"),
        "a changed key must offer no trust command: {rotated}"
    );
    assert!(
        !rotated.contains("git-trust "),
        "a changed key must never offer one-click trust: {rotated}"
    );

    // Sync is refused with the same signal.
    let out = cmd(&["sync", "push"]);
    assert!(!out.status.success(), "push must fail after rotation");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("changed"),
        "expected changed-key refusal: {err}"
    );

    // And a stale/bogus id still refuses with the usual message.
    let out = cmd(&["git-trust", "deadbeefdeadbeefdeadbeefdeadbeef"]);
    assert!(!out.status.success(), "stale trust must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no pending host-key request"),
        "expected the stale-id refusal: {err}"
    );
}

/// Spawn the python HTTPS git server (e2e/git-server/http-git-server.py)
/// with a throwaway CA-trusted cert for 127.0.0.1 and one bare repo.
/// Returns the server plus the repo URL and credentials.
fn spawn_git_server() -> (GitServerGuard, String, &'static str, &'static str) {
    let dir = tempfile::tempdir().expect("git server tmp");
    let repos = dir.path().join("repos");
    std::fs::create_dir_all(&repos).expect("repos dir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ok = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"])
        .args(["-addext", "subjectAltName=IP:127.0.0.1"])
        .status()
        .expect("openssl must be on PATH");
    assert!(ok.success(), "cert generation failed");

    let repo = repos.join("custom.git");
    let ok = std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&repo)
        .status()
        .expect("git must be on PATH");
    assert!(ok.success(), "bare repo init failed");

    // A fixed high port keeps the flow deterministic; a busy port fails
    // loudly rather than silently skipping coverage.
    let port = 24000 + (std::process::id() % 20000) as u16;
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../e2e/git-server/http-git-server.py");
    let child = std::process::Command::new("python3")
        .arg(&script)
        .args(["--port", &port.to_string()])
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--repos")
        .arg(&repos)
        .args(["--user", "alex", "--pass", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("python3 must be on PATH");
    std::thread::sleep(Duration::from_millis(1200));
    let url = format!("https://127.0.0.1:{port}/custom.git");
    (GitServerGuard { child, port, dir }, url, "alex", "secret")
}

#[test]
fn e2e_custom_remote_https_push_pull() {
    let (server, url, user, pass) = spawn_git_server();
    let _ = (&server.port, user, pass);

    // The daemon must trust the server's throwaway CA: point OpenSSL's
    // per-process roots at it before the daemon spawns (libgit2 inherits
    // OpenSSL's env). Process-wide is safe: no other e2e flow speaks TLS.
    // SAFETY: single-threaded test start; the env is process-global TLS
    // config for children spawned by this test.
    let cert_path = server_dir_cert(&server);
    unsafe {
        std::env::set_var("SSL_CERT_FILE", &cert_path);
    }

    let tmp = tempfile::tempdir().expect("tmp");
    let guard = spawn_daemon(tmp);
    baluard_daemon(&guard)
        .args([
            "init",
            "--name",
            "Custom E2E",
            "--slug",
            "baluard-e2e-cr",
            "--json",
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-e2e-cr"])
        .assert()
        .success();
    baluard_daemon(&guard).arg("unlock").assert().success();

    // Store host-bound credentials, wire the custom remote, push and pull.
    baluard_daemon(&guard)
        .args([
            "credentials",
            "set",
            "--host",
            "127.0.0.1",
            "--token",
            pass,
            "--username",
            user,
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "remote", &url])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "push"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    baluard_daemon(&guard)
        .args(["sync", "pull"])
        .assert()
        .success();

    // The probe with candidate credentials reports a healthy connection.
    let probe = baluard_daemon(&guard)
        .args(["git-probe", &url, "--token", pass, "--username", user])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(String::from_utf8(probe).unwrap().contains("Connection OK"));

    // Probe with a wrong token is refused by the server.
    baluard_daemon(&guard)
        .args(["git-probe", &url, "--token", "wrong", "--username", user])
        .assert()
        .failure();

    // The credential file is device-local and host-bound on disk.
    let cred_file = guard
        ._tmp
        .path()
        .join("data/vaults/baluard-e2e-cr/meta/git-credentials.json");
    let raw = std::fs::read_to_string(&cred_file).expect("credential file exists");
    assert!(raw.contains("\"host\":\"127.0.0.1\""));
}

/// The throwaway CA the server was started with (OpenSSL trust root).
fn server_dir_cert(server: &GitServerGuard) -> std::path::PathBuf {
    server.dir.path().join("cert.pem")
}

#[test]
fn e2e_multi_device_join_and_sync() {
    let guard = spawn_daemon(tempfile::Builder::new().prefix("e2emd").tempdir().unwrap());
    let pw = TEST_PASSWORD;

    // Bare remote for the file:// transport.
    let remote = guard.path().join("remote.git");
    let st = Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .expect("git must be on PATH (vault creation shells out to git)");
    assert!(st.success(), "git init --bare failed");
    let remote_url = format!("file://{}", remote.display());

    // ── Device A: create, unlock, publish ──
    let a = daemon_init_json(&guard, "baluard-deva");
    let phrase = a["recovery_phrase"].as_str().expect("phrase").to_string();
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-deva"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["unlock"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault unlocked (daemon)."));
    baluard_daemon(&guard)
        .args(["sync", "remote", &remote_url])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "push"])
        .assert()
        .success()
        .stdout(predicates::str::contains("pushed"));

    // ── Device B: clone, enroll (locked), unlock ──
    baluard_daemon(&guard)
        .args(["sync", "clone-url", &remote_url, "--slug", "baluard-devb"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Cloned vault 'baluard-devb'"));
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-devb"])
        .assert()
        .success();
    // Enrollment MUST work on the locked clone: unlocking is impossible
    // until a device key exists (chicken-and-egg regression guard).
    baluard_daemon(&guard)
        .args([
            "devices",
            "enroll-with-phrase",
            "--phrase",
            &phrase,
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Device enrolled"));
    baluard_daemon(&guard)
        .args(["unlock"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault unlocked (daemon)."));

    // ── Device B: write and sign its own commit ──
    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "FromDeviceB",
            "--username",
            "bob",
            "--password",
            &format!("{pw}-b"),
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "push"])
        .assert()
        .success();

    // ── Propagation: A accepts B's self-proving first commit ──
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-deva"])
        .assert()
        .success();
    // Each CLI process starts tokenless; the switch back needs a fresh
    // unlock before sync routes accept the session.
    baluard_daemon(&guard).args(["unlock"]).assert().success();
    baluard_daemon(&guard)
        .args(["sync", "pull"])
        .assert()
        .success();
    // The enrollment proof carried B's entry into A's verified history.
    baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("FromDeviceB"));
}

/// Enrollment-proof forgery: a proof whose signature does not verify under
/// the Root-Key-derived key must not smuggle an unknown signer past A's
/// pull verification. Tamper B's proof file BEFORE B commits, so the
/// forged proof rides B's first commit to the remote.
#[test]
fn e2e_multi_device_enrollment_proof_forgery_refused() {
    let guard = spawn_daemon(tempfile::Builder::new().prefix("e2emf").tempdir().unwrap());
    let pw = TEST_PASSWORD;

    let remote = guard.path().join("remote.git");
    let st = Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .expect("git must be on PATH (vault creation shells out to git)");
    assert!(st.success(), "git init --bare failed");
    let remote_url = format!("file://{}", remote.display());

    let a = daemon_init_json(&guard, "baluard-deva");
    let phrase = a["recovery_phrase"].as_str().expect("phrase").to_string();
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-deva"])
        .assert()
        .success();
    baluard_daemon(&guard).args(["unlock"]).assert().success();
    baluard_daemon(&guard)
        .args(["sync", "remote", &remote_url])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "push"])
        .assert()
        .success();

    baluard_daemon(&guard)
        .args(["sync", "clone-url", &remote_url, "--slug", "baluard-devb"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-devb"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args([
            "devices",
            "enroll-with-phrase",
            "--phrase",
            &phrase,
            "--yes",
        ])
        .assert()
        .success();

    // Forge the proof: keep the structure (parses, epoch intact) but
    // replace the Root-Key-derived signature with garbage of equal shape.
    let enroll_dir = guard
        .path()
        .join("data/vaults/baluard-devb/meta/enrollments");
    let mut forged = None;
    for entry in std::fs::read_dir(&enroll_dir).expect("enrollments dir") {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|e| e == "proof") {
            let raw = std::fs::read_to_string(&p).unwrap();
            let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
            // 64 zero bytes, base64: decodes cleanly, so ed25519
            // verification itself must reject it (not just the length
            // check).
            json["signature"] = serde_json::Value::String("A".repeat(84) + "AA==");
            std::fs::write(&p, json.to_string()).unwrap();
            forged = Some(p);
            break;
        }
    }
    assert!(forged.is_some(), "enrollment proof not found for tampering");

    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "ForgedDeviceB",
            "--username",
            "bob",
            "--password",
            &format!("{pw}-b"),
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["sync", "push"])
        .assert()
        .success();

    // A refuses: the proof does not carry Root-Key authority.
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-deva"])
        .assert()
        .success();
    baluard_daemon(&guard).args(["unlock"]).assert().success();
    baluard_daemon(&guard)
        .args(["sync", "pull"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "commit signature verification failed",
        ));
    baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("ForgedDeviceB").not());
}

/// Encrypted backup (docs/adr/0099-encrypted-backup.md): vault A exports a
/// passphrase-protected .bldbak container; a wrong passphrase fails with the
/// single generic error (never an import summary); then a DIFFERENT vault B
/// restores the same file under its own keys — the not-locked-in guarantee,
/// since the file key derives only from the passphrase. All surfaces ride
/// the path-based daemon transport (§8): the daemon builds and reads the
/// file itself, so no bucket is capped by frame limits.
#[test]
fn e2e_encrypted_backup_cross_vault_restore() {
    let guard = spawn_daemon(tempfile::Builder::new().prefix("e2ebk").tempdir().unwrap());

    // Vault A: create, unlock, add one entry, export encrypted.
    daemon_init_json(&guard, "baluard-vaulta");
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-vaulta"])
        .assert()
        .success();
    baluard_daemon(&guard).args(["unlock"]).assert().success();
    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "FromBackup",
            "--username",
            "u",
            "--password",
            "backup-pw-123",
        ])
        .assert()
        .success();

    let backup = guard.path().join("backup.bldbak");
    baluard_daemon(&guard)
        .env("BALUARD_BACKUP_PASSPHRASE", "backup-phrase-2026")
        .args(["export", "--encrypted", "--force"])
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicates::str::contains("Backup checked:"));
    assert!(backup.exists(), "daemon must write the container itself");

    // Vault B: a different vault restores the same file. Listed FIRST to
    // prove it is a distinct, empty vault ("Imported: 1" would print
    // equally if the switch had silently failed back to A).
    daemon_init_json(&guard, "baluard-vaultb");
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-vaultb"])
        .assert()
        .success();
    baluard_daemon(&guard).args(["unlock"]).assert().success();
    baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("FromBackup").not());

    // Wrong passphrase: one generic error, indistinguishable from corruption,
    // and never an import summary on stdout.
    baluard_daemon(&guard)
        .env("BALUARD_BACKUP_PASSPHRASE", "not-the-passphrase")
        .args(["import", "baluard-encrypted"])
        .arg(&backup)
        .assert()
        .failure()
        .stderr(predicates::str::contains("wrong password or damaged file"))
        .stdout(predicates::str::contains("Imported:").not());

    // Right passphrase: entries land in vault B (fresh UUIDs, B's keys), and
    // the secret itself survived the roundtrip.
    baluard_daemon(&guard)
        .env("BALUARD_BACKUP_PASSPHRASE", "backup-phrase-2026")
        .args(["import", "baluard-encrypted"])
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicates::str::contains("Imported: 1"));
    let listing = baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let id = row_id(&listing, "FromBackup");
    baluard_daemon(&guard)
        .args(["get", &id, "--decrypt", "--output=text"])
        .assert()
        .success()
        .stdout(predicates::str::contains("backup-pw-123"));
}

/// G24 step 6 (plan §6): CLI search is the executable spec of the fan-out
/// contract. --all merges unlocked vaults (a locked one contributes
/// nothing), the default form is active-vault only, --vault scopes to one
/// explicit vault, and an explicit search of a locked vault fails loudly.
#[test]
fn e2e_search_all_and_explicit_vault() {
    let tmp = tempfile::tempdir().expect("tmp");
    // Vault A exists before the daemon and is the initial active vault.
    let _a = init_vault_json(&tmp, "baluard-e2e-sa");
    let guard = spawn_daemon(tmp);

    baluard_daemon(&guard).arg("unlock").assert().success();
    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "Alpha Query",
            "--username",
            "a",
            "--password",
            "pw-a",
        ])
        .assert()
        .success();

    // Second vault through the running daemon: init registers it and makes
    // it active, so the following unlock/add land in B.
    baluard_daemon(&guard)
        .args([
            "init",
            "--name",
            "Search B",
            "--slug",
            "baluard-e2e-sb",
            "--json",
        ])
        .assert()
        .success();
    // init registers + sets the registry default but does NOT flip the
    // daemon host's active pointer - the explicit switch is required
    // (the multi-device join flow hit the same thing).
    baluard_daemon(&guard)
        .args(["vaults", "switch", "baluard-e2e-sb"])
        .assert()
        .success();
    baluard_daemon(&guard).arg("unlock").assert().success();
    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "Beta Query",
            "--username",
            "b",
            "--password",
            "pw-b",
        ])
        .assert()
        .success();

    // Lock A in place while B stays active and unlocked.
    baluard_daemon(&guard)
        .args(["--vault", "baluard-e2e-sa", "lock"])
        .assert()
        .success();

    // --all sees only the unlocked vault, tagged with its display name.
    baluard_daemon(&guard)
        .args(["search", "Query", "--all"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Beta Query"))
        .stdout(predicates::str::contains("Search B"))
        .stdout(predicates::str::contains("Alpha Query").not());

    // Default form: the active vault only.
    baluard_daemon(&guard)
        .args(["search", "Alpha"])
        .assert()
        .success()
        .stdout(predicates::str::contains("No matches."));

    // An explicit search of a locked vault fails loudly.
    baluard_daemon(&guard)
        .args(["search", "Alpha", "--vault", "baluard-e2e-sa"])
        .assert()
        .failure();

    // Unlock A while B stays active; --all now merges both, each tagged.
    baluard_daemon(&guard)
        .args(["--vault", "baluard-e2e-sa", "unlock"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["search", "Query", "--all"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Alpha Query"))
        .stdout(predicates::str::contains("Beta Query"));

    // Explicit --vault scopes to one vault even with both unlocked.
    baluard_daemon(&guard)
        .args(["search", "Query", "--vault", "baluard-e2e-sb"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Beta Query"))
        .stdout(predicates::str::contains("Alpha Query").not());
}

/// Wave B (CLI parity): the G7/G9/G11-phase-1 commands ride their daemon
/// routes end to end - generation with history best-effort, TOTP by name
/// resolution, SSH keygen (private material printed, never stored unless
/// asked), collections create/assign/list, members list, and a root-key
/// rotation the vault keeps unlocking after.
#[test]
fn e2e_cli_parity_generate_totp_ssh_collections_rotation() {
    let tmp = tempfile::tempdir().expect("tmp");
    let _a = init_vault_json(&tmp, "baluard-e2e-wb");
    let guard = spawn_daemon(tmp);
    baluard_daemon(&guard).arg("unlock").assert().success();

    // G7: generation prints once. The vault is unlocked, so the
    // best-effort history hook must not fail the command.
    let generated = baluard_daemon(&guard)
        .args(["generate", "password", "--length", "24", "--no-symbols"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let generated = String::from_utf8(generated).expect("utf8");
    let generated = generated.trim();
    assert_eq!(generated.len(), 24, "password length: {generated}");
    assert!(
        !generated
            .chars()
            .any(|c| "!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\ ".contains(c)),
        "no symbols or separators: {generated}"
    );
    baluard_daemon(&guard)
        .args(["generate", "passphrase", "--words", "4"])
        .assert()
        .success();

    // G7: TOTP resolves a name substring to the entry and prints a
    // live code with its validity window.
    baluard_daemon(&guard)
        .args([
            "add",
            "login",
            "--name",
            "Totp Site",
            "--username",
            "me",
            "--password",
            "pw-123456",
            "--totp-uri",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
        ])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["totp", "Totp"])
        .assert()
        .success()
        .stdout(predicates::str::contains("(valid for"));

    // G7: SSH keygen prints all three artifacts; --store lands an
    // SshKey entry whose get shows the fingerprint.
    baluard_daemon(&guard)
        .args([
            "ssh-keygen",
            "--comment",
            "e2e@test",
            "--store",
            "Server key",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Public key:"))
        .stdout(predicates::str::contains("Fingerprint:"))
        .stdout(predicates::str::contains("PRIVATE KEY"));
    let listing = baluard_daemon(&guard)
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ssh_id = row_id(&listing, "Server key");
    baluard_daemon(&guard)
        .args(["get", &ssh_id])
        .assert()
        .success()
        .stdout(predicates::str::contains("Server key"));

    // G11 phase 1: collections create -> assign by name -> list shows
    // the admin grant table.
    baluard_daemon(&guard)
        .args(["collections", "create", "Family"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["collections", "assign", "Totp", "--to", "Family"])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["collections", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Family  (admin)"));

    // G11 phase 1: members list marks the self row and the role.
    baluard_daemon(&guard)
        .args(["members", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("owner"))
        .stdout(predicates::str::contains("You are owner."));

    // G9: a standalone root-key rotation succeeds and the vault
    // keeps serving decrypted reads afterwards (keys re-derived in
    // place; other devices adopt on their next unlock).
    baluard_daemon(&guard)
        .arg("rotate-root")
        .assert()
        .success()
        .stdout(predicates::str::contains("Root key rotated"));
    baluard_daemon(&guard)
        .args(["totp", "Totp"])
        .assert()
        .success();
}

/// G26: `members replace-device` — the stolen-device journey in one CLI
/// call. Seeds a hand-written live member row (required fields only;
/// everything else serde-defaults), replaces it against the real daemon,
/// and pins the one-time invite code, the successor id, and the two
/// refusal paths (own row, already-gone row).
#[test]
fn e2e_members_replace_device() {
    let tmp = tempfile::TempDir::new().unwrap();
    let guard = spawn_daemon(tmp);
    let slug = "baluard-rdev";
    let created = daemon_init_json(&guard, slug);
    let vault_path = created["path"].as_str().unwrap().to_string();
    baluard_daemon(&guard)
        .args(["vaults", "switch", slug])
        .assert()
        .success();
    baluard_daemon(&guard)
        .args(["unlock"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault unlocked (daemon)."));

    // Self row id (the owner device's own member row) from members list.
    let list = baluard_daemon(&guard)
        .args(["members", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let self_line = String::from_utf8(list)
        .unwrap()
        .lines()
        .find(|l| l.starts_with('*'))
        .expect("self member row")
        .to_string();
    let own_id = self_line.split_whitespace().nth(1).unwrap().to_string();

    // Hand-write a second live member row (minimal JSON: the other
    // MemberFile fields are serde-defaulted) plus a device binding to an
    // unknown device, so the revoke-and-rekey leg errors and the CLI's
    // warning formatter is pinned too.
    let stolen_id = uuid::Uuid::new_v4();
    let stolen_device = uuid::Uuid::new_v4();
    let row = format!(
        "{{\"id\":\"{stolen_id}\",\"display_name\":\"Stolen Tablet\",\"role\":\"editor\",\"trust\":\"channel\"}}",
    );
    std::fs::write(
        std::path::Path::new(&vault_path)
            .join("meta/members")
            .join(format!("{stolen_id}.json")),
        row,
    )
    .unwrap();
    let devices_dir = std::path::Path::new(&vault_path)
        .join("meta/members")
        .join(stolen_id.to_string())
        .join("devices");
    std::fs::create_dir_all(&devices_dir).unwrap();
    std::fs::write(
        devices_dir.join(format!("{stolen_device}.json")),
        format!("{{\"device_id\":\"{stolen_device}\",\"member_id\":\"{stolen_id}\"}}"),
    )
    .unwrap();

    // Happy path: reset + report. No bindings exist for the stolen
    // row, so the revoke leg finds nothing and reports no error.
    let out = baluard_daemon(&guard)
        .args(["members", "replace-device", &stolen_id.to_string()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("Device replaced. Successor member:"));
    assert!(out.contains("Replacement invite code (shown once"));
    let code_line = out
        .lines()
        .find(|l| {
            !l.is_empty()
                && !l.starts_with("Device replaced")
                && !l.starts_with("Replacement invite code")
                && !l.starts_with("Collections rotated")
        })
        .expect("invite code line")
        .trim()
        .to_string();
    assert!(
        code_line.len() > 100,
        "invite code should be long: {code_line}"
    );
    assert!(out.contains("Collections rotated: 0."));
    // The binding points at a device that was never enrolled: the
    // revoke-and-rekey leg refuses it and the CLI surfaces the stop.
    assert!(out.contains("Revoke-and-rekey stopped:"));

    // The row is now tombstoned: a second replace refuses.
    baluard_daemon(&guard)
        .args(["members", "replace-device", &stolen_id.to_string()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already gone"));

    // Own row: the daemon refuses to lock the actor out.
    baluard_daemon(&guard)
        .args(["members", "replace-device", &own_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("would lock you out"));
}
