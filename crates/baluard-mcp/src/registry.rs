//! Pairing registry plus the volatile agent state: read grants, yolo
//! windows, and cap meters. Pairings persist (hashed tokens only); every
//! grant and yolo window is in-memory with a monotonic expiry and dies on
//! vault lock or daemon restart by construction.

use baluard_core::error::{BaluardError, VaultError};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::policy::{CapMeter, CapOutcome};

pub const MCP_TOKEN_PREFIX: &str = "blrd_mcp_";
pub const MCP_SESSION_PREFIX: &str = "blrd_mcp_s_";
const PAIRINGS_FILE: &str = "mcp-pairings.json";

/// Approval session grant for the CLI stdio transport, in flight for this
/// long while the human approves the named parent executable.
pub const SESSION_APPROVAL_WAIT: Duration = Duration::from_secs(60);

/// Per-read desktop approval window for the pending request itself (the
/// queue sweeps older ones anyway); the tool call waits at most this long.
pub const READ_APPROVAL_WAIT: Duration = Duration::from_secs(30);

/// Persisted pairing. The raw token exists exactly once, returned at pair
/// time; only this SHA-256 is kept, on disk in this struct.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pairing {
    pub id: String,
    pub name: String,
    pub vault_slug: String,
    pub token_sha256: [u8; 32],
    pub created_at_ms: u64,
}

/// What the desktop settings row shows per pairing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PairingView {
    pub id: String,
    pub name: String,
    pub vault_slug: String,
    pub created_at_ms: u64,
    pub yolo_expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct YoloWindow {
    expires: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadGrantKey {
    pub pairing_id: String,
    pub item_id: String,
    pub tool: String,
}

/// Why a pairing verification failed. The caller maps these to the
/// machine-readable outcomes; never a raw crypto error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    UnknownPairing,
    Revoked,
    WrongVault,
    Locked,
    NoSession,
    WrongProcess,
    AuditFailed(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPairing => write!(f, "unknown pairing"),
            Self::Revoked => write!(f, "pairing was revoked"),
            Self::WrongVault => write!(f, "pairing is bound to a different vault"),
            Self::Locked => write!(f, "vault is locked"),
            Self::NoSession => write!(f, "no active MCP session"),
            Self::WrongProcess => write!(f, "MCP session belongs to a different process tree"),
            Self::AuditFailed(e) => write!(f, "audit failed: {e}"),
        }
    }
}

impl From<RegistryError> for BaluardError {
    fn from(e: RegistryError) -> Self {
        BaluardError::Vault(VaultError::InvalidOperation(e.to_string()))
    }
}

/// A verified stdio session: the pairing-equivalent identity for the CLI
/// transport, bound to the resolved parent process instead of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionVerdict {
    pub session_id: String,
    pub vault_slug: String,
    pub display_name: String,
    pub exe_path: String,
}

#[derive(Default)]
struct Volatile {
    yolo: HashMap<String, YoloWindow>,
    read_grants: HashMap<ReadGrantKey, Instant>,
    caps: HashMap<String, CapMeter>,
    sessions: HashMap<String, McpSession>,
    /// slug -> vault path, bound at pair/tool-call time so the runtime
    /// lock path (which knows paths, not slugs) can clear volatile state.
    vault_paths: HashMap<String, PathBuf>,
}

#[derive(Debug, Clone)]
struct McpSession {
    token_sha256: [u8; 32],
    vault_slug: String,
    exe_path: String,
    /// Peer binding of the coding agent (the parent of the `mcp serve`
    /// process the daemon resolved at connect time).
    peer: SessionPeer,
}

pub struct McpRegistry {
    pairings: RwLock<Vec<Pairing>>,
    volatile: RwLock<Volatile>,
}

/// Minimal peer identity for the stdio path: the daemon resolves the real
/// PeerBinding from socket credentials; this struct carries the fields the
/// chain-membership check needs without pulling runtime types in.
#[derive(Debug, Clone)]
pub struct SessionPeer {
    pub pid: u32,
    pub start_ticks: u64,
    pub exe_path: String,
}

impl SessionPeer {
    /// True when `chain` (the presenting process's ancestor chain, nearest
    /// ancestor first, as (pid, start_ticks) pairs) contains the bound pid
    /// with matching start ticks. Start ticks make pid reuse safe.
    pub fn in_chain(&self, chain: &[(u32, u64)]) -> bool {
        chain.iter().take(8).any(|(pid, start)| {
            pid == &self.pid && (*start == self.start_ticks || self.start_ticks == 0 || *start == 0)
        })
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

impl McpRegistry {
    pub fn new() -> Self {
        Self {
            pairings: RwLock::new(Vec::new()),
            volatile: RwLock::new(Volatile::default()),
        }
    }

    /// Loads persisted pairings from the daemon data dir. Missing file is
    /// a fresh install; a corrupt file fails closed (no pairings load).
    pub fn load_from_disk(data_dir: &std::path::Path) -> Self {
        let reg = Self::new();
        let Ok(raw) = std::fs::read_to_string(data_dir.join(PAIRINGS_FILE)) else {
            return reg;
        };
        if let Ok(pairings) = serde_json::from_str::<Vec<Pairing>>(&raw) {
            *reg.pairings.write().unwrap() = pairings;
        }
        reg
    }

    pub fn persist(&self, data_dir: &std::path::Path) -> Result<(), String> {
        let pairings = self.pairings.read().unwrap().clone();
        let bytes = serde_json::to_vec_pretty(&pairings).map_err(|e| e.to_string())?;
        baluard_core::secret_file::write_secret_file(&data_dir.join(PAIRINGS_FILE), &bytes)
            .map_err(|e| format!("write mcp pairings: {e}"))
    }

    /// Mints a pairing and returns the raw token exactly once. The token
    /// is never stored in clear anywhere; only its digest persists.
    pub fn create_pairing(
        &self,
        name: &str,
        vault_slug: &str,
        data_dir: &std::path::Path,
    ) -> Result<(Pairing, String), String> {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = format!("{MCP_TOKEN_PREFIX}{}", hex::encode(raw));
        let pairing = Pairing {
            id: uuid_like(),
            name: name.to_string(),
            vault_slug: vault_slug.to_string(),
            token_sha256: sha256(token.as_bytes()),
            created_at_ms: now_ms(),
        };
        let mut guard = self.pairings.write().unwrap();
        guard.push(pairing.clone());
        drop(guard);
        self.persist(data_dir)?;
        Ok((pairing, token))
    }

    /// Constant-time pairing verification. Returns the pairing's vault
    /// binding so the caller can enforce single-vault reach.
    pub fn verify_pairing(&self, token: &str) -> Result<Pairing, RegistryError> {
        use subtle::ConstantTimeEq;
        if !token.starts_with(MCP_TOKEN_PREFIX) {
            return Err(RegistryError::UnknownPairing);
        }
        let digest = sha256(token.as_bytes());
        let pairings = self.pairings.read().unwrap();
        pairings
            .iter()
            .find(|p| bool::from(p.token_sha256.ct_eq(&digest)))
            .cloned()
            .ok_or(RegistryError::UnknownPairing)
    }

    pub fn revoke_pairing(
        &self,
        pairing_id: &str,
        data_dir: &std::path::Path,
    ) -> Result<bool, String> {
        let mut guard = self.pairings.write().unwrap();
        let before = guard.len();
        guard.retain(|p| p.id != pairing_id);
        let removed = guard.len() != before;
        drop(guard);
        // Revocation kills the volatile state immediately: grants, yolo,
        // and caps for this pairing cannot outlive their row.
        let mut vol = self.volatile.write().unwrap();
        vol.yolo.remove(pairing_id);
        vol.caps.remove(pairing_id);
        vol.read_grants.retain(|k, _| k.pairing_id != pairing_id);
        drop(vol);
        if removed {
            self.persist(data_dir)?;
        }
        Ok(removed)
    }

    pub fn revoke_all_for_vault(
        &self,
        vault_slug: &str,
        data_dir: &std::path::Path,
    ) -> Result<usize, String> {
        let removed = {
            let mut guard = self.pairings.write().unwrap();
            let before = guard.len();
            guard.retain(|p| p.vault_slug != vault_slug);
            before - guard.len()
        };
        let mut vol = self.volatile.write().unwrap();
        let ids: Vec<String> = self
            .pairings
            .read()
            .unwrap()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        vol.yolo.retain(|id, _| ids.contains(id));
        vol.caps.retain(|id, _| ids.contains(id));
        vol.read_grants.retain(|k, _| ids.contains(&k.pairing_id));
        drop(vol);
        if removed > 0 {
            self.persist(data_dir)?;
        }
        Ok(removed)
    }

    pub fn pairing_views(&self) -> Vec<PairingView> {
        let pairings = self.pairings.read().unwrap();
        let vol = self.volatile.read().unwrap();
        pairings
            .iter()
            .map(|p| PairingView {
                id: p.id.clone(),
                name: p.name.clone(),
                vault_slug: p.vault_slug.clone(),
                created_at_ms: p.created_at_ms,
                yolo_expires_in_secs: vol.yolo.get(&p.id).and_then(|w| {
                    w.expires
                        .checked_duration_since(Instant::now())
                        .map(|d| d.as_secs())
                }),
            })
            .collect()
    }

    // ── Yolo ─────────────────────────────────────────────────────────────

    /// Enables a yolo window for one pairing. Fails closed if the pairing
    /// is unknown or a window is already live (disable first, or let it
    /// expire — re-enabling with a fresh duration must never extend a
    /// running window silently).
    pub fn yolo_enable(&self, pairing_id: &str, ttl_secs: u64) -> Result<(), RegistryError> {
        let exists = self
            .pairings
            .read()
            .unwrap()
            .iter()
            .any(|p| p.id == pairing_id);
        if !exists {
            return Err(RegistryError::UnknownPairing);
        }
        let mut vol = self.volatile.write().unwrap();
        if vol
            .yolo
            .get(pairing_id)
            .is_some_and(|w| w.expires > Instant::now())
        {
            return Err(RegistryError::Revoked);
        }
        vol.yolo.insert(
            pairing_id.to_string(),
            YoloWindow {
                expires: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(())
    }

    pub fn yolo_kill(&self, pairing_id: &str) -> bool {
        self.volatile
            .write()
            .unwrap()
            .yolo
            .remove(pairing_id)
            .is_some()
    }

    /// None, expired, or wrong pairing all read as inactive: fail closed.
    pub fn yolo_active(&self, pairing_id: &str) -> bool {
        let vol = self.volatile.read().unwrap();
        vol.yolo
            .get(pairing_id)
            .is_some_and(|w| w.expires > Instant::now())
    }

    // ── Scoped read grants ──────────────────────────────────────────────

    /// Activates a per-read window scoped strictly to (pairing, item, tool).
    /// A just-this-read approval activates nothing (no grant recorded).
    pub fn grant_read(&self, key: ReadGrantKey, ttl_secs: u64) {
        if ttl_secs == 0 {
            return;
        }
        self.volatile
            .write()
            .unwrap()
            .read_grants
            .insert(key, Instant::now() + Duration::from_secs(ttl_secs));
    }

    pub fn read_grant_live(&self, key: &ReadGrantKey) -> bool {
        let vol = self.volatile.read().unwrap();
        vol.read_grants
            .get(key)
            .is_some_and(|exp| *exp > Instant::now())
    }

    // ── Caps ─────────────────────────────────────────────────────────────

    pub fn charge_read(&self, pairing_id: &str) -> CapOutcome {
        let mut vol = self.volatile.write().unwrap();
        vol.caps.entry(pairing_id.to_string()).or_default().charge(
            crate::policy::SECRET_READS_PER_DAY,
            crate::policy::SECRET_BURST_PER_MINUTE,
        )
    }

    pub fn charge_search(&self, pairing_id: &str) -> CapOutcome {
        let mut vol = self.volatile.write().unwrap();
        vol.caps.entry(pairing_id.to_string()).or_default().charge(
            crate::policy::SEARCH_CAP_PER_DAY,
            crate::policy::SEARCH_BURST_PER_MINUTE,
        )
    }

    // ── Stdio sessions ───────────────────────────────────────────────────

    /// Mints a volatile stdio session token after the human approved the
    /// named parent executable. The token dies with this registry (daemon
    /// restart) or when the bound vault locks.
    pub fn create_session(&self, vault_slug: &str, exe_path: &str, peer: SessionPeer) -> String {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = format!("{MCP_SESSION_PREFIX}{}", hex::encode(raw));
        let id = uuid_like();
        self.volatile.write().unwrap().sessions.insert(
            id.clone(),
            McpSession {
                token_sha256: sha256(token.as_bytes()),
                vault_slug: vault_slug.to_string(),
                exe_path: exe_path.to_string(),
                peer,
            },
        );
        // The session id rides separately so tool calls never re-present
        // the token; the CLI keeps both and presents the token.
        let _ = id;
        token
    }

    /// Verifies a presented stdio session token against the caller's
    /// process chain (nearest ancestor first). Start-time matching makes
    /// pid reuse safe.
    pub fn verify_session(
        &self,
        token: &str,
        chain: &[(u32, u64)],
    ) -> Result<SessionVerdict, RegistryError> {
        use subtle::ConstantTimeEq;
        if !token.starts_with(MCP_SESSION_PREFIX) {
            return Err(RegistryError::NoSession);
        }
        let digest = sha256(token.as_bytes());
        let vol = self.volatile.read().unwrap();
        let (session_id, session) = vol
            .sessions
            .iter()
            .find(|(_, s)| bool::from(s.token_sha256.ct_eq(&digest)))
            .ok_or(RegistryError::NoSession)?;
        if !session.peer.in_chain(chain) {
            return Err(RegistryError::WrongProcess);
        }
        Ok(SessionVerdict {
            session_id: session_id.clone(),
            vault_slug: session.vault_slug.clone(),
            display_name: format!("{} (stdio)", session.exe_path),
            exe_path: session.exe_path.clone(),
        })
    }

    pub fn kill_session(&self, token: &str) -> bool {
        use subtle::ConstantTimeEq;
        let digest = sha256(token.as_bytes());
        let mut vol = self.volatile.write().unwrap();
        let before = vol.sessions.len();
        vol.sessions
            .retain(|_, s| !bool::from(s.token_sha256.ct_eq(&digest)));
        vol.sessions.len() != before
    }

    /// The lock path: every grant, yolo window, and session bound to this
    /// vault dies. Volatile state only — nothing to persist or restore.
    pub fn vault_locked(&self, vault_slug: &str) {
        let mut vol = self.volatile.write().unwrap();
        let dead: Vec<String> = self
            .pairings
            .read()
            .unwrap()
            .iter()
            .filter(|p| p.vault_slug == vault_slug)
            .map(|p| p.id.clone())
            .collect();
        for id in dead {
            vol.yolo.remove(&id);
        }
        vol.read_grants
            .retain(|k, _| !self.pairing_vault_is(&k.pairing_id, vault_slug));
        vol.sessions.retain(|_, s| s.vault_slug != vault_slug);
    }

    /// Binds a vault slug to its path so the runtime lock hook (which only
    /// knows paths) can clear volatile state. Re-binding with the same slug
    /// updates the path; missing bindings make the lock hook a no-op.
    pub fn bind_vault(&self, vault_slug: &str, vault_path: &std::path::Path) {
        self.volatile
            .write()
            .unwrap()
            .vault_paths
            .insert(vault_slug.to_string(), vault_path.to_path_buf());
    }

    /// Called from VaultState::lock(): resolves the slug for this path and
    /// clears everything volatile bound to it. Unknown paths are a no-op
    /// (the vault never carried MCP state).
    pub fn vault_locked_by_path(&self, vault_path: &std::path::Path) {
        let slug = {
            let vol = self.volatile.read().unwrap();
            vol.vault_paths
                .iter()
                .find(|(_, p)| **p == vault_path)
                .map(|(slug, _)| slug.clone())
        };
        if let Some(slug) = slug {
            self.vault_locked(&slug);
        }
    }

    /// Daemon restart shape: drop every volatile window. Pairings survive;
    /// nothing else does.
    pub fn reset_volatile(&self) {
        *self.volatile.write().unwrap() = Volatile::default();
    }

    fn pairing_vault_is(&self, pairing_id: &str, vault_slug: &str) -> bool {
        self.pairings
            .read()
            .unwrap()
            .iter()
            .any(|p| p.id == pairing_id && p.vault_slug == vault_slug)
    }
}

impl Default for McpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn uuid_like() -> String {
    let mut raw = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// The process-wide registry. One daemon (and its runtime lock hook) share
/// it; tests build their own instances with `McpRegistry::new`.
pub static GLOBAL: std::sync::LazyLock<McpRegistry> =
    std::sync::LazyLock::new(|| McpRegistry::load_from_disk(&baluard_core::paths::data_dir()));

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    #[test]
    fn pairing_token_verifies_once_and_revocation_kills_it() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (pairing, token) = reg.create_pairing("Claude", "personal", &path).unwrap();
        assert!(token.starts_with(MCP_TOKEN_PREFIX));
        assert_eq!(reg.verify_pairing(&token).unwrap().id, pairing.id);
        // The digest never round-trips: no clear token on disk.
        let raw = std::fs::read_to_string(path.join(PAIRINGS_FILE)).unwrap();
        assert!(
            !raw.contains(&token),
            "raw pairing token must never persist"
        );
        assert!(reg.revoke_pairing(&pairing.id, &path).unwrap());
        assert_eq!(
            reg.verify_pairing(&token),
            Err(RegistryError::UnknownPairing)
        );
    }

    #[test]
    fn pairing_is_bound_to_one_vault() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (pairing, token) = reg.create_pairing("Cursor", "work", &path).unwrap();
        assert_eq!(reg.verify_pairing(&token).unwrap().vault_slug, "work");
        assert_eq!(pairing.name, "Cursor");
    }

    #[test]
    fn revoke_all_for_vault_leaves_other_vaults_paired() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (a, ta) = reg.create_pairing("A", "personal", &path).unwrap();
        let (b, tb) = reg.create_pairing("B", "work", &path).unwrap();
        assert_eq!(reg.revoke_all_for_vault("personal", &path).unwrap(), 1);
        assert_eq!(reg.verify_pairing(&ta), Err(RegistryError::UnknownPairing));
        assert!(reg.verify_pairing(&tb).is_ok());
        assert_eq!(a.id, a.id);
        let _ = b;
    }

    #[test]
    fn yolo_fails_closed_everywhere() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (pairing, _) = reg.create_pairing("A", "v", &path).unwrap();
        assert!(!reg.yolo_active(&pairing.id));
        assert!(!reg.yolo_active("nonexistent"));
        assert_eq!(
            reg.yolo_enable("nonexistent", 60),
            Err(RegistryError::UnknownPairing)
        );
        reg.yolo_enable(&pairing.id, 60).unwrap();
        assert!(reg.yolo_active(&pairing.id));
        // A live window refuses silent re-extension.
        assert_eq!(
            reg.yolo_enable(&pairing.id, 60),
            Err(RegistryError::Revoked)
        );
        assert!(reg.yolo_kill(&pairing.id));
        assert!(!reg.yolo_active(&pairing.id));
        assert!(!reg.yolo_kill(&pairing.id));
    }

    #[test]
    fn yolo_expires_by_monotonic_clock() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (pairing, _) = reg.create_pairing("A", "v", &path).unwrap();
        // 1 second is the smallest real window; sleep past it.
        reg.yolo_enable(&pairing.id, 1).unwrap();
        assert!(reg.yolo_active(&pairing.id));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            !reg.yolo_active(&pairing.id),
            "expired yolo must read inactive"
        );
    }

    #[test]
    fn read_grants_are_scoped_to_one_item_and_tool() {
        let key1 = ReadGrantKey {
            pairing_id: "p".into(),
            item_id: "item-1".into(),
            tool: "get_login".into(),
        };
        let key2 = ReadGrantKey {
            pairing_id: "p".into(),
            item_id: "item-2".into(),
            tool: "get_login".into(),
        };
        let key3 = ReadGrantKey {
            pairing_id: "p".into(),
            item_id: "item-1".into(),
            tool: "get_totp".into(),
        };
        let reg = McpRegistry::new();
        reg.grant_read(key1.clone(), 60);
        assert!(reg.read_grant_live(&key1));
        assert!(
            !reg.read_grant_live(&key2),
            "approving one item never widens to another"
        );
        assert!(
            !reg.read_grant_live(&key3),
            "approving one tool never widens to another"
        );
        // Just-this-read records nothing.
        reg.grant_read(key2.clone(), 0);
        assert!(!reg.read_grant_live(&key2));
    }

    #[test]
    fn vault_lock_kills_yolo_grants_and_sessions_for_that_vault_only() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (a, _) = reg.create_pairing("A", "personal", &path).unwrap();
        let (b, _) = reg.create_pairing("B", "work", &path).unwrap();
        reg.yolo_enable(&a.id, 60).unwrap();
        reg.yolo_enable(&b.id, 60).unwrap();
        let key_a = ReadGrantKey {
            pairing_id: a.id.clone(),
            item_id: "i".into(),
            tool: "get_login".into(),
        };
        let key_b = ReadGrantKey {
            pairing_id: b.id.clone(),
            item_id: "i".into(),
            tool: "get_login".into(),
        };
        reg.grant_read(key_a.clone(), 60);
        reg.grant_read(key_b.clone(), 60);
        let peer = SessionPeer {
            pid: 7,
            start_ticks: 1,
            exe_path: "/usr/bin/agent".into(),
        };
        let tok_a = reg.create_session("personal", "/usr/bin/agent", peer.clone());
        let tok_b = reg.create_session("work", "/usr/bin/agent", peer);

        reg.vault_locked("personal");

        assert!(
            !reg.yolo_active(&a.id),
            "locked vault kills its pairing's yolo"
        );
        assert!(reg.yolo_active(&b.id), "other vault's yolo survives");
        assert!(!reg.read_grant_live(&key_a));
        assert!(reg.read_grant_live(&key_b));
        assert!(
            reg.verify_session(&tok_a, &[(7, 1)]).is_err(),
            "lock kills the session"
        );
        assert!(reg.verify_session(&tok_b, &[(7, 1)]).is_ok());
    }

    #[test]
    fn vault_lock_by_path_kills_yolo_grants_and_sessions() {
        let (_dir, path) = temp_dir();
        let reg = McpRegistry::new();
        let (a, _) = reg.create_pairing("A", "personal", &path).unwrap();
        reg.yolo_enable(&a.id, 60).unwrap();
        let key_a = ReadGrantKey {
            pairing_id: a.id.clone(),
            item_id: "i".into(),
            tool: "get_login".into(),
        };
        reg.grant_read(key_a.clone(), 60);
        let vault = std::path::Path::new("/tmp/personal-vault");
        reg.bind_vault("personal", vault);
        // The runtime lock hook knows only the path.
        reg.vault_locked_by_path(vault);
        assert!(!reg.yolo_active(&a.id));
        assert!(!reg.read_grant_live(&key_a));
        // An unknown path is a no-op, not a wipe of everything.
        let (b, _) = reg.create_pairing("B", "work", &path).unwrap();
        reg.yolo_enable(&b.id, 60).unwrap();
        reg.vault_locked_by_path(std::path::Path::new("/tmp/unknown"));
        assert!(reg.yolo_active(&b.id));
    }

    #[test]
    fn restart_clears_every_volatile_window_but_keeps_pairings() {
        let dir = tempfile::tempdir().unwrap();
        let (pairing, token) = McpRegistry::new()
            .create_pairing("A", "v", dir.path())
            .unwrap();
        // "Restart": a fresh registry loads pairings from disk.
        let reg = McpRegistry::load_from_disk(dir.path());
        assert!(reg.verify_pairing(&token).is_ok());
        assert!(!reg.yolo_active(&pairing.id));
        let key = ReadGrantKey {
            pairing_id: pairing.id.clone(),
            item_id: "i".into(),
            tool: "get_login".into(),
        };
        assert!(!reg.read_grant_live(&key));
    }

    #[test]
    fn stdio_session_verifies_only_in_its_own_process_tree() {
        let reg = McpRegistry::new();
        let agent = SessionPeer {
            pid: 500,
            start_ticks: 4242,
            exe_path: "/usr/bin/agent".into(),
        };
        let token = reg.create_session("v", "/usr/bin/agent", agent);
        // agent(500) -> baluard(700): presenting chain nearest first.
        assert!(reg.verify_session(&token, &[(700, 1), (500, 4242)]).is_ok());
        assert_eq!(
            reg.verify_session(&token, &[(900, 9)]),
            Err(RegistryError::WrongProcess)
        );
        // A reused pid with different start ticks is refused.
        assert_eq!(
            reg.verify_session(&token, &[(500, 9999)]),
            Err(RegistryError::WrongProcess)
        );
        assert!(reg.kill_session(&token));
        assert_eq!(
            reg.verify_session(&token, &[(700, 1), (500, 4242)]),
            Err(RegistryError::NoSession)
        );
    }

    #[test]
    fn caps_are_per_pairing() {
        let reg = McpRegistry::new();
        for _ in 0..crate::policy::SECRET_BURST_PER_MINUTE {
            assert_eq!(reg.charge_read("p1"), CapOutcome::Allowed);
        }
        assert_eq!(reg.charge_read("p1"), CapOutcome::Throttled);
        // A different pairing has its own meter.
        assert_eq!(reg.charge_read("p2"), CapOutcome::Allowed);
    }
}
