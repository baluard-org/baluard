//! Phase 6: Multi-vault host.
//!
//! Replaces the daemon's single `Arc<VaultState>` with an `Arc<VaultHost>`
//! that holds every opened vault in memory at once. The "active" pointer
//! is the live focus; switching is a pointer flip, never a re-derivation
//! or zeroization. Each `VaultState` keeps its own session token, last
//! activity, cover timer, and auto-lock countdown, so vaults auto-lock
//! independently on their own schedules.
//!
//! Invariant: if `active` is `Some(slug)`, that slug MUST exist in `vaults`.
//! The single `RwLock<VaultHostInner>` is what makes this provable — a
//! concurrent `close` and `switch` cannot interleave to leave `active`
//! pointing at a removed entry.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::state::VaultState;

/// Per-vault visibility for `vaults.list` / vault switcher UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPresence {
    /// Loaded in the host map with an unlocked handle.
    Unlocked,
    /// Loaded in the host map but the handle is locked (keys zeroized).
    Locked,
    /// Registered but never opened in this session (or was closed).
    Closed,
}

impl VaultPresence {
    /// Lowercase wire label for JSON consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            VaultPresence::Unlocked => "unlocked",
            VaultPresence::Locked => "locked",
            VaultPresence::Closed => "closed",
        }
    }
}

/// Single critical section: holds the map and the active pointer together.
#[derive(Default)]
struct VaultHostInner {
    /// All vaults the daemon has opened, keyed by slug. Each entry is an
    /// independent `VaultState` (own handle, session token, last_activity,
    /// cover timer, auto-lock countdown).
    vaults: HashMap<String, Arc<VaultState>>,
    /// Slug currently "focused" by the desktop/CLI. Switching only mutates
    /// this; never touches any vault's key material. Invariant: if `Some`,
    /// the slug MUST exist in `vaults`.
    active: Option<String>,
}

impl VaultHostInner {
    /// Resolve the target slug for a request. Caller passes an explicit
    /// slug (from payload); when absent, falls back to the current `active`.
    /// Returns `None` when neither is available.
    fn target_slug<'a>(&'a self, slug: Option<&'a str>) -> Option<String> {
        if let Some(s) = slug.filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
        self.active.clone()
    }
}

/// Multi-vault host shared across all connection handlers.
pub struct VaultHost {
    inner: RwLock<VaultHostInner>,
    /// Host-level bridge-token registry (vault-agnostic, per Decision 10).
    /// Separate lock from `inner` so bridge auth never blocks vault ops.
    bridge: crate::bridge::SharedBridgeRegistry,
    /// D80: pending human-approval requests, shared across all vaults.
    pending: crate::agents::PendingQueue,
}

/// Convenience alias — the daemon always shares an `Arc<VaultHost>`.
pub type SharedVaultHost = Arc<VaultHost>;

impl VaultHost {
    /// Build an empty host. The active vault is opened lazily on the
    /// first `vault.open` / `vault.unlock` request (or by an explicit
    /// `vaults.switch`). At construction time we know nothing about
    /// the registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(VaultHostInner::default()),
            bridge: std::sync::Arc::new(RwLock::new(crate::bridge::BridgeRegistry::default())),
            pending: crate::agents::PendingQueue::new(),
        }
    }

    /// Wrap into the shared handle the daemon passes to connection handlers.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Borrow the bridge registry (for `bridge.*` routes + token verification).
    pub fn bridge(&self) -> &crate::bridge::SharedBridgeRegistry {
        &self.bridge
    }

    // ── lookups ──

    /// Read the current active slug. Does not touch the map.
    pub async fn active_slug(&self) -> Option<String> {
        self.inner.read().await.active.clone()
    }

    /// Resolve the target slug for a request. If the caller passed an
    /// explicit slug, use it; otherwise fall back to `active`. Returns
    /// `None` if no slug can be determined.
    #[allow(dead_code)]
    pub async fn resolve_target_slug(&self, slug: Option<&str>) -> Option<String> {
        self.inner.read().await.target_slug(slug)
    }

    /// Snapshot a strong reference to the target vault. Callers MUST
    /// operate on this clone for the whole request: it removes the
    /// TOCTOU where a mid-request `switch` would re-route an in-flight
    /// operation to a different vault.
    ///
    /// Returns `Ok(slug, arc)` when the slug is present. `Err(None)` when
    /// no slug could be resolved (no explicit slug + no active). `Err(Some)`
    /// when a slug was resolved but is not in the map (closed/never-opened).
    pub async fn snapshot_target(
        &self,
        slug: Option<&str>,
    ) -> Result<(String, Arc<VaultState>), SnapshotError> {
        let guard = self.inner.read().await;
        let target = match guard.target_slug(slug) {
            Some(s) => s,
            None => return Err(SnapshotError::NoActive),
        };
        match guard.vaults.get(&target) {
            Some(arc) => Ok((target, arc.clone())),
            None => Err(SnapshotError::SlugNotOpen(target)),
        }
    }

    /// Insert (or replace) a vault state under a slug. Returns the inserted
    /// arc. Used by `vault.open`, `vault.unlock`, and `vault.create`.
    pub async fn insert(&self, slug: String, state: Arc<VaultState>) -> Arc<VaultState> {
        let mut guard = self.inner.write().await;
        // A replaced entry keeps its autosync loop alive otherwise (same
        // leak as close).
        if let Some(old) = guard.vaults.get(&slug) {
            if !Arc::ptr_eq(old, &state) {
                old.autosync_deactivate().await;
            }
        }
        guard.vaults.insert(slug, state.clone());
        state
    }

    /// Atomic get-or-insert (H1 fix). Holds the write lock across the
    /// lookup + insert so two concurrent unlocks of the same not-yet-mapped
    /// slug cannot each build their own `VaultState` (which would leave the
    /// map holding one and the caller holding another, with mismatched
    /// session tokens). The closure runs at most once, under the lock.
    /// Returns the (possibly pre-existing) arc for the slug.
    pub async fn get_or_insert_with(
        &self,
        slug: &str,
        f: impl FnOnce() -> Arc<VaultState>,
    ) -> Arc<VaultState> {
        let mut guard = self.inner.write().await;
        guard
            .vaults
            .entry(slug.to_string())
            .or_insert_with(f)
            .clone()
    }

    /// Atomic try-insert (H1/M3 fix). Inserts only if the slug is vacant;
    /// returns `Err(existing)` if a `VaultState` for this slug is already in
    /// the map. Used by `vault.create` to reject slug collisions instead of
    /// silently replacing.
    pub async fn try_insert(
        &self,
        slug: String,
        state: Arc<VaultState>,
    ) -> Result<Arc<VaultState>, Arc<VaultState>> {
        use std::collections::hash_map::Entry;
        let mut guard = self.inner.write().await;
        match guard.vaults.entry(slug) {
            Entry::Occupied(o) => Err(o.get().clone()),
            Entry::Vacant(v) => Ok(v.insert(state).clone()),
        }
    }

    /// Get a snapshot of a slug if present (read-only check).
    pub async fn get(&self, slug: &str) -> Option<Arc<VaultState>> {
        self.inner.read().await.vaults.get(slug).cloned()
    }

    // ── switch (pointer flip only) ──

    /// Flip the active pointer to `slug` and return the slug's state for the
    /// caller to report. Validates that the slug is present in the map.
    ///
    /// This is the *live focus change*. It does NOT zeroize the previously
    /// active vault and does NOT generate a new session token. The registry
    /// `last_opened` touch is performed by the caller OUTSIDE the host
    /// write lock — no I/O in the critical section.
    ///
    /// Returns `SwitchOutcome` so the caller can branch: if the target is
    /// locked/closed the desktop shows the unlock screen for that slug.
    pub async fn switch(&self, slug: &str) -> Result<SwitchOutcome, SwitchError> {
        let mut guard = self.inner.write().await;
        let Some(state) = guard.vaults.get(slug) else {
            return Err(SwitchError::UnknownSlug(slug.to_string()));
        };
        let state = state.clone();
        guard.active = Some(slug.to_string());
        // Drop guard before the is_unlocked() read so we don't hold the host
        // write lock across an await on the vault's inner lock.
        drop(guard);

        let unlocked = state.is_unlocked().await;
        Ok(SwitchOutcome {
            slug: slug.to_string(),
            presence: if unlocked {
                VaultPresence::Unlocked
            } else {
                VaultPresence::Locked
            },
        })
    }

    /// Persist the active slug in the registry (next-launch default). Does
    /// NOT touch the in-memory `active` pointer; that is `switch`'s job.
    /// Returns an error if the slug is not in the registry.
    pub async fn set_active_registry(&self, slug: &str) -> Result<(), SwitchError> {
        let mut reg = baluard_core::vault::registry::VaultRegistry::load_locked()
            .map_err(|e| SwitchError::Registry(e.to_string()))?;
        reg.set_active(slug)
            .map_err(|_| SwitchError::UnknownSlug(slug.to_string()))?;
        reg.save_locked()
            .map_err(|e| SwitchError::Registry(e.to_string()))?;
        Ok(())
    }

    // ── close (Arc-drain) ──

    /// Remove a vault from the in-memory map. Returns `true` if it was
    /// present. If the closed vault was `active`, `active` is cleared to
    /// `None` in the SAME critical section so it can never dangle.
    ///
    /// In-flight handlers that already cloned the `Arc<VaultState>` drain
    /// to completion naturally and zeroize on their own last drop. We do
    /// NOT track an in-flight counter or block — `Arc::strong_count` is
    /// not used as a synchronization primitive.
    pub async fn close(&self, slug: &str) -> bool {
        let mut guard = self.inner.write().await;
        // Deactivate BEFORE dropping the map entry: the background loop
        // owns an AutoSyncHandle clone, so without this it would keep
        // pulling (and holding the devkey seal) against a closed or
        // deleted vault, and a re-unlock would run a second loop on the
        // same repo.
        if let Some(state) = guard.vaults.get(slug) {
            state.autosync_deactivate().await;
        }
        let removed = guard.vaults.remove(slug).is_some();
        if removed && guard.active.as_deref() == Some(slug) {
            guard.active = None;
        }
        removed
    }

    // ── list ──

    /// Enumerate every registered vault, joining registry entries with the
    /// in-memory map so each row carries its `VaultPresence`. Drives the
    /// desktop vault switcher and `baluard vaults list`.
    pub async fn list(&self) -> Vec<VaultListRow> {
        // Snapshot the map keys + arcs once, then drop the host lock before
        // the per-vault is_unlocked() reads (those acquire the vault's inner
        // read lock — never nest under the host lock).
        let (active, in_map): (Option<String>, HashMap<String, Arc<VaultState>>) = {
            let guard = self.inner.read().await;
            (guard.active.clone(), guard.vaults.clone())
        };

        // Read the registry without holding the host lock.
        let mut reg =
            baluard_core::vault::registry::VaultRegistry::load_locked().unwrap_or_default();

        // Self-heal: if the registry lost entries (e.g. a crash wrote an
        // empty index while vault files are intact), re-discover orphaned
        // vaults from the default vaults directory and persist them so the
        // user never has to know the path or touch a hidden folder.
        if reg.vaults.is_empty() {
            let orphans = reg.discover_orphans();
            if !orphans.is_empty() {
                for entry in orphans {
                    // add() validates the slug + dedupes; ignore a failure on
                    // one entry and keep going (best-effort recovery).
                    let _ = reg.add(entry);
                }
                if reg.save_locked().is_ok() {
                    log::info!(
                        "[host] registry self-healed: recovered {} vault(s) from disk",
                        reg.vaults.len()
                    );
                }
            }
        }

        let mut rows = Vec::with_capacity(reg.vaults.len());
        for entry in reg.vaults.values() {
            let presence = match in_map.get(&entry.slug) {
                Some(state) => {
                    if state.is_unlocked().await {
                        VaultPresence::Unlocked
                    } else {
                        VaultPresence::Locked
                    }
                }
                None => VaultPresence::Closed,
            };
            rows.push(VaultListRow {
                slug: entry.slug.clone(),
                display_name: entry.display_name.clone(),
                presence: presence.as_str(),
                active: active.as_deref() == Some(entry.slug.as_str()),
                provider: entry.provider.clone(),
                last_opened: entry.last_opened,
                // Audit C19: withhold the filesystem path while the vault is
                // not unlocked. Pre-unlock surfaces (login screen, vault
                // switcher on a locked vault) must not reveal where vaults
                // live on disk. The CLI never prints this field; the desktop
                // detach modal shows it only for unlocked vaults.
                path: if matches!(presence, VaultPresence::Unlocked) {
                    entry.path.to_string_lossy().into_owned()
                } else {
                    String::new()
                },
                // Family-spaces §2 classification union: purpose OR
                // flipped shape OR the legacy pair flag. Flag-only would
                // classify every flipped org as personal.
                space: baluard_core::vault::space::is_space(&entry.path),
            });
        }

        // Stable sort by slug for deterministic output.
        rows.sort_by(|a, b| a.slug.cmp(&b.slug));
        rows
    }

    // ── shutdown ──

    /// Lock every open vault (zeroizes all key material). Called from the
    /// daemon's shutdown path before process exit. Returns the number of
    /// vaults it locked.
    pub async fn lock_all(&self) -> usize {
        // Snapshot the arcs once, drop the host lock, then lock each vault.
        let open: Vec<(String, Arc<VaultState>)> = {
            let guard = self.inner.read().await;
            guard
                .vaults
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut locked = 0usize;
        for (_slug, state) in open {
            if state.lock().await.is_ok() {
                locked += 1;
            }
        }
        locked
    }

    /// D79: drain in-flight sync cycles and lock every vault before a desktop
    /// update replaces the binaries. Returns the slugs it locked; the error
    /// names the first vault whose sync cycle did not finish in time.
    pub async fn prepare_for_update(&self) -> Result<Vec<String>, String> {
        // Snapshot the arcs once, drop the host lock, then drain+lock each
        // vault sequentially (same shape as lock_all: never hold the host
        // lock across a vault's cycle/inner locks).
        let open: Vec<(String, Arc<VaultState>)> = {
            let guard = self.inner.read().await;
            guard
                .vaults
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut locked = Vec::new();
        for (slug, state) in open {
            state
                .prepare_for_update()
                .await
                .map_err(|e| format!("{slug}: {e}"))?;
            locked.push(slug);
        }
        Ok(locked)
    }

    /// Lock only the open vaults whose timeout policy is `Immediately`. Called
    /// by the desktop on window blur / minimize so backgrounding the app
    /// honors each vault's own policy instead of unconditionally locking
    /// everything (the old behavior). Returns the number locked. Other
    /// policies (`Minutes`, `OnAppExit`) are left for the idle
    /// walker / app-exit to handle.
    pub async fn lock_blur_vaults(&self) -> Vec<String> {
        use baluard_core::vault::manifest::VaultTimeout;

        // Snapshot the arcs once, drop the host lock, then check each vault's
        // policy + lock (both acquire the vault's inner lock — never nested
        // under the host lock).
        let open: Vec<(String, Arc<VaultState>)> = {
            let guard = self.inner.read().await;
            guard
                .vaults
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut locked_slugs = Vec::new();
        for (slug, state) in open {
            // D80: an active agent grant keeps working through desktop blur.
            if state.has_live_agent_grants() {
                continue;
            }
            if state.timeout_policy().await == VaultTimeout::Immediately
                && state.lock().await.is_ok()
            {
                locked_slugs.push(slug);
            }
        }
        locked_slugs
    }

    /// D80: shared pending approval queue. The daemon owns all transitions;
    /// desktop approval surfaces only read/list and send user decisions.
    pub fn pending_requests(&self) -> &crate::agents::PendingQueue {
        &self.pending
    }

    /// Phase 6 / T15: log the aggregate `mlock` footprint across all open
    /// vaults.
    ///
    /// This is a **fixed key-hierarchy baseline** (a floor), NOT the full
    /// resident footprint: it counts only Root Key (64 B) + Space Group Key
    /// (32 B) per unlocked vault. It excludes transient Item Keys (32 B
    /// each, derived per cipher op and dropped after) AND any resident KEK
    /// / X25519 device private key, both of which may be resident while
    /// unlocked. The number scales linearly with N and is the component
    /// most likely to approach `RLIMIT_MEMLOCK`; treat the real footprint
    /// as strictly higher.
    ///
    /// On Unix we query the soft memlock limit and warn when the baseline
    /// is within 2x of it (older Linux defaults are 64 KB). `mlock` failure
    /// remains best-effort and silent per T6; this log is the legibility
    /// control that makes multi-vault residency visible.
    pub async fn log_mlock_budget(&self) {
        const PER_VAULT_BYTES: usize = 64 + 32;

        // Snapshot the arcs, drop the host lock, then count unlocked vaults
        // (is_unlocked() acquires each vault's inner lock — never nested
        // under the host lock).
        let open: Vec<Arc<VaultState>> = {
            let guard = self.inner.read().await;
            guard.vaults.values().cloned().collect()
        };
        let mut unlocked_count = 0usize;
        for state in &open {
            if state.is_unlocked().await {
                unlocked_count += 1;
            }
        }

        let baseline = unlocked_count * PER_VAULT_BYTES;

        #[cfg(unix)]
        {
            // M5: check getrlimit's return value; on failure log "unknown"
            // instead of the misleading "0 B" (a zeroed struct yields
            // rlim_cur = 0 on failure, which is a valid limit value).
            let rlim_result = unsafe {
                let mut limit: libc::rlimit = std::mem::zeroed();
                let rc = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit);
                (rc, limit.rlim_cur)
            };
            match rlim_result {
                (0, libc::RLIM_INFINITY) => {
                    log::info!(
                        "[host] mlock baseline: {unlocked_count} unlocked vault(s) \
                         = {baseline} B (RootKey+SGK; floor, excludes KEK/device/item keys); \
                         RLIMIT_MEMLOCK = unlimited"
                    );
                }
                (0, rlim) if rlim > 0 => {
                    log::info!(
                        "[host] mlock baseline: {unlocked_count} unlocked vault(s) \
                         = {baseline} B (RootKey+SGK; floor, excludes KEK/device/item keys); \
                         RLIMIT_MEMLOCK = {rlim} B"
                    );
                    // Warn when within 2x of the limit so the user can raise it
                    // (`ulimit -l` / /etc/security/limits.conf) before mlock
                    // starts silently failing for new vaults. rlim is u32 on
                    // 32-bit targets (armv7) and u64 elsewhere; the u128
                    // comparison is a real widening on both, so clippy stays
                    // quiet on either platform.
                    if (baseline as u128) * 2 >= u128::from(rlim) {
                        log::warn!(
                            "[host] mlock baseline within 2x of RLIMIT_MEMLOCK ({rlim} B). \
                             Multi-vault mlock may silently fail; raise the limit \
                             (ulimit -l or /etc/security/limits.conf memlock) for full protection."
                        );
                    }
                }
                _ => {
                    // getrlimit failed OR rlim_cur == 0 (ambiguous). Don't
                    // pretend we know the limit.
                    log::info!(
                        "[host] mlock baseline: {unlocked_count} unlocked vault(s) \
                         = {baseline} B (RootKey+SGK; floor, excludes KEK/device/item keys); \
                         RLIMIT_MEMLOCK = unknown"
                    );
                }
            }
        }
        #[cfg(not(unix))]
        {
            log::info!(
                "[host] mlock baseline: {unlocked_count} unlocked vault(s) \
                 = {baseline} B (RootKey+SGK; floor) (mlock unavailable on this platform)"
            );
        }
    }

    // ── auto-lock ──

    /// Single background task that walks the vault map every 30s and
    /// applies each vault's own `vault_timeout` + `last_activity`.
    ///
    /// Active-pointer-on-autolock policy: when the active vault auto-locks,
    /// `active` is LEFT pointing at it. The next implicit-`active` request
    /// resolves to a locked vault and the handler returns `locked: true`;
    /// the desktop shows a re-unlock prompt for that same vault (not the
    /// vault picker). Only `vaults.close` on the active vault clears
    /// `active` to `None`.
    pub fn spawn_auto_lock_checker(self: &Arc<Self>) {
        let host = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                // Snapshot the active slug + every open arc OUTSIDE the
                // per-vault locks. We never call VaultState::lock() while
                // holding the host write lock — that would serialize all
                // vault-map operations behind each lock.
                let active_slug: Option<String>;
                let open: Vec<(String, Arc<VaultState>)> = {
                    let guard = host.inner.read().await;
                    active_slug = guard.active.clone();
                    guard
                        .vaults
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };

                for (slug, state) in open {
                    if state.should_auto_lock().await {
                        log::info!("[host] auto-lock firing for vault '{slug}'");
                        state.lock().await.ok();
                        // active stays pointed at it; policy is to leave it.
                        if active_slug.as_deref() == Some(slug.as_str()) {
                            log::info!(
                                "[host] active vault '{slug}' auto-locked; \
                                 active pointer left in place (re-unlock UX)"
                            );
                        }
                    }
                }
            }
        });
    }
}

impl Default for VaultHost {
    fn default() -> Self {
        Self::new()
    }
}

// ── types for the wire layer ──

/// Why a request could not be routed to a vault.
#[derive(Debug)]
pub enum SnapshotError {
    /// No explicit slug AND no current active slug.
    NoActive,
    /// A slug was resolved (explicit or active) but is not in the map.
    /// The slug is returned so the handler can branch: show the vault
    /// picker, prompt for password, etc.
    SlugNotOpen(String),
}

/// Result of a successful `vaults.switch`. Carries enough for the caller
/// to know whether to show the unlock screen.
#[derive(Debug, Clone)]
pub struct SwitchOutcome {
    pub slug: String,
    pub presence: VaultPresence,
}

/// Failure modes for `vaults.switch` / `vaults.set_active_registry`.
#[derive(Debug)]
pub enum SwitchError {
    UnknownSlug(String),
    Registry(String),
}

/// One row of `vaults.list`. Serialized to JSON for the wire layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VaultListRow {
    pub slug: String,
    pub display_name: String,
    /// `unlocked` | `locked` | `closed`
    pub presence: &'static str,
    pub active: bool,
    pub provider: Option<String>,
    pub last_opened: Option<u64>,
    /// Vault directory on disk (from the registry entry). Surfaced so the
    /// desktop detach modal can show the user what is about to be removed.
    pub path: String,
    /// S2 IS-5: the vault is a pair Space (shape flag in plaintext
    /// settings-pub.json). Pre-unlock safe: same charter as theme/lang.
    pub space: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn switch_to_unknown_slug_errors() {
        let host = VaultHost::new();
        let err = host.switch("ghost").await.unwrap_err();
        assert!(matches!(err, SwitchError::UnknownSlug(s) if s == "ghost"));
    }

    /// P1c: lock_all must cascade the full chokepoint (generation bump +
    /// token death) across every open vault, and must complete without
    /// holding the host lock across per-vault locks (no deadlock under a
    /// deadline).
    #[tokio::test]
    async fn lock_all_cascades_generation_and_tokens() {
        let host = VaultHost::new();
        for slug in ["alpha", "beta"] {
            let state = Arc::new(VaultState::new(PathBuf::from(format!("/tmp/{slug}"))));
            // Simulate an unlocked session: mint a token at the current
            // generation (same fields the unlock path stamps).
            state.test_mint_session_token(&format!("tok-{slug}")).await;
            host.insert(slug.to_string(), state).await;
        }

        let locked = tokio::time::timeout(std::time::Duration::from_secs(2), host.lock_all())
            .await
            .expect("lock_all must not deadlock");
        assert_eq!(locked, 2, "both open vaults must lock");

        for slug in ["alpha", "beta"] {
            let state = host.get(slug).await.expect("vault still registered");
            assert!(
                state
                    .verify_session_token(&format!("tok-{slug}"))
                    .await
                    .is_err(),
                "token for {slug} must be dead after lock_all"
            );
        }
    }

    #[tokio::test]
    async fn close_clears_the_device_signing_key_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let password = format!("close-cache-pass-{}", std::process::id());
        let handle = baluard_core::vault::creation::VaultCreator::new(&path, &password, "device")
            .execute()
            .unwrap()
            .0;
        let device_id = handle.device_id;
        drop(handle);
        let state = Arc::new(VaultState::new(path.clone()));
        state.unlock(&password).await.unwrap();
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(&path, device_id).is_some(),
            "unlock must warm the cache"
        );
        let host = VaultHost::new();
        host.insert("alpha".into(), state).await;
        assert!(host.close("alpha").await);
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(&path, device_id).is_none(),
            "closing the runtime state must clear its signing key"
        );
    }

    #[tokio::test]
    async fn close_clears_active_in_one_critical_section() {
        let host = VaultHost::new();
        let state = Arc::new(VaultState::new(PathBuf::from("/tmp/x")));
        host.insert("alpha".into(), state).await;
        host.switch("alpha").await.unwrap();
        assert_eq!(host.active_slug().await.as_deref(), Some("alpha"));

        assert!(host.close("alpha").await);
        // Invariant: active must NOT dangle after close.
        assert_eq!(host.active_slug().await, None);
    }

    #[tokio::test]
    async fn resolve_target_slug_prefers_explicit() {
        let host = VaultHost::new();
        let state = Arc::new(VaultState::new(PathBuf::from("/tmp/x")));
        host.insert("alpha".into(), state).await;
        host.switch("alpha").await.unwrap();

        // Explicit slug wins over active.
        assert_eq!(
            host.resolve_target_slug(Some("alpha")).await.as_deref(),
            Some("alpha")
        );
    }

    #[tokio::test]
    async fn snapshot_target_returns_no_active_when_empty() {
        let host = VaultHost::new();
        let err = host
            .snapshot_target(None)
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, SnapshotError::NoActive));
    }

    #[tokio::test]
    async fn snapshot_target_returns_slug_not_open_for_unknown() {
        let host = VaultHost::new();
        let state = Arc::new(VaultState::new(PathBuf::from("/tmp/x")));
        host.insert("alpha".into(), state).await;
        host.switch("alpha").await.unwrap();

        let err = host
            .snapshot_target(Some("ghost"))
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, SnapshotError::SlugNotOpen(s) if s == "ghost"));
    }
}
