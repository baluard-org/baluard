//! Batch favicon backfill for imported vaults.
//!
//! Icon fetching normally happens at entry save time, so imported entries
//! have none. This job walks the ACTIVE vault, fetches a missing icon per
//! login (one by one, sequential), and writes them back. Safeguards:
//!
//! - Hard opt-in: refuses unless settings.fetch_favicons is true.
//! - 2s per-entry budget: slow or dead sites are skipped, never stall the
//!   run; every fetch runs OUTSIDE the vault locks.
//! - Same-domain dedup: one fetch serves every login on that domain.
//! - The same SSRF and DNS guards as favicon.get gate every entry.
//! - Cooperative cancel, polled progress, and an abort when the vault
//!   changes or locks mid-run. One job at a time per daemon.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::state::{SharedVaultState, VaultState};

/// Per-entry fetch budget. Sites slower than this are skipped.
const ENTRY_BUDGET_SECS: u64 = 2;

#[derive(Debug, Clone, Serialize, Default)]
pub struct BackfillProgress {
    pub running: bool,
    pub finished: bool,
    pub total: usize,
    pub done: usize,
    pub fetched: usize,
    pub skipped: usize,
    pub current_domain: Option<String>,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct IconBackfillJob {
    cancel: AtomicBool,
    progress: Mutex<BackfillProgress>,
}

impl IconBackfillJob {
    fn snapshot(&self) -> BackfillProgress {
        self.progress
            .lock()
            .expect("backfill progress poisoned")
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut BackfillProgress)) {
        let mut p = self.progress.lock().expect("backfill progress poisoned");
        f(&mut p);
    }
}

/// One work item: the first cipher claims the fetch; every cipher on the
/// same domain receives the icon without a second fetch.
struct BackfillTarget {
    cipher_ids: Vec<Uuid>,
    domain: String,
}

/// Pure work-list builder, split out for tests: logins without a favicon
/// whose first fetchable URI yields a domain, deduped by domain in
/// first-seen order.
fn build_targets<'a>(
    items: impl IntoIterator<Item = (&'a Uuid, &'a baluard_core::types::CipherKind)>,
) -> Vec<BackfillTarget> {
    let mut targets: Vec<BackfillTarget> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (id, kind) in items {
        let baluard_core::types::CipherKind::Login(login) = kind else {
            continue;
        };
        if login.favicon.is_some() {
            continue;
        }
        let domain = login
            .uris
            .iter()
            .map(|u| VaultState::extract_domain(u.uri.trim()))
            .find(|d| !d.is_empty() && VaultState::host_fetchable_str(d));
        let Some(domain) = domain else { continue };
        if let Some(&i) = index.get(&domain) {
            targets[i].cipher_ids.push(*id);
        } else {
            index.insert(domain.clone(), targets.len());
            targets.push(BackfillTarget {
                cipher_ids: vec![*id],
                domain,
            });
        }
    }
    targets
}

/// Validate, snapshot the work list, and spawn the job. Returns the initial
/// status JSON so the caller can render it immediately.
pub async fn start(state: &SharedVaultState) -> Result<String, String> {
    {
        let guard = state.inner.read().await;
        let Some(handle) = guard.as_ref() else {
            return Err("Vault is locked. Unlock first.".into());
        };
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        if !matches!(settings.fetch_favicons, Some(true)) {
            return Err(
                "Fetching site icons is turned off. Enable \"Show website icons\" in Settings first."
                    .into(),
            );
        }
    }

    if state
        .icon_backfill
        .progress
        .lock()
        .expect("backfill progress poisoned")
        .running
    {
        return Err("An icon fetch is already running.".into());
    }

    // Snapshot under a read lock: cipher reads need decryption, so the
    // vault must stay unlocked for the duration of this call.
    let (vault_id, targets) = {
        let guard = state.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked. Unlock first.")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let mut items = Vec::new();
        for id in handle.list_cipher_ids().map_err(|e| format!("{e}"))? {
            if let Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) = handle.get_cipher(id)
            {
                items.push((id, *c));
            }
        }
        (
            handle.vault_id,
            build_targets(items.iter().map(|(id, c)| (id, &c.kind))),
        )
    };

    let total = targets.len();
    state.icon_backfill.cancel.store(false, Ordering::SeqCst);
    state.icon_backfill.update(|p| {
        *p = BackfillProgress {
            running: true,
            finished: false,
            total,
            ..Default::default()
        };
    });

    let job_state = state.clone();
    tokio::spawn(async move {
        run(job_state, targets, vault_id).await;
    });

    Ok(serde_json::to_string(&state.icon_backfill.snapshot()).unwrap_or_default())
}

pub fn cancel(state: &SharedVaultState) {
    state.icon_backfill.cancel.store(true, Ordering::SeqCst);
}

pub fn status(state: &SharedVaultState) -> String {
    serde_json::to_string(&state.icon_backfill.snapshot()).unwrap_or_default()
}

async fn run(state: SharedVaultState, targets: Vec<BackfillTarget>, vault_id: Uuid) {
    let client = match VaultState::build_icon_client() {
        Some(c) => c,
        None => {
            finish(&state, "Could not initialize the network client.");
            return;
        }
    };

    let mut applied_any = false;
    for target in &targets {
        if state.icon_backfill.cancel.load(Ordering::SeqCst) {
            finish(&state, "Cancelled.");
            return;
        }
        state
            .icon_backfill
            .update(|p| p.current_domain = Some(target.domain.clone()));

        let fetch = fetch_domain(&client, &target.domain);
        let icon_json =
            match tokio::time::timeout(Duration::from_secs(ENTRY_BUDGET_SECS), fetch).await {
                Ok(Ok(Some(json))) => json,
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                    state.icon_backfill.update(|p| {
                        p.done += 1;
                        p.skipped += 1;
                    });
                    continue;
                }
            };

        // crawl_site_icon returns the same base64 JSON envelope as the
        // favicon.get route: {"data": "...", "mime": "..."}. A malformed
        // payload counts as a skip, not a job failure.
        let favicon = serde_json::from_str::<baluard_core::types::FaviconData>(&icon_json);
        let favicon = match favicon {
            Ok(f) if !f.data.is_empty() => f,
            _ => {
                state.icon_backfill.update(|p| {
                    p.done += 1;
                    p.skipped += 1;
                });
                continue;
            }
        };

        match apply_icon(&state, vault_id, &target.cipher_ids, favicon).await {
            Ok(count) => {
                applied_any = applied_any || count > 0;
                state.icon_backfill.update(|p| {
                    p.done += 1;
                    p.fetched += count;
                });
            }
            Err(e) => {
                // Vault locked, switched, or a write failed mid-run: stop
                // rather than keep fetching for a vault we can no longer
                // write to.
                finish(&state, &e);
                return;
            }
        }
    }

    if applied_any {
        let mut guard = state.inner.write().await;
        if let Some(handle) = guard.as_mut() {
            let _ = handle.rebuild_tag_index();
        }
    }
    finish(&state, "");
}

async fn fetch_domain(client: &reqwest::Client, domain: &str) -> Result<Option<String>, String> {
    // Same guards as the one-shot route, re-run per entry: the snapshot
    // happened earlier and the world may have changed.
    if !VaultState::host_fetchable_str(domain) || !VaultState::host_resolves_public(domain).await {
        return Ok(None);
    }
    Ok(VaultState::crawl_site_icon(client, domain).await)
}

/// Write the fetched icon onto every cipher in the target group. Returns
/// the number of entries updated; a vault-state problem aborts the job.
async fn apply_icon(
    state: &SharedVaultState,
    vault_id: Uuid,
    cipher_ids: &[Uuid],
    icon: baluard_core::types::FaviconData,
) -> Result<usize, String> {
    let mut guard = state.inner.write().await;
    let Some(handle) = guard.as_mut() else {
        return Err("Vault is locked. Unlock first.".into());
    };
    if !handle.is_unlocked() {
        return Err("Vault is locked. Unlock first.".into());
    }
    if handle.vault_id != vault_id {
        return Err("The active vault changed during the fetch.".into());
    }

    let mut count = 0;
    for id in cipher_ids {
        let Ok(baluard_core::vault::handle::CipherRead::Decrypted(mut cipher)) =
            handle.get_cipher(*id)
        else {
            continue;
        };
        let baluard_core::types::CipherKind::Login(ref mut login) = cipher.kind else {
            continue;
        };
        if login.favicon.is_some() {
            continue;
        }
        login.favicon = Some(icon.clone());
        let input = baluard_core::types::CipherInput {
            name: cipher.name.clone(),
            folder_id: cipher.folder_id,
            collection_id: None,
            kind: cipher.kind.clone(),
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            notes: cipher.notes.clone(),
            custom_fields: cipher.custom_fields.clone(),
            created_at: Some(cipher.created_at),
            password_history: cipher.password_history.clone(),
            attachments: cipher.attachments.clone(),
            archived: cipher.archived,
            tags: cipher.tags.clone(),
        };
        handle
            .update_cipher(*id, &input)
            .map_err(|e| format!("{e}"))?;
        count += 1;
    }
    Ok(count)
}

fn finish(state: &SharedVaultState, error: &str) {
    state.icon_backfill.update(|p| {
        p.running = false;
        p.finished = true;
        p.current_domain = None;
        p.error = (!error.is_empty()).then(|| error.to_string());
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use baluard_core::types::{CipherKind, LoginData, LoginUri, UriMatchStrategy};

    fn login(uris: &[&str], favicon: Option<baluard_core::types::FaviconData>) -> CipherKind {
        CipherKind::Login(LoginData {
            uris: uris
                .iter()
                .map(|u| LoginUri {
                    uri: (*u).to_string(),
                    match_strategy: UriMatchStrategy::default(),
                })
                .collect(),
            favicon,
            ..Default::default()
        })
    }

    #[test]
    fn build_targets_dedups_domains_and_skips_covered_entries() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();
        let e = Uuid::new_v4();
        let items = vec![
            (a, login(&["https://github.com/x"], None)),
            (
                b,
                login(&["https://api.github.com/y", "https://github.com/z"], None),
            ),
            // Already has an icon: never a target, even same domain.
            (
                c,
                login(
                    &["https://github.com/w"],
                    Some(baluard_core::types::FaviconData {
                        data: "AA".into(),
                        mime: "image/png".into(),
                    }),
                ),
            ),
            // Non-login kinds are skipped outright.
            (d, CipherKind::SecureNote),
            // Localhost-style and non-http hosts are not fetchable.
            (e, login(&["http://localhost:8080/panel"], None)),
        ];
        // Dedup is per exact host (same semantics as the save-time fetch):
        // github.com and api.github.com are separate targets, but two
        // entries on the SAME host share one fetch.
        let t = build_targets(items.iter().map(|(id, k)| (id, k)));
        assert_eq!(t.len(), 2, "localhost is refused; subdomains stay separate");
        assert_eq!(t[0].domain, "github.com");
        assert_eq!(t[0].cipher_ids, vec![a]);
        assert_eq!(t[1].domain, "api.github.com");
        assert_eq!(t[1].cipher_ids, vec![b]);
    }

    #[test]
    fn build_targets_orders_domains_by_first_seen() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let items = vec![
            (a, login(&["https://gitlab.com/x"], None)),
            (b, login(&["https://example.com/y"], None)),
        ];
        let t = build_targets(items.iter().map(|(id, k)| (id, k)));
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].domain, "gitlab.com");
        assert_eq!(t[1].domain, "example.com");
    }

    /// The start gate refuses closed: no vault, or favicons off.
    #[tokio::test]
    async fn start_refuses_locked_and_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let state: SharedVaultState =
            std::sync::Arc::new(VaultState::new(dir.path().to_path_buf()));
        let err = start(&state).await.unwrap_err();
        assert!(err.contains("locked"), "got: {err}");

        if baluard_core::keyring_disabled() {
            return;
        }
        state
            .create_vault(r#"{"password":"icon-backfill-test-pw","profile":"mobile_low"}"#)
            .await
            .unwrap();
        let err = start(&state).await.unwrap_err();
        assert!(
            err.contains("Show website icons"),
            "must name the setting; got: {err}"
        );
    }

    /// Enabled flag + nothing to do: the job spawns, reports total 0 and
    /// finishes clean without touching the network.
    #[tokio::test]
    async fn start_with_zero_targets_finishes_clean() {
        if baluard_core::keyring_disabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let state: SharedVaultState =
            std::sync::Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(r#"{"password":"icon-backfill-test-pw","profile":"mobile_low"}"#)
            .await
            .unwrap();
        state
            .settings_set(r#"{"fetch_favicons":true}"#)
            .await
            .unwrap();

        let s: serde_json::Value = serde_json::from_str(&start(&state).await.unwrap()).unwrap();
        assert_eq!(s["total"], 0);

        // The spawned run drains instantly; poll the status to finished.
        for _ in 0..50 {
            let st: serde_json::Value = serde_json::from_str(&status(&state)).unwrap();
            if st["finished"] == true {
                assert_eq!(st["running"], false);
                assert_eq!(st["fetched"], 0);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("job never finished");
    }

    /// apply_icon writes onto every same-domain entry, skips entries that
    /// already carry an icon, and leaves other kinds untouched.
    #[tokio::test]
    async fn apply_icon_covers_the_domain_group() {
        if baluard_core::keyring_disabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let state: SharedVaultState =
            std::sync::Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(r#"{"password":"icon-backfill-test-pw","profile":"mobile_low"}"#)
            .await
            .unwrap();

        let id1 = state
            .add_cipher(
                r#"{"name":"GH1","kind":{"type":"login","data":{"username":"u","uris":[{"uri":"https://github.com/a","matchStrategy":"default"}]}}}"#,
            )
            .await
            .unwrap();
        let id2 = state
            .add_cipher(
                r#"{"name":"GH2","kind":{"type":"login","data":{"username":"u","uris":[{"uri":"https://github.com/b","matchStrategy":"default"}]}}}"#,
            )
            .await
            .unwrap();
        // Same-shape login on another domain: the group must not leak.
        let other = state
            .add_cipher(
                r#"{"name":"GL","kind":{"type":"login","data":{"username":"u","uris":[{"uri":"https://gitlab.com/a","matchStrategy":"default"}]}}}"#,
            )
            .await
            .unwrap();

        let vault_id = {
            let guard = state.inner.read().await;
            guard.as_ref().unwrap().vault_id
        };
        let icon = baluard_core::types::FaviconData {
            data: "AAEC".into(),
            mime: "image/png".into(),
        };
        let ids = vec![
            Uuid::parse_str(&id1).unwrap(),
            Uuid::parse_str(&id2).unwrap(),
        ];
        let n = apply_icon(&state, vault_id, &ids, icon).await.unwrap();
        assert_eq!(n, 2);

        async fn fav_of(state: &SharedVaultState, id: &str) -> Option<String> {
            let guard = state.inner.read().await;
            let handle = guard.as_ref().unwrap();
            match handle.get_cipher(Uuid::parse_str(id).unwrap()).unwrap() {
                baluard_core::vault::handle::CipherRead::Decrypted(c) => match &c.kind {
                    CipherKind::Login(l) => l.favicon.as_ref().map(|f| f.data.clone()),
                    _ => None,
                },
                _ => None,
            }
        }
        assert_eq!(fav_of(&state, &id1).await.as_deref(), Some("AAEC"));
        assert_eq!(fav_of(&state, &id2).await.as_deref(), Some("AAEC"));
        assert_eq!(fav_of(&state, &other).await, None, "group is domain-scoped");

        // Idempotency: a re-apply touches nothing.
        let icon2 = baluard_core::types::FaviconData {
            data: "FFFF".into(),
            mime: "image/png".into(),
        };
        let n2 = apply_icon(&state, vault_id, &ids, icon2).await.unwrap();
        assert_eq!(n2, 0);
        assert_eq!(fav_of(&state, &id1).await.as_deref(), Some("AAEC"));
    }
}
