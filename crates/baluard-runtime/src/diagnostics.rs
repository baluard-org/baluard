//! Vault diagnostics snapshot: the per-device sync state a user (or a
//! bug report) needs to answer "why does this device show different
//! data". Read-only by construction — every field here is shareable:
//! hashes, ids, counts, and D9's static commit messages. The remote URL
//! is deliberately reduced to its host before it enters the snapshot,
//! because provider credentials ride in some remote URLs.

use crate::autosync::AutoSyncStatus;
use crate::state::VaultState;
use serde::{Deserialize, Serialize};

/// One row of the recent sync-commit log (newest first).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRow {
    #[serde(rename = "oid")]
    pub oid: String,
    /// Unix seconds (display-only; git timestamps skew across devices).
    #[serde(rename = "at")]
    pub at: i64,
    #[serde(rename = "msg")]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    /// One of: no_remote | unfetched | failing | local_pending | behind |
    /// up_to_date | locked.
    #[serde(rename = "verdict")]
    pub verdict: String,
    #[serde(rename = "vaultId")]
    pub vault_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "autosync")]
    pub autosync: AutoSyncStatus,
    #[serde(rename = "hasRemote")]
    pub has_remote: bool,
    /// Host only — never the full URL (tokens ride in some remote URLs).
    #[serde(rename = "remoteHost")]
    pub remote_host: Option<String>,
    #[serde(rename = "headOid")]
    pub head_oid: Option<String>,
    /// Unix seconds of HEAD's committer time.
    #[serde(rename = "headAt")]
    pub head_at: Option<i64>,
    /// origin/main as of this device's last fetch (no network involved).
    #[serde(rename = "upstreamOid")]
    pub upstream_oid: Option<String>,
    #[serde(rename = "ahead")]
    pub ahead: Option<u32>,
    #[serde(rename = "behind")]
    pub behind: Option<u32>,
    #[serde(rename = "staged")]
    pub staged: usize,
    #[serde(rename = "unstaged")]
    pub unstaged: usize,
    #[serde(rename = "commits")]
    pub commits: Vec<CommitRow>,
    // Counts are Option because they need an unlocked vault; the git and
    // autosync state above stay meaningful while locked.
    #[serde(rename = "entries")]
    pub entries: Option<usize>,
    #[serde(rename = "folders")]
    pub folders: Option<usize>,
    #[serde(rename = "tags")]
    pub tags: Option<usize>,
    #[serde(rename = "totp")]
    pub totp: Option<usize>,
    #[serde(rename = "archived")]
    pub archived: Option<usize>,
    #[serde(rename = "trashed")]
    pub trashed: Option<usize>,
    /// Ready-to-copy diagnostic report (English, fixed labels, redacted
    /// by construction).
    #[serde(rename = "report")]
    pub report: String,
}

/// Verdict classifier over plain fields so the priority rules are unit
/// testable without any git fixture.
pub fn classify(
    has_remote: bool,
    upstream_known: bool,
    access_denied_streak: u32,
    dirty_changes: usize,
    ahead: u32,
    behind: u32,
) -> &'static str {
    if !has_remote {
        return "no_remote";
    }
    if !upstream_known {
        return "unfetched";
    }
    if access_denied_streak > 0 {
        return "failing";
    }
    if dirty_changes > 0 || ahead > 0 {
        return "local_pending";
    }
    if behind > 0 {
        return "behind";
    }
    "up_to_date"
}

/// Host-only reduction of a git remote URL. Strips scheme and any
/// user:pass@ prefix; scp-like syntax (host:path) has no scheme to strip.
fn remote_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let end = rest.find(['/', ':']).unwrap_or(rest.len());
    rest[..end].to_string()
}

fn fmt_utc(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn fmt_ago(secs: i64, now: i64) -> String {
    let d = now - secs;
    let (label, unit) = if d < 90 {
        (d.to_string(), "s")
    } else if d < 5400 {
        ((d / 60).to_string(), "m")
    } else if d < 129600 {
        ((d / 3600).to_string(), "h")
    } else {
        ((d / 86400).to_string(), "d")
    };
    format!("{label}{unit} ago")
}

/// The copy-to-clipboard report. English with fixed labels so a bug
/// report reads the same regardless of the reporter's locale.
fn report_text(s: &DiagnosticsSnapshot, slug: &str, now: i64) -> String {
    let mut r = String::new();
    r.push_str("Baluard diagnostic report\n");
    r.push_str(&format!("vault: {slug}\n"));
    r.push_str(&format!("vault id: {}\n", s.vault_id));
    r.push_str(&format!("device: {}\n", s.device_id));
    r.push_str(&format!("verdict: {}\n", s.verdict));
    r.push_str(&format!(
        "autosync: {} ({})\n",
        if s.autosync.active { "on" } else { "off" },
        s.autosync.state.tag()
    ));
    if let Some(ls) = s.autosync.last_sync {
        r.push_str(&format!(
            "last sync: {} ({})\n",
            fmt_utc(ls as i64),
            fmt_ago(ls as i64, now)
        ));
    } else {
        r.push_str("last sync: never\n");
    }
    if !s.has_remote {
        r.push_str("remote: none configured\n");
    } else {
        if let Some(h) = &s.remote_host {
            r.push_str(&format!("remote host: {h}\n"));
        }
        match (&s.head_oid, &s.upstream_oid) {
            (Some(h), Some(u)) => {
                r.push_str(&format!(
                    "head: {} ({})\n",
                    &h[..7.min(h.len())],
                    fmt_ago(s.head_at.unwrap_or(now), now)
                ));
                r.push_str(&format!(
                    "origin/main (last fetch): {}\n",
                    &u[..7.min(u.len())]
                ));
                r.push_str(&format!(
                    "ahead {} / behind {}\n",
                    s.ahead.unwrap_or(0),
                    s.behind.unwrap_or(0)
                ));
            }
            (Some(h), None) => {
                r.push_str(&format!("head: {} (never fetched)\n", &h[..7.min(h.len())]));
            }
            _ => {}
        }
    }
    if s.staged + s.unstaged > 0 {
        r.push_str(&format!(
            "local changes: {} staged, {} unstaged (blocks pulls)\n",
            s.staged, s.unstaged
        ));
    }
    if s.autosync.access_denied_streak > 0 {
        r.push_str(&format!(
            "remote rejections: {} consecutive (auth class)\n",
            s.autosync.access_denied_streak
        ));
    }
    if s.autosync.conflicts_resolved > 0 {
        r.push_str(&format!(
            "conflicts auto-resolved since unlock: {}\n",
            s.autosync.conflicts_resolved
        ));
    }
    let c = |name: &str, v: Option<usize>| match v {
        Some(n) => format!("{name}: {n}\n"),
        None => format!("{name}: (locked)\n"),
    };
    r.push_str(&c("entries", s.entries));
    r.push_str(&c("folders", s.folders));
    r.push_str(&c("tags", s.tags));
    r.push_str(&c("totp", s.totp));
    r.push_str(&c("archived", s.archived));
    r.push_str(&c("trashed", s.trashed));
    if !s.commits.is_empty() {
        r.push_str("recent commits:\n");
        for row in s.commits.iter().take(10) {
            r.push_str(&format!(
                "  {} {} {}\n",
                row.oid,
                fmt_utc(row.at),
                row.message
            ));
        }
    }
    r
}

fn json_len(raw: &str) -> Option<usize> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
}

/// Build the snapshot for an open vault. Counts that need the vault
/// unlocked degrade to None instead of failing the whole snapshot.
pub async fn snapshot(state: &VaultState, slug: &str) -> Result<DiagnosticsSnapshot, String> {
    let device_id = crate::bridge_policy::first_device_id(&state.vault_path);
    let vault_id = state.vault_id_str().await?;
    let autosync = state.autosync.status().await;

    let mut s = DiagnosticsSnapshot {
        verdict: "up_to_date".into(),
        vault_id,
        device_id,
        autosync,
        has_remote: false,
        remote_host: None,
        head_oid: None,
        head_at: None,
        upstream_oid: None,
        ahead: None,
        behind: None,
        staged: 0,
        unstaged: 0,
        commits: Vec::new(),
        entries: None,
        folders: None,
        tags: None,
        totp: None,
        archived: None,
        trashed: None,
        report: String::new(),
    };

    #[cfg(feature = "git-sync")]
    {
        let vault_path = state.vault_path.clone();
        let device = s.device_id.clone();
        let git = tokio::task::spawn_blocking(move || git_state(&vault_path, &device))
            .await
            .map_err(|e| format!("diagnostics join: {e}"))?;
        let (has_remote, host, head, upstream, ahead_behind, dirty, commits) = git?;
        s.has_remote = has_remote;
        s.remote_host = host;
        if let Some((oid, at)) = head {
            s.head_oid = Some(oid);
            s.head_at = Some(at);
        }
        s.upstream_oid = upstream;
        s.ahead = ahead_behind.as_ref().map(|(a, _)| *a);
        s.behind = ahead_behind.as_ref().map(|(_, b)| *b);
        s.staged = dirty.as_ref().map(|d| d.staged).unwrap_or(0);
        s.unstaged = dirty.as_ref().map(|d| d.unstaged).unwrap_or(0);
        s.commits = commits;
    }

    // Counts: each degrades independently.
    s.entries = state.list_cipher_meta().await.ok().map(|m| m.len());
    s.archived = state.list_archived_meta().await.ok().map(|m| m.len());
    s.totp = state.list_totp_meta().await.ok().map(|m| m.len());
    s.trashed = state.list_trash_ids().await.ok().map(|m| m.len());
    s.folders = state
        .list_folders()
        .await
        .ok()
        .as_deref()
        .and_then(json_len);
    s.tags = state.list_tags().await.ok().as_deref().and_then(json_len);

    // A conflict awaiting the user's verdict is its own verdict: the repo is
    // mid-merge and both devices can legitimately differ until it resolves.
    if s.autosync.state == crate::autosync::AutoSyncState::NeedsDecision {
        s.verdict = "needs_decision".into();
        let now = chrono::Utc::now().timestamp();
        s.report = report_text(&s, slug, now);
        return Ok(s);
    }
    let dirty_changes = s.staged + s.unstaged;
    s.verdict = classify(
        s.has_remote,
        s.upstream_oid.is_some(),
        s.autosync.access_denied_streak,
        dirty_changes,
        s.ahead.unwrap_or(0),
        s.behind.unwrap_or(0),
    )
    .into();
    let now = chrono::Utc::now().timestamp();
    s.report = report_text(&s, slug, now);
    Ok(s)
}

/// All git reads in one blocking closure. Errors degrade per-field so a
/// corrupt repo still yields partial diagnostics.
#[cfg(feature = "git-sync")]
type GitState = (
    bool,
    Option<String>,
    Option<(String, i64)>,
    Option<String>,
    Option<(u32, u32)>,
    Option<baluard_core::sync::engine::WorkTreeStatus>,
    Vec<CommitRow>,
);

#[cfg(feature = "git-sync")]
fn git_state(vault_path: &std::path::Path, device_id: &str) -> Result<GitState, String> {
    use baluard_core::sync::engine::SyncEngine;

    let engine = SyncEngine::new(vault_path, device_id, None);
    let repo = match engine.open_repo() {
        Ok(r) => r,
        Err(_) => {
            return Ok((false, None, None, None, None, None, Vec::new()));
        }
    };
    let has_remote = SyncEngine::has_remote(&repo).unwrap_or(false);
    let mut host = None;
    let mut upstream = None;
    let mut ahead_behind = None;
    if let Ok(remote) = repo.find_remote("origin") {
        if let Some(url) = remote.url() {
            host = Some(remote_host(url));
        }
        if let Ok(head) = repo.find_reference("refs/heads/main") {
            if let Ok(up) = repo.find_reference("refs/remotes/origin/main") {
                upstream = up.target().map(|o| o.to_string());
                if let (Some(h), Some(u)) = (head.target(), up.target()) {
                    ahead_behind = repo
                        .graph_ahead_behind(h, u)
                        .ok()
                        .map(|(a, b)| (a as u32, b as u32));
                }
            }
        }
    }
    let head = repo
        .head()
        .ok()
        .and_then(|h| h.peel_to_commit().ok())
        .map(|c| (c.id().to_string(), c.time().seconds()));
    let dirty = engine.status(&repo).ok();
    let commits = engine
        .log(&repo, 20)
        .unwrap_or_default()
        .into_iter()
        .map(|c| CommitRow {
            oid: c.id.chars().take(7).collect(),
            at: c.time,
            message: c.message.trim().to_string(),
        })
        .collect();
    Ok((
        has_remote,
        host,
        head,
        upstream,
        ahead_behind,
        dirty,
        commits,
    ))
}

#[cfg(all(test, feature = "git-sync"))]
mod tests {
    use super::*;

    #[test]
    fn classifier_priority_matches_support_needs() {
        // No remote beats everything.
        assert_eq!(classify(false, false, 0, 0, 0, 0), "no_remote");
        // Remote configured but never fetched.
        assert_eq!(classify(true, false, 0, 0, 0, 0), "unfetched");
        // Auth failures outrank a behind head: the reason matters most.
        assert_eq!(classify(true, true, 2, 0, 0, 4), "failing");
        // Uncommitted changes block pulls even when behind.
        assert_eq!(classify(true, true, 0, 1, 0, 4), "local_pending");
        // Local commits not pushed are also pending sync.
        assert_eq!(classify(true, true, 0, 0, 2, 0), "local_pending");
        assert_eq!(classify(true, true, 0, 0, 0, 3), "behind");
        assert_eq!(classify(true, true, 0, 0, 0, 0), "up_to_date");
    }

    #[test]
    fn remote_host_never_leaks_credentials() {
        assert_eq!(
            remote_host("https://user:ghp_token123@github.com/x/y.git"),
            "github.com"
        );
        assert_eq!(remote_host("git@github.com:x/y.git"), "github.com");
        assert_eq!(remote_host("https://gitlab.com/x/y.git"), "gitlab.com");
        assert_eq!(
            remote_host("ssh://git@example.com:2222/x/y.git"),
            "example.com"
        );
    }

    #[tokio::test]
    async fn snapshot_on_a_fresh_vault_reports_no_remote_and_counts() {
        let sb = crate::test_support::lock_env();
        let _ = &sb;
        let dir = tempfile::tempdir().unwrap();
        let vpath = dir.path().join("v");
        let password = format!("diag-pass-{}", std::process::id());
        let handle = baluard_core::vault::creation::VaultCreator::new(&vpath, &password, "device")
            .execute()
            .unwrap()
            .0;
        let state = std::sync::Arc::new(crate::VaultState::new(handle.path.clone()));
        state.unlock(&password).await.unwrap();

        state
            .add_cipher(r#"{"name":"Site","type":1}"#)
            .await
            .unwrap();

        let snap = snapshot(&state, "diag").await.unwrap();
        assert_eq!(snap.verdict, "no_remote");
        assert!(!snap.has_remote);
        assert_eq!(snap.entries, Some(1));
        assert_eq!(snap.remote_host, None);
        assert!(!snap.vault_id.is_empty());
        assert!(!snap.device_id.is_empty());
        assert!(snap.report.contains("remote: none configured"));
        assert!(snap.report.contains("entries: 1"));
        assert!(!snap.report.contains("https://"));
    }

    #[test]
    fn report_stays_within_the_shareable_field_set() {
        let s = DiagnosticsSnapshot {
            verdict: "behind".into(),
            vault_id: "0f0e0d0c-1111-2222-3333-444455556666".into(),
            device_id: "dev123".into(),
            autosync: AutoSyncStatus {
                active: true,
                state: crate::autosync::AutoSyncState::Offline,
                last_sync: Some(1_700_000_000),
                pending: 0,
                conflicts_resolved: 1,
                access_denied_streak: 0,
            },
            has_remote: true,
            remote_host: Some("github.com".into()),
            head_oid: Some("a".repeat(40)),
            head_at: Some(1_700_000_100),
            upstream_oid: Some("b".repeat(40)),
            ahead: Some(0),
            behind: Some(2),
            staged: 0,
            unstaged: 0,
            commits: vec![CommitRow {
                oid: "abc1234".into(),
                at: 1_700_000_000,
                message: "vault update".into(),
            }],
            entries: Some(12),
            folders: Some(2),
            tags: Some(0),
            totp: Some(1),
            archived: Some(0),
            trashed: Some(3),
            report: String::new(),
        };
        let text = report_text(&s, "personal", 1_700_010_000);
        // Safe by construction: hashes, ids, counts, static messages.
        assert!(text.contains("head: aaaaaaa"));
        assert!(text.contains("behind 2"));
        assert!(text.contains("entries: 12"));
        // Nothing that could carry secrets or user content.
        assert!(!text.contains("https://"));
        assert!(!text.contains("github.com/x"));
        assert!(!text.contains("token"));
        assert_eq!(
            text.lines().last().unwrap().trim(),
            "abc1234 2023-11-14 22:13 UTC vault update"
        );
    }
}
