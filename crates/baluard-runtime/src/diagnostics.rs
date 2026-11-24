//! Vault diagnostics snapshot: the per-device sync state a user (or a
//! bug report) needs to answer "why does this device show different
//! data". Read-only by construction — the repo is opened without the
//! sync engine's side effects, and every field here is shareable:
//! hashes, ids, counts, and sanitized commit subjects. The remote URL is
//! deliberately reduced to its host before it enters the snapshot,
//! because provider credentials ride in some remote URLs.
//!
//! Commit messages are NOT trusted as a static-string invariant: peers
//! can push arbitrary messages, so they are sanitized to a bounded
//! single-line ASCII subject before display.

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
    /// up_to_date | needs_decision. Clients map anything else to a
    /// generic "unknown" string (the runtime never emits "locked": the
    /// daemon route requires an unlocked vault and counts degrade
    /// independently otherwise).
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
    /// None when the URL has no parseable host (fail closed).
    #[serde(rename = "remoteHost")]
    pub remote_host: Option<String>,
    /// Resolved remote branch (defaults to "main" when undetectable).
    #[serde(rename = "branch")]
    pub branch: String,
    #[serde(rename = "headOid")]
    pub head_oid: Option<String>,
    /// Unix seconds of HEAD's committer time.
    #[serde(rename = "headAt")]
    pub head_at: Option<i64>,
    /// Remote branch tip as of this device's last fetch (no network).
    #[serde(rename = "upstreamOid")]
    pub upstream_oid: Option<String>,
    /// Unix seconds of the upstream tip's committer time: how stale the
    /// last fetch is, so "up to date" is always qualified by a date.
    #[serde(rename = "upstreamAt")]
    pub upstream_at: Option<i64>,
    #[serde(rename = "ahead")]
    pub ahead: Option<u32>,
    #[serde(rename = "behind")]
    pub behind: Option<u32>,
    #[serde(rename = "staged")]
    pub staged: usize,
    #[serde(rename = "unstaged")]
    pub unstaged: usize,
    /// Envelopes this device holds untracked that the last-known remote
    /// attachment line lacks (offline pin comparison, no network). None
    /// when the repo could not be read. A plain sync clears it: the push
    /// publishes the blobs and advances the tracking ref it compares
    /// against.
    #[serde(rename = "unpublishedAttachments")]
    pub unpublished_attachments: Option<usize>,
    /// Names of the pending local files behind the staged/unstaged
    /// counts, capped at 10 with an "(and N more)" marker, None when the
    /// repo could not be read. Diagnostic aid: turns "1 unstaged" into
    /// the file to look at.
    #[serde(rename = "dirtyPaths")]
    pub dirty_paths: Option<Vec<String>>,
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
    /// No usable unlock session right now: the counts above are None and
    /// everything below stays meaningful. Defensive only — the daemon
    /// route refuses locked vaults upstream and mobile gates Settings on
    /// an unlocked vault, so no client reads this today.
    #[serde(rename = "locked")]
    pub locked: bool,
    /// Baluard core version (workspace version) + on-disk envelope
    /// format. Version skew between devices is a prime suspect when
    /// machines disagree on contents.
    #[serde(rename = "coreVersion")]
    pub core_version: String,
    #[serde(rename = "formatVersion")]
    pub format_version: u8,
    #[serde(rename = "os")]
    pub os: String,
    #[serde(rename = "arch")]
    pub arch: String,
    /// Linux distro pretty name; None elsewhere (the client header
    /// covers Windows/macOS/Android).
    #[serde(rename = "osVersion")]
    pub os_version: Option<String>,
    /// Cipher/trash blob counts read straight from the HEAD tree: the
    /// ground truth that arbitrates "different item counts" against any
    /// local index or meta-cache drift, independent of the live meta
    /// lists. Works while locked. headCiphers counts every blob under
    /// ciphers/ including archived entries (archiving is a meta flag,
    /// the blob stays), so the comparable meta figure is
    /// entries + archived, not entries alone. None = the tree read
    /// failed; Some(0) is a real empty vault.
    #[serde(rename = "headCiphers")]
    pub head_ciphers: Option<u64>,
    #[serde(rename = "headTrash")]
    pub head_trash: Option<u64>,
    /// Kit-recovery signer file present: the device signs commits under
    /// the kit key until its first push, and peers verify against the
    /// kit file's verifier key in the meantime.
    #[serde(rename = "kitSignerFile")]
    pub kit_signer_file: bool,
    /// Last failed autosync cycle (scrubbed) and when. Cleared by any
    /// success: the reason a silently-stalled vault stopped syncing.
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
    #[serde(rename = "lastErrorAt")]
    pub last_error_at: Option<i64>,
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
    unpublished_attachments: usize,
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
    if dirty_changes > 0 || ahead > 0 || unpublished_attachments > 0 {
        return "local_pending";
    }
    if behind > 0 {
        return "behind";
    }
    "up_to_date"
}

/// Host-only reduction of a git remote URL, fail-closed: None unless a
/// clean hostname survives the parse. Handles scheme'd URLs, scp-like
/// host:path syntax, user:pass@ prefixes, ports, and bracketed IPv6.
fn remote_host(url: &str) -> Option<String> {
    let authority = match url.split_once("://") {
        Some((_, rest)) => rest.split(['/', '?', '#']).next()?,
        // scp-like or bare path: split on '/' first, then treat ':' as the
        // scp separator. A single-letter "host" is a Windows drive path
        // (C:\repo), not a hostname — refuse.
        None => {
            let first = url.split('/').next()?;
            let (h, _) = first.split_once(':')?;
            if h.len() <= 1 {
                return None;
            }
            h
        }
    };
    let hp = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hp.strip_prefix('[') {
        v6.split(']').next()?.to_string()
    } else {
        match hp.split_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
            // A ':' whose tail is not a port means the split hit a path or
            // password containing '/'; refuse rather than guess.
            Some(_) => return None,
            None => hp.to_string(),
        }
    };
    let clean = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    clean.then_some(host)
}

/// Peer-authored commit messages are arbitrary bytes: reduce to a
/// bounded single-line ASCII subject so a forged message cannot add
/// report lines ("x\nverdict: up_to_date") or carry junk.
fn display_safe(raw: &str) -> String {
    let s: String = raw
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(48)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        "(none)".into()
    } else {
        s.to_string()
    }
}

fn fmt_utc(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn fmt_ago(secs: i64, now: i64) -> String {
    let d = (now - secs).max(0);
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

fn short(oid: &str) -> String {
    oid.chars().take(7).collect()
}

/// The copy-to-clipboard report. English with fixed labels so a bug
/// report reads the same regardless of the reporter's locale.
fn report_text(s: &DiagnosticsSnapshot, now: i64) -> String {
    let mut r = String::new();
    r.push_str("Baluard diagnostic report\n");
    r.push_str(&format!("vault id: {}\n", s.vault_id));
    r.push_str(&format!("device: {}\n", s.device_id));
    r.push_str(&format!(
        "vault format: {} (core {})\n",
        s.format_version, s.core_version
    ));
    r.push_str(&match &s.os_version {
        Some(v) => format!("os: {} {} ({v})\n", s.os, s.arch),
        None => format!("os: {} {}\n", s.os, s.arch),
    });
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
        match &s.remote_host {
            Some(h) => r.push_str(&format!("remote host: {h}\n")),
            None => r.push_str("remote host: (not a hostname)\n"),
        }
        match (&s.head_oid, &s.upstream_oid) {
            (Some(h), Some(u)) => {
                r.push_str(&format!(
                    "head: {} ({})\n",
                    short(h),
                    fmt_ago(s.head_at.unwrap_or(now), now)
                ));
                let tip = s
                    .upstream_at
                    .map(|a| format!(", tip committed {}", fmt_ago(a, now)))
                    .unwrap_or_default();
                r.push_str(&format!(
                    "origin/{} (as of last fetch): {}{}\n",
                    s.branch,
                    short(u),
                    tip
                ));
                r.push_str(&format!(
                    "ahead {} / behind {}\n",
                    s.ahead.unwrap_or(0),
                    s.behind.unwrap_or(0)
                ));
            }
            (Some(h), None) => {
                r.push_str(&format!("head: {} (never fetched)\n", short(h)));
            }
            _ => {}
        }
    }
    if s.staged + s.unstaged > 0 {
        r.push_str(&format!(
            "local changes: {} staged, {} unstaged\n",
            s.staged, s.unstaged
        ));
    }
    if let Some(count) = s.unpublished_attachments.filter(|&c| c > 0) {
        r.push_str(&format!(
            "unpublished attachments: {count} (run a sync to publish)\n"
        ));
    }
    if let Some(paths) = s.dirty_paths.as_deref().filter(|p| !p.is_empty()) {
        r.push_str(&format!("dirty paths: {}\n", paths.join(", ")));
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
    if let Some((c, t)) = s.head_ciphers.zip(s.head_trash) {
        r.push_str(&format!("head tree: {c} ciphers, {t} trash\n"));
    }
    if let Some((msg, at)) = s.last_error.as_ref().zip(s.last_error_at) {
        r.push_str(&format!("last cycle error: {msg} ({})\n", fmt_ago(at, now)));
    }
    if s.kit_signer_file {
        r.push_str(
            "kit signer file: present (device signs under the kit key until its first push)\n",
        );
    }
    let c = |name: &str, v: Option<usize>| match v {
        Some(n) => format!("{name}: {n}\n"),
        None => format!("{name}: (unavailable)\n"),
    };
    if s.locked {
        r.push_str("counts: unavailable (vault locked; unlock and regenerate the report)\n");
    } else {
        r.push_str(&c("entries", s.entries));
        r.push_str(&c("folders", s.folders));
        r.push_str(&c("tags", s.tags));
        r.push_str(&c("totp", s.totp));
        r.push_str(&c("archived", s.archived));
        r.push_str(&c("trashed", s.trashed));
    }
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
pub async fn snapshot(state: &VaultState) -> Result<DiagnosticsSnapshot, String> {
    let device_id = crate::bridge_policy::first_device_id(&state.vault_path);
    let vault_id = state.vault_id_str().await?;
    let autosync = state.autosync.status().await;
    let last_err = state.autosync.last_error().await;

    let mut s = DiagnosticsSnapshot {
        verdict: "up_to_date".into(),
        vault_id,
        // An unreadable device id prints as "unknown" instead of blank.
        device_id: {
            let d = device_id;
            if d.is_empty() { "unknown".into() } else { d }
        },
        autosync,
        has_remote: false,
        remote_host: None,
        branch: "main".into(),
        head_oid: None,
        head_at: None,
        upstream_oid: None,
        upstream_at: None,
        ahead: None,
        behind: None,
        staged: 0,
        unstaged: 0,
        unpublished_attachments: None,
        dirty_paths: None,
        commits: Vec::new(),
        entries: None,
        folders: None,
        tags: None,
        totp: None,
        archived: None,
        trashed: None,
        locked: !state.is_unlocked().await,
        core_version: env!("CARGO_PKG_VERSION").into(),
        format_version: baluard_core::BALUARD_VERSION,
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        os_version: os_version(),
        head_ciphers: None,
        head_trash: None,
        kit_signer_file: state.vault_path.join("meta/recovery-signer.key").exists(),
        last_error: last_err.as_ref().map(|(m, _)| m.clone()),
        last_error_at: last_err.as_ref().map(|(_, t)| *t),
        report: String::new(),
    };

    #[cfg(feature = "git-sync")]
    {
        let vault_path = state.vault_path.clone();
        let device = s.device_id.clone();
        let git = tokio::task::spawn_blocking(move || git_state(&vault_path, &device))
            .await
            .map_err(|e| format!("diagnostics join: {e}"))?;
        let (
            has_remote,
            host,
            branch,
            head,
            upstream,
            ahead_behind,
            dirty,
            unpublished,
            dirty_paths,
            commits,
            tree_counts,
        ) = git;
        s.has_remote = has_remote;
        s.remote_host = host;
        if !branch.is_empty() {
            s.branch = branch;
        }
        if let Some((oid, at)) = head {
            s.head_oid = Some(oid);
            s.head_at = Some(at);
        }
        if let Some((oid, at)) = upstream {
            s.upstream_oid = Some(oid);
            s.upstream_at = at;
        }
        s.ahead = ahead_behind.as_ref().map(|(a, _)| *a);
        s.behind = ahead_behind.as_ref().map(|(_, b)| *b);
        s.staged = dirty.as_ref().map(|d| d.staged).unwrap_or(0);
        s.unstaged = dirty.as_ref().map(|d| d.unstaged).unwrap_or(0);
        s.unpublished_attachments = unpublished;
        s.dirty_paths = dirty_paths;
        s.commits = commits;
        if let Some((c, t)) = tree_counts {
            s.head_ciphers = c;
            s.head_trash = t;
        }
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
        s.report = report_text(&s, now);
        return Ok(s);
    }
    // A cycle in flight legitimately leaves the tree half-staged; that
    // transient must not read as local_pending.
    let dirty_changes = if s.autosync.state == crate::autosync::AutoSyncState::Syncing {
        0
    } else {
        s.staged + s.unstaged
    };
    s.verdict = classify(
        s.has_remote,
        s.upstream_oid.is_some(),
        s.autosync.access_denied_streak,
        dirty_changes,
        s.ahead.unwrap_or(0),
        s.behind.unwrap_or(0),
        s.unpublished_attachments.unwrap_or(0),
    )
    .into();
    let now = chrono::Utc::now().timestamp();
    s.report = report_text(&s, now);
    Ok(s)
}

/// All git reads in one blocking closure. Every field degrades
/// independently so a corrupt repo still yields partial diagnostics.
///
/// Opens the repo directly (not via SyncEngine::open_repo, which writes
/// .gitignore/config/index as repair side effects and could flip the
/// dirty counts mid-snapshot).
#[cfg(feature = "git-sync")]
type GitState = (
    bool,
    Option<String>,
    String,
    Option<(String, i64)>,
    Option<(String, Option<i64>)>,
    Option<(u32, u32)>,
    Option<baluard_core::sync::engine::WorkTreeStatus>,
    Option<usize>,
    Option<Vec<String>>,
    Vec<CommitRow>,
    Option<(Option<u64>, Option<u64>)>,
);

#[cfg(feature = "git-sync")]
fn git_state(vault_path: &std::path::Path, device_id: &str) -> GitState {
    use baluard_core::sync::engine::SyncEngine;

    let repo = match git2::Repository::open(vault_path) {
        Ok(r) => r,
        Err(_) => {
            return (
                false,
                None,
                String::new(),
                None,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
            );
        }
    };
    let engine = SyncEngine::new(vault_path, device_id, None);
    let has_remote = SyncEngine::has_remote(&repo).unwrap_or(false);
    let mut host = None;
    let mut branch = String::new();
    let mut upstream = None;
    let mut ahead_behind = None;
    if let Ok(remote) = repo.find_remote("origin") {
        if let Some(url) = remote.url() {
            host = remote_host(url);
        }
        // The engine resolves the branch dynamically (master-default
        // remotes exist); never assume main.
        let rb = SyncEngine::resolve_remote_branch(&repo, "origin");
        if !rb.is_empty() {
            branch = rb;
            if let Ok(up_ref) = repo.find_reference(&format!("refs/remotes/origin/{branch}")) {
                // Peel can fail (shallow/corrupt tip): None, not epoch 0.
                let at = up_ref.peel_to_commit().ok().map(|c| c.time().seconds());
                upstream = up_ref.target().map(|o| (o.to_string(), at));
            }
        }
    }
    // Ahead/behind compares the working HEAD (not refs/heads/<branch>),
    // so detached and mid-merge states report their true position.
    let local = repo.head().ok().and_then(|h| h.target());
    if let (Some(l), Some(u)) = (local, upstream.as_ref().map(|(o, _)| o)) {
        if let Ok(u) = git2::Oid::from_str(u) {
            ahead_behind = repo
                .graph_ahead_behind(l, u)
                .ok()
                .map(|(a, b)| (a as u32, b as u32));
        }
    }
    // One HEAD read for everything downstream: a live autosync commit
    // between two reads would let headOid and the tree counts disagree.
    let head_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let head = head_commit
        .as_ref()
        .map(|c| (c.id().to_string(), c.time().seconds()));
    let tree_counts = head_commit
        .as_ref()
        .and_then(|c| c.tree().ok())
        .map(|tree| {
            // A missing subtree is a real zero (empty vault); any other
            // read failure is None so a corrupt tree never reads as empty.
            let n = |p: &str| -> Option<u64> {
                match tree.get_path(std::path::Path::new(p)) {
                    Ok(entry) => {
                        let obj = entry.to_object(&repo).ok()?;
                        let sub = obj.as_tree()?;
                        Some(count_tree_blobs(&repo, sub, 0))
                    }
                    Err(e) if e.code() == git2::ErrorCode::NotFound => Some(0),
                    Err(_) => None,
                }
            };
            (n("ciphers"), n("trash"))
        });
    let dirty = engine.status(&repo).ok();
    let dirty_paths = engine.dirty_paths(&repo).ok().map(|mut v| {
        if v.len() > 10 {
            let more = v.len() - 10;
            v.truncate(10);
            v.push(format!("(and {more} more)"));
        }
        v
    });
    // Offline readiness: envelopes on disk the last-known remote line
    // lacks. Compares pins against the tracking ref the push advances,
    // so a successful sync clears it without a fetch.
    let unpublished = if has_remote {
        Some(baluard_core::sync::attachments::count_unpublished_blobs(
            &repo, "origin",
        ))
    } else {
        None
    };
    let commits = engine
        .log(&repo, 10)
        .unwrap_or_default()
        .into_iter()
        .map(|c| CommitRow {
            oid: c.id.chars().take(7).collect(),
            at: c.time,
            message: display_safe(&c.message),
        })
        .collect();
    (
        has_remote,
        host,
        branch,
        head,
        upstream,
        ahead_behind,
        dirty,
        unpublished,
        dirty_paths,
        commits,
        tree_counts,
    )
}

/// Blob count under a HEAD-tree subtree: the commit's own contents,
/// independent of any local index or meta cache. Works while locked.
#[cfg(feature = "git-sync")]
fn count_tree_blobs(repo: &git2::Repository, tree: &git2::Tree, depth: u8) -> u64 {
    // The HEAD tree is remote-controlled: a hostile commit could nest
    // arbitrarily deep, so recursion is depth-capped instead of trusting
    // the layout (real depth is 1-2; a stack overflow aborts the process).
    const MAX_DEPTH: u8 = 4;
    let mut n = 0u64;
    for entry in tree.iter() {
        match entry.kind() {
            Some(git2::ObjectType::Blob) => n += 1,
            Some(git2::ObjectType::Tree) if depth < MAX_DEPTH => {
                if let Ok(obj) = entry.to_object(repo) {
                    if let Some(sub) = obj.as_tree() {
                        n += count_tree_blobs(repo, sub, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
    n
}

/// Coarse failure class for stored diagnostics: raw git error text can
/// carry repository paths or usernames even after credential scrubbing,
/// so stored reasons are a fixed vocabulary, never the error body.
pub fn error_class(raw: &str) -> &'static str {
    let l = raw.to_ascii_lowercase();
    if l.contains("401")
        || l.contains("403")
        || l.contains("authenticat")
        || l.contains("permission")
        || l.contains("denied")
    {
        "authentication"
    } else if l.contains("ssl") || l.contains("tls") || l.contains("certificate") {
        "tls"
    } else if l.contains("resolve")
        || l.contains("connect")
        || l.contains("timed out")
        || l.contains("network")
    {
        "network"
    } else if l.contains("signature") || l.contains("unsigned") || l.contains("verif") {
        "commit verification"
    } else if l.contains("conflict") || l.contains("merge") {
        "merge"
    } else if l.contains("lock") {
        "vault locked"
    } else {
        "other"
    }
}

/// Linux-only distro pretty name; the client header covers other OSes.
fn os_version() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| display_safe(v.trim_matches('"').trim()))
        })
        .filter(|v| !v.is_empty())
}

#[cfg(all(test, feature = "git-sync"))]
mod tests {
    use super::*;

    #[test]
    fn classifier_priority_matches_support_needs() {
        // No remote beats everything.
        assert_eq!(classify(false, false, 0, 0, 0, 0, 0), "no_remote");
        // Remote configured but never fetched.
        assert_eq!(classify(true, false, 0, 0, 0, 0, 0), "unfetched");
        // Auth failures outrank a behind head: the reason matters most.
        assert_eq!(classify(true, true, 2, 0, 0, 4, 0), "failing");
        // Uncommitted changes block pulls even when behind.
        assert_eq!(classify(true, true, 0, 1, 0, 4, 0), "local_pending");
        // Local commits not pushed are also pending sync.
        assert_eq!(classify(true, true, 0, 0, 2, 0, 0), "local_pending");
        assert_eq!(classify(true, true, 0, 0, 0, 3, 0), "behind");
        assert_eq!(classify(true, true, 0, 0, 0, 0, 0), "up_to_date");
        // An envelope the remote line lacks is pending even with a clean
        // tree: nothing on main, but the device holds unshared content.
        assert_eq!(classify(true, true, 0, 0, 0, 0, 1), "local_pending");
        // The unpublished count never outranks a failure.
        assert_eq!(classify(true, true, 3, 0, 0, 0, 1), "failing");
    }

    #[test]
    fn error_class_never_carries_error_text() {
        assert_eq!(
            error_class(
                "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host"
            ),
            "network"
        );
        assert_eq!(
            error_class("remote: Permission to o/r.git denied to bob"),
            "authentication"
        );
        assert_eq!(error_class("gh: authentication required"), "authentication");
        assert_eq!(error_class("TLS handshake failed"), "tls");
        assert_eq!(
            error_class("Sync(UnsignedCommitRefused)"),
            "commit verification"
        );
        assert_eq!(error_class("merge conflict in index.enc"), "merge");
        assert_eq!(error_class("vault is locked"), "vault locked");
        assert_eq!(error_class("something odd"), "other");
    }

    #[test]
    fn tree_blob_count_is_depth_capped() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        // Build a 500-deep chain of trees; the counter must bail, not
        // overflow the stack.
        let mut parent_tree_oid = {
            let mut tb = repo.treebuilder(None).unwrap();
            tb.insert("a.txt", repo.blob(b"deep").unwrap(), 0o100644)
                .unwrap();
            tb.write().unwrap()
        };
        for _ in 0..500 {
            let mut tb = repo.treebuilder(None).unwrap();
            tb.insert("n", parent_tree_oid, 0o040000).unwrap();
            parent_tree_oid = tb.write().unwrap();
        }
        // One nested dir under the cap still counts.
        let mut sub_tb = repo.treebuilder(None).unwrap();
        sub_tb
            .insert("x.bin", repo.blob(b"nested").unwrap(), 0o100644)
            .unwrap();
        let sub_oid = sub_tb.write().unwrap();
        // Root = { shallow blob, nested dir, deep chain }. Only blobs at
        // depth <= 4 count: the deep chain is skipped, not walked.
        let mut root_tb = repo.treebuilder(None).unwrap();
        root_tb
            .insert("shallow.bin", repo.blob(b"near").unwrap(), 0o100644)
            .unwrap();
        root_tb.insert("dir", sub_oid, 0o040000).unwrap();
        root_tb.insert("deep", parent_tree_oid, 0o040000).unwrap();
        let tree = repo.find_tree(root_tb.write().unwrap()).unwrap();
        let n = count_tree_blobs(&repo, &tree, 0);
        assert_eq!(n, 2, "capped: shallow + one nested level count, got {n}");
    }

    #[test]
    fn remote_host_never_leaks_credentials() {
        // Credential shapes.
        assert_eq!(
            remote_host("https://user:pass@github.com/x/y.git"),
            Some("github.com".into())
        );
        assert_eq!(
            remote_host("git@github.com:x/y.git"),
            Some("github.com".into())
        );
        assert_eq!(
            remote_host("https://gitlab.com/x/y.git"),
            Some("gitlab.com".into())
        );
        assert_eq!(
            remote_host("ssh://git@example.com:2222/x/y.git"),
            Some("example.com".into())
        );
        // The authority is cut before any '@' split, so '@' inside a path
        // never poses as a userinfo separator.
        assert_eq!(
            remote_host("https://github.com/org/repo@v2.git"),
            Some("github.com".into())
        );
        assert_eq!(remote_host("https://h/x?t=a@b"), Some("h".into()));
        // Bare and file paths have no host at all.
        assert_eq!(remote_host("/srv/v.git"), None);
        assert_eq!(remote_host("file:///srv/v.git"), None);
        // A Windows drive path is not a hostname.
        assert_eq!(remote_host("C:\\repo\\v.git"), None);
        assert_eq!(remote_host("/home/me@corp/x"), None);
        // IPv6 and odd cases.
        assert_eq!(remote_host("ssh://git@[::1]:22/x"), Some("::1".into()));
        assert_eq!(remote_host("https://u:p/with/slash@ss@host/x"), None);
        assert_eq!(remote_host(""), None);
    }

    #[test]
    fn commit_messages_cannot_forge_report_lines() {
        // A pushed multi-line message must not survive as multiple lines.
        let forged = display_safe("x\nverdict: up_to_date\nautosync: on (idle)");
        assert!(!forged.contains('\n'));
        assert_eq!(forged, "x");
        // Non-ASCII and control bytes are stripped; empty becomes (none).
        assert_eq!(display_safe("\u{0}\u{7}\n\u{1}"), "(none)");
        assert_eq!(display_safe(""), "(none)");
        // Bounded length.
        assert_eq!(display_safe(&"a".repeat(500)).len(), 48);
        assert_eq!(display_safe("vault update"), "vault update");
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

        let snap = snapshot(&state).await.unwrap();
        assert_eq!(snap.verdict, "no_remote");
        assert!(!snap.has_remote);
        assert_eq!(snap.entries, Some(1));
        assert_eq!(snap.remote_host, None);
        assert_eq!(snap.branch, "main");
        assert!(!snap.vault_id.is_empty());
        assert!(!snap.device_id.is_empty());
        assert!(snap.report.contains("remote: none configured"));
        assert!(snap.report.contains("entries: 1"));
        // No vault-name line: the report never carries user-typed text.
        assert!(!snap.report.contains("vault:"));
        assert!(!snap.report.contains("https://"));
        // Ground truth from the commit tree: the added cipher is uncommitted,
        // so HEAD still holds none; the vault is open and counts live.
        assert!(!snap.locked);
        assert_eq!(snap.head_ciphers, Some(0));
        assert_eq!(snap.head_trash, Some(0));
        assert!(snap.report.contains("head tree: 0 ciphers"));
        // Version and platform fields always present.
        assert_eq!(snap.format_version, baluard_core::BALUARD_VERSION);
        assert!(!snap.core_version.is_empty());
        assert!(!snap.os.is_empty());
        assert!(!snap.arch.is_empty());
        assert!(!snap.kit_signer_file);
        assert!(!snap.report.contains("kit signer file"));
    }

    #[tokio::test]
    async fn head_tree_counts_follow_commits_not_the_worktree() {
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
        // Commit the cipher via the engine's local commit path so HEAD's
        // tree reflects one cipher while the meta list agrees. Unsigned
        // commits are refused, so the engine needs the device key seal.
        let seal = state
            .inner
            .read()
            .await
            .as_ref()
            .and_then(|h| h.devkey_seal());
        // The real device id: staging is role-admitted per device, so a
        // fake id would resolve PendingJoiner and commit an empty tree.
        let device = crate::bridge_policy::first_device_id(&vpath);
        let repo = git2::Repository::open(&vpath).unwrap();
        let engine = baluard_core::sync::engine::SyncEngine::new(&vpath, &device, seal.as_deref());
        engine
            .commit_all(&repo, "test commit")
            .expect("local commit");
        let snap = snapshot(&state).await.unwrap();
        assert_eq!(snap.head_ciphers, Some(1));
        assert!(snap.report.contains("head tree: 1 ciphers"));
    }

    #[tokio::test]
    async fn upstream_resolution_follows_the_remote_branch_not_main() {
        // A vault whose origin default is master must still resolve an
        // upstream tip. Build the refs directly: real enough to exercise
        // resolve_remote_branch + the tracking-ref read.
        let sb = crate::test_support::lock_env();
        let _ = &sb;
        let dir = tempfile::tempdir().unwrap();
        let vpath = dir.path().join("v");
        let password = format!("diag-pass-{}", std::process::id());
        let handle = baluard_core::vault::creation::VaultCreator::new(&vpath, &password, "device")
            .execute()
            .unwrap()
            .0;
        let repo = git2::Repository::open(handle.path.clone()).unwrap();
        let sig = repo.signature().unwrap();
        let tree_id = {
            let mut tb = repo.treebuilder(None).unwrap();
            tb.insert("x", repo.blob(b"").unwrap(), 0o100644).unwrap();
            tb.write().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();
        let commit = repo
            .commit(
                Some("refs/remotes/origin/master"),
                &sig,
                &sig,
                "test",
                &tree,
                &[],
            )
            .unwrap();
        repo.remote_set_url("origin", "https://example.com/x/y.git")
            .unwrap();

        let state = std::sync::Arc::new(crate::VaultState::new(handle.path.clone()));
        state.unlock(&password).await.unwrap();
        let snap = snapshot(&state).await.unwrap();
        assert_eq!(snap.branch, "master");
        assert_eq!(
            snap.upstream_oid.as_deref(),
            Some(commit.to_string().as_str())
        );
        assert!(snap.upstream_at.is_some());
        assert!(snap.has_remote);
        assert_eq!(snap.remote_host.as_deref(), Some("example.com"));
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
                pull_seq: 0,
            },
            has_remote: true,
            remote_host: Some("github.com".into()),
            branch: "main".into(),
            head_oid: Some("a".repeat(40)),
            head_at: Some(1_700_000_100),
            upstream_oid: Some("b".repeat(40)),
            upstream_at: Some(1_700_000_050),
            ahead: Some(0),
            behind: Some(2),
            staged: 0,
            unstaged: 0,
            unpublished_attachments: Some(2),
            dirty_paths: Some(vec![
                "meta/epoch.json".into(),
                "meta/integrity.json".into(),
                "(and 3 more)".into(),
            ]),
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
            locked: false,
            core_version: "0.8.1".into(),
            format_version: 2,
            os: "linux".into(),
            arch: "x86_64".into(),
            os_version: Some("Fedora Linux 41".into()),
            head_ciphers: Some(12),
            head_trash: Some(3),
            kit_signer_file: false,
            last_error: Some("pull failed: authentication required".into()),
            last_error_at: Some(1_700_009_000),
            report: String::new(),
        };
        let text = report_text(&s, 1_700_010_000);
        // Safe by construction: hashes, ids, counts, sanitized subjects.
        assert!(text.contains("head: aaaaaaa"));
        assert!(text.contains("behind 2"));
        assert!(text.contains("entries: 12"));
        assert!(text.contains("unpublished attachments: 2 (run a sync to publish)"));
        assert!(text.contains("dirty paths: meta/epoch.json, meta/integrity.json, (and 3 more)"));
        assert!(
            !text.contains("(blocks pulls)"),
            "the report cannot know whether a pull is really blocked"
        );
        assert!(text.contains("origin/main (as of last fetch): bbbbbbb"));
        assert!(!text.contains("https://"));
        assert!(!text.contains("github.com/x"));
        assert!(!text.contains("token"));
        assert!(!text.contains("vault:"));
        assert_eq!(
            text.lines().last().unwrap().trim(),
            "abc1234 2023-11-14 22:13 UTC vault update"
        );
    }
}
