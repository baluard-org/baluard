//! S1b-1: sharing activity log — structured, human-sentence events for
//! the Activity surface (plan-sharing §4.6).
//!
//! Storage: `meta/share-events.enc`, AES-256-GCM under the RootKey-
//! derived events key (rotation-covered: read pre-swap, re-encrypted
//! post-swap in both rotation flows, like contacts). Git-tracked, so
//! every client converges on the same audit trail.
//!
//! Emission is best-effort by contract: an event-log failure must never
//! fail the member operation that produced it. Viewing propagates.
//!
//! Compaction: the log keeps the most recent [`MAX_SHARE_EVENTS`]
//! entries; appends beyond the cap fold the oldest away.

use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::hkdf_derive::derive_events_key;
use crate::error::{BaluardError, VaultError};

/// Keep the most recent 500 events (§4.6: compaction — the log is a
/// recent-activity surface, not an archive).
pub const MAX_SHARE_EVENTS: usize = 500;

const EVENTS_PATH: &str = "meta/share-events.enc";

/// Kind of a sharing activity event. Tagged kebab-case in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareEventKind {
    MemberJoined,
    MemberRemoved,
    MemberReset,
    OwnershipTransferred,
    IdentityRotated,
    ContactTrustReset,
}

/// One activity entry: a machine-readable kind plus a human sentence
/// (the display form — the Activity screen renders `detail` verbatim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareEvent {
    /// Monotonic within this log (max existing + 1, starts at 1).
    pub seq: u64,
    /// Unix seconds at emission.
    pub at: u64,
    pub kind: ShareEventKind,
    /// Human sentence, pre-rendered at emission (best-effort labels
    /// belong to the UI; the sentence is the source of truth).
    pub detail: String,
}

fn events_path(vault_path: &Path) -> std::path::PathBuf {
    vault_path.join(EVENTS_PATH)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Load the event log. Missing file = empty log. Corrupt envelope or
/// plaintext = hard error (tamper, fail closed) — viewing surfaces it;
/// emission treats it as best-effort upstream.
pub fn load(
    vault_path: &Path,
    _vault_id: Uuid,
    root_key: &[u8; 64],
) -> Result<Vec<ShareEvent>, BaluardError> {
    let path = events_path(vault_path);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let key = derive_events_key(root_key)?;
    let data = std::fs::read(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("read events: {e}"))))?;
    let envelope = crate::vault::envelope::deserialize(&data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("events envelope: {e}"))))?;
    let plaintext = crate::crypto::aead::decrypt(&key, &envelope)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("events decrypt: {e}"))))?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("events parse: {e}"))))
}

pub(crate) fn save(
    vault_path: &Path,
    vault_id: Uuid,
    root_key: &[u8; 64],
    epoch: u64,
    events: &[ShareEvent],
) -> Result<(), BaluardError> {
    let key = derive_events_key(root_key)?;
    let json = serde_json::to_vec(events)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("events serialize: {e}"))))?;
    let nonce = crate::crypto::aead::build_random_nonce();
    let nonce_counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());
    let aad = crate::crypto::aead::build_aad(
        vault_id,
        crate::types::ObjectType::Meta,
        Uuid::nil(),
        None,
        crate::ALG_AES_256_GCM,
        epoch,
        1,
    );
    let header = crate::types::EnvelopeHeader {
        version: crate::BALUARD_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: epoch,
        nonce_counter,
        update_seq: 1,
        tier: None,
    };
    let envelope = crate::crypto::aead::encrypt(&key, &json, &aad, &nonce, header)?;
    let data = crate::vault::envelope::serialize(&envelope)?;
    super::write_vault_file(&events_path(vault_path), &data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write events: {e}"))))
}

/// Append one event (best-effort by contract — callers use `let _ =`).
/// Compacts to the most recent [`MAX_SHARE_EVENTS`] entries.
pub fn append(
    vault_path: &Path,
    vault_id: Uuid,
    root_key: &[u8; 64],
    epoch: u64,
    kind: ShareEventKind,
    detail: impl Into<String>,
) -> Result<(), BaluardError> {
    let mut events = load(vault_path, vault_id, root_key)?;
    let seq = events.last().map(|e| e.seq).unwrap_or(0).saturating_add(1);
    events.push(ShareEvent {
        seq,
        at: now_secs(),
        kind,
        detail: detail.into(),
    });
    if events.len() > MAX_SHARE_EVENTS {
        let drop = events.len() - MAX_SHARE_EVENTS;
        events.drain(..drop);
    }
    save(vault_path, vault_id, root_key, epoch, &events)
}
