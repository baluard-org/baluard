//! Family-spaces §13 step 8b: the selective item-copy founding flow.
//!
//! A family vault is born empty; the founder's existing personal vault
//! holds the items worth bringing. This module copies selected ciphers
//! from an unlocked source vault into an unlocked target vault on the
//! shared host. The copy is decrypt-then-re-add: the target assigns
//! fresh ids, re-encrypts under its own keys, and the ordinary add
//! path applies the target's filing defaults (on a family vault,
//! logins and notes land in Shared). Attachments are NOT copied —
//! their blobs live under the source vault directory and have no
//! cross-vault transport; the report says so.
//!
//! Both vaults must already be unlocked on this daemon: the route
//! moves no keys and mints no session, it only bridges two open
//! sessions the operator explicitly names.

use crate::state::VaultState;
use baluard_core::types::CipherInput;
use std::sync::Arc;

pub async fn copy_items_between_states(
    source: &Arc<VaultState>,
    target: &Arc<VaultState>,
    cipher_ids: Vec<uuid::Uuid>,
) -> Result<String, String> {
    // Read side: pull the decrypted ciphers out of the source before
    // touching the target, so a locked target leaves the source read
    // untouched.
    let mut inputs: Vec<CipherInput> = Vec::with_capacity(cipher_ids.len());
    let mut skipped_attachments = 0usize;
    for id in &cipher_ids {
        let cipher = source
            .read_decrypted_for_copy(*id)
            .await?
            .ok_or_else(|| format!("cannot read {id}: not found or locked"))?;
        skipped_attachments += cipher.attachments.len();
        let mut input = CipherInput::from_cipher(&cipher);
        // Same hygiene as item-package import: attachment blobs do not
        // travel (their bytes live under the source vault) and the
        // folder id names a folder the target vault has never seen.
        // Password history IS item data and travels.
        input.attachments.clear();
        input.folder_id = None;
        inputs.push(input);
    }

    let mut copied = 0u32;
    let mut failed: Vec<serde_json::Value> = Vec::new();
    for (input, id) in inputs.iter().zip(cipher_ids.iter()) {
        // The state-layer add applies the target vault's filing
        // defaults (family vaults route unfiled logins to Shared).
        let mut payload =
            serde_json::to_string(input).map_err(|e| format!("input serialization: {e}"))?;
        let res = target.add_cipher(&payload).await;
        zeroize::Zeroize::zeroize(&mut payload);
        match res {
            Ok(_) => copied += 1,
            Err(e) => failed.push(serde_json::json!({
                "cipher_id": id.to_string(),
                "error": e,
            })),
        }
    }

    Ok(serde_json::json!({
        "copied": copied,
        "failed": failed,
        "attachments_not_copied": skipped_attachments,
    })
    .to_string())
}

/// Resolve the id list for `all: true` requests: every non-archived
/// cipher id in the source, read through the handle (no wire parse).
pub async fn all_source_cipher_ids(source: &Arc<VaultState>) -> Result<Vec<uuid::Uuid>, String> {
    source.list_cipher_ids_for_copy().await
}
