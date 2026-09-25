//! Encrypted lookup index (index.enc) for high-performance O(1) searches.
//!
//! D2: Padded index.enc lookup table.
//! D4: Auto-healing on sync conflict.

use crate::crypto::aead;
use crate::error::{BaluardError, VaultError};
use crate::types::{CipherMeta, EnvelopeHeader, ObjectType, Tier};
use crate::vault::envelope;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexTable {
    pub ciphers: Vec<CipherMeta>,
    /// P5b: this shard's position and the layout's total shard count. Serde
    /// defaults keep legacy single-envelope tables readable (shard 0 of 1).
    /// read_sharded uses `total_shards` to detect missing shards (silent
    /// truncation) and stale extra shards (ghost entries after a crash
    /// between write and prune).
    #[serde(default)]
    pub shard_index: usize,
    #[serde(default = "default_total_shards")]
    pub total_shards: usize,
    /// Cipher ids present on disk but excluded from this index because they
    /// could not be decrypted at rebuild time (cross-epoch or corrupt).
    /// Lets the staleness check compare like-for-like counts without
    /// rebuilding on every list.
    #[serde(default)]
    pub skipped: Vec<Uuid>,
}

fn default_total_shards() -> usize {
    1
}

/// Encrypt one index shard. The shard position binds into the AAD's object
/// id (shard 0 = nil UUID, byte-compatible with legacy single-envelope
/// indexes), so swapping two shard files fails AAD verification.
pub fn encrypt_shard(
    vault_id: Uuid,
    ciphers: &[CipherMeta],
    index_key: &[u8; 32],
    key_epoch: u64,
    shard_index: usize,
    total_shards: usize,
    skipped: &[Uuid],
) -> Result<Vec<u8>, BaluardError> {
    let table = IndexTable {
        ciphers: ciphers.to_vec(),
        shard_index,
        total_shards,
        skipped: skipped.to_vec(),
    };
    let json = serde_json::to_vec(&table)
        .map_err(|e| VaultError::Metadata(format!("index serialization: {e}")))?;

    let tier = Tier::fit(json.len()).ok_or_else(|| {
        VaultError::InvalidTier(format!("index shard too large: {} bytes", json.len()))
    })?;

    let padded = super::padding::pad(&json, tier)?;

    let aad = aead::build_aad(
        vault_id,
        ObjectType::Meta,
        Uuid::from_u128(shard_index as u128),
        Some(tier),
        ALG_AES_256_GCM,
        key_epoch,
        1,
    );

    let nonce = aead::build_random_nonce();
    // Header stores only a u64 `nonce_counter`; derive it from the first
    // 8 bytes of the 96-bit random nonce so the field stays populated
    // (metadata-only — decrypt reads the full 12-byte nonce from the
    // envelope, not this field). A-1 fix: previously build_nonce(counter,
    // Uuid::nil()) zeroed the shard tail, leaving only 64 random bits under
    // a fixed key on the highest-write-frequency object.
    let nonce_counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());

    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
        nonce_counter,
        update_seq: 1,
        tier: Some(tier),
    };

    let enc_envelope = aead::encrypt(index_key, &padded, &aad, &nonce, header)?;
    let envelope_bytes = envelope::serialize(&enc_envelope)?;

    Ok(envelope_bytes)
}

/// Compatibility wrapper: legacy single-envelope index = shard 0 of 1.
pub fn encrypt_index(
    vault_id: Uuid,
    ciphers: &[CipherMeta],
    index_key: &[u8; 32],
    key_epoch: u64,
) -> Result<Vec<u8>, BaluardError> {
    encrypt_shard(vault_id, ciphers, index_key, key_epoch, 0, 1, &[])
}

/// Decrypt a shard-0 envelope (legacy single-envelope format) into metas.
pub fn decrypt_index(
    vault_id: Uuid,
    envelope_bytes: &[u8],
    index_key: &[u8; 32],
) -> Result<Vec<CipherMeta>, BaluardError> {
    Ok(decrypt_shard_table(vault_id, envelope_bytes, index_key, 0)?.ciphers)
}

/// Decrypt one shard envelope, verifying the AAD against its expected shard
/// position — swapping two shard files fails identity verification.
pub fn decrypt_shard_table(
    vault_id: Uuid,
    envelope_bytes: &[u8],
    index_key: &[u8; 32],
    expected_shard_index: usize,
) -> Result<IndexTable, BaluardError> {
    let enc_envelope = envelope::deserialize(envelope_bytes)?;

    let expected_aad = aead::build_aad(
        vault_id,
        ObjectType::Meta,
        Uuid::from_u128(expected_shard_index as u128),
        enc_envelope.header.tier,
        enc_envelope.header.alg_id,
        enc_envelope.header.key_epoch,
        enc_envelope.header.update_seq,
    );

    if enc_envelope.aad != expected_aad {
        return Err(VaultError::Corrupt(
            "index identity mismatch (AAD verification failed)".into(),
        )
        .into());
    }

    let decrypted = aead::decrypt(index_key, &enc_envelope)?;

    let unpadded = super::padding::unpad(&decrypted)?;
    let table: IndexTable = serde_json::from_slice(&unpadded)
        .map_err(|e| VaultError::Corrupt(format!("index deserialization: {e}")))?;

    Ok(table)
}

// ── P5b: sharded index ────────────────────────────────────────────────────
//
// The index is local-only bookkeeping (gitignored, rebuilt from ciphers on
// demand). As a single padded envelope it hard-fails at the XL tier's 2 MB
// ceiling (~8-13k entries). Sharding splits the sorted table into fixed-size
// chunks, each its own padded envelope.

/// Entries per index shard. CipherMeta is ~150-250 B of JSON per entry, so a
/// 2048-entry shard lands in a mid tier instead of one envelope riding the
/// XL ceiling.
pub(crate) const INDEX_SHARD_ENTRIES: usize = 2048;

/// Shard file names: shard 0 keeps the legacy name `index.enc` (single-shard
/// vaults are byte-compatible with the old layout), extra shards append
/// `.s1`, `.s2`, ...
fn shard_file_name(k: usize) -> String {
    if k == 0 {
        "index.enc".to_string()
    } else {
        format!("index.enc.s{k}")
    }
}

/// Sort by cipher id and chunk. Sorting makes the shard layout
/// deterministic: the same cipher set produces the same shard boundaries on
/// every device.
fn chunk_ciphers(mut ciphers: Vec<CipherMeta>) -> Vec<Vec<CipherMeta>> {
    ciphers.sort_by_key(|m| m.id);
    if ciphers.len() <= INDEX_SHARD_ENTRIES {
        return vec![ciphers];
    }
    ciphers
        .chunks(INDEX_SHARD_ENTRIES)
        .map(<[CipherMeta]>::to_vec)
        .collect()
}

/// Write the index as deterministic shards into `dir` (the vault's meta/),
/// pruning orphaned higher shards left over from a previous larger layout.
/// Returns the number of shards written. `skipped` records cipher ids that
/// could not be decrypted at rebuild time (excluded from `ciphers`) so the
/// staleness check in `list_cipher_meta_full` can compare like-for-like
/// counts without rebuilding on every list.
pub fn write_sharded(
    vault_id: Uuid,
    ciphers: &[CipherMeta],
    index_key: &[u8; 32],
    key_epoch: u64,
    dir: &std::path::Path,
    skipped: &[Uuid],
) -> Result<usize, BaluardError> {
    let chunks = chunk_ciphers(ciphers.to_vec());
    let total = chunks.len();
    for (k, chunk) in chunks.iter().enumerate() {
        // The skipped list rides shard 0 only — the reader reads it from the
        // head shard; duplicating it into every shard would waste padded
        // tier budget.
        let shard_skipped: &[Uuid] = if k == 0 { skipped } else { &[] };
        let bytes = encrypt_shard(
            vault_id,
            chunk,
            index_key,
            key_epoch,
            k,
            total,
            shard_skipped,
        )?;
        let path = dir.join(shard_file_name(k));
        // Vault-file write: 0600 perms, atomic tmp+rename — same invariant
        // as every other file under meta/.
        super::write_vault_file(&path, &bytes)?;
    }
    // Prune orphaned shards (previous layout was larger).
    for entry in std::fs::read_dir(dir)
        .map_err(|e| VaultError::Metadata(format!("index prune listing: {e}")))?
    {
        let entry = entry.map_err(|e| VaultError::Metadata(format!("index prune read: {e}")))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(suffix) = name.strip_prefix("index.enc.s") {
            if suffix.parse::<usize>().map(|n| n >= total).unwrap_or(false) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(total)
}

/// Read the sharded index. Returns `None` when the layout is incomplete,
/// stale, or undecryptable (caller falls back to the auto-heal rebuild):
/// shard 0 carries `total_shards`, and EVERY shard must be present and
/// decrypt at its expected position — a missing higher shard would mean
/// silent truncation; a leftover higher shard after a crash-before-prune
/// would mean ghost entries. Both fail closed. Also returns shard 0's
/// skipped-id list for the staleness set-equality check.
pub fn read_sharded(
    vault_id: Uuid,
    dir: &std::path::Path,
    index_key: &[u8; 32],
) -> Option<(Vec<CipherMeta>, Vec<Uuid>)> {
    let first = std::fs::read(dir.join(shard_file_name(0))).ok()?;
    let head = decrypt_shard_table(vault_id, &first, index_key, 0).ok()?;
    let total_shards = head.total_shards.max(1);

    let mut out = head.ciphers;
    for k in 1..total_shards {
        let bytes = std::fs::read(dir.join(shard_file_name(k))).ok()?;
        let table = decrypt_shard_table(vault_id, &bytes, index_key, k).ok()?;
        if table.total_shards != total_shards {
            return None; // torn layout — refuse rather than guess
        }
        out.extend(table.ciphers);
    }
    if out.len() > 10_000_000 {
        // Sanity bound; no real vault is this large.
        return None;
    }
    Some((out, head.skipped))
}

/// P5b: the sharded layout roundtrips across multiple shards, prunes
/// orphaned shards when the table shrinks, and still reads a legacy
/// single-envelope index.enc.
#[cfg(test)]
mod sharding_tests {
    use super::*;
    use crate::types::CipherType;

    fn meta_with_id(i: u128) -> CipherMeta {
        CipherMeta {
            id: Uuid::from_u128(i),
            name: format!("cipher-{i}"),
            folder_id: None,
            cipher_type: CipherType::Login,
            favorite: false,
            reprompt: false,
            username: None,
            tier: Tier::S,
            key_epoch: 1,
            update_seq: 1,
            updated_at: i as u64,
            archived: false,
            tags: vec![],
            collection_id: None,
        }
    }

    #[test]
    fn sharded_index_roundtrip_prune_and_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let vault_id = Uuid::new_v4();

        // Force multi-shard: more entries than one shard holds.
        let metas: Vec<CipherMeta> = (0..INDEX_SHARD_ENTRIES * 2 + 5)
            .map(|i| meta_with_id(i as u128))
            .collect();

        let shards = write_sharded(vault_id, &metas, &key, 3, dir.path(), &[]).unwrap();
        assert_eq!(shards, 3, "2*2048+5 entries must split into 3 shards");
        assert!(dir.path().join("index.enc").exists());
        assert!(dir.path().join("index.enc.s1").exists());
        assert!(dir.path().join("index.enc.s2").exists());

        let (read_back, skipped) = read_sharded(vault_id, dir.path(), &key).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(read_back.len(), metas.len());
        // Sorted-by-id shard boundaries are invisible to the reader.
        let mut expected = metas.clone();
        expected.sort_by_key(|m| m.id);
        let got_ids: Vec<Uuid> = read_back.iter().map(|m| m.id).collect();
        let want_ids: Vec<Uuid> = expected.iter().map(|m| m.id).collect();
        assert_eq!(got_ids, want_ids);
        for (got, want) in read_back.iter().zip(expected.iter()) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.updated_at, want.updated_at);
        }

        // Shrink: orphaned .s1/.s2 must be pruned.
        let small: Vec<CipherMeta> = metas[..10].to_vec();
        let shards_after = write_sharded(vault_id, &small, &key, 3, dir.path(), &[]).unwrap();
        assert_eq!(shards_after, 1);
        assert!(
            !dir.path().join("index.enc.s1").exists(),
            "orphan not pruned"
        );
        assert_eq!(
            read_sharded(vault_id, dir.path(), &key).unwrap().0.len(),
            10
        );

        // Legacy single-envelope layout (plain encrypt_index) stays readable.
        let legacy_dir = tempfile::tempdir().unwrap();
        let legacy = encrypt_index(vault_id, &small, &key, 1).unwrap();
        std::fs::write(legacy_dir.path().join("index.enc"), legacy).unwrap();
        assert_eq!(
            read_sharded(vault_id, legacy_dir.path(), &key)
                .unwrap()
                .0
                .len(),
            10
        );

        // Wrong key → None (caller auto-heals), never a wrong answer.
        assert!(read_sharded(vault_id, dir.path(), &[0u8; 32]).is_none());

        // Truncation: a missing higher shard must fail closed (None), not
        // return a silently truncated list.
        write_sharded(vault_id, &metas, &key, 3, dir.path(), &[]).unwrap();
        std::fs::remove_file(dir.path().join("index.enc.s2")).unwrap();
        assert!(read_sharded(vault_id, dir.path(), &key).is_none());

        // Ghost entries: with total_shards=1 declared, a leftover garbage
        // higher shard after a crash-before-prune is IGNORED (the reader is
        // count-driven), never resurrected.
        write_sharded(vault_id, &small, &key, 3, dir.path(), &[]).unwrap();
        std::fs::write(dir.path().join("index.enc.s1"), b"garbage").unwrap();
        assert_eq!(
            read_sharded(vault_id, dir.path(), &key).unwrap().0.len(),
            10
        );
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let metas: Vec<CipherMeta> = (0..5).map(|i| meta_with_id(i as u128)).collect();
        let encrypted = encrypt_index(vault_id, &metas, &index_key, 1).expect("encrypt");
        assert!(!encrypted.is_empty());
        let decrypted = decrypt_index(vault_id, &encrypted, &index_key).expect("decrypt");
        assert_eq!(decrypted.len(), metas.len());
        for (got, want) in decrypted.iter().zip(metas.iter()) {
            assert_eq!(got.id, want.id);
            assert_eq!(got.name, want.name);
            assert_eq!(got.favorite, want.favorite);
        }
    }

    #[test]
    fn decrypt_with_wrong_vault_id_fails() {
        let vault_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let metas: Vec<CipherMeta> = (0..5).map(|i| meta_with_id(i as u128)).collect();
        let encrypted = encrypt_index(vault_id, &metas, &index_key, 1).unwrap();
        // AAD mismatch must be detected — wrong vault_id means the AAD
        // builder produces different bytes and decrypt rejects.
        let err = decrypt_index(other_id, &encrypted, &index_key).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("aad")
                || err.to_string().to_lowercase().contains("identity"),
            "expected AAD/identity error: {err}"
        );
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let other_key = [0x99u8; 32];
        let metas: Vec<CipherMeta> = (0..5).map(|i| meta_with_id(i as u128)).collect();
        let encrypted = encrypt_index(vault_id, &metas, &index_key, 1).unwrap();
        // Wrong key: AAD matches but AEAD tag check fails.
        let err = decrypt_index(vault_id, &encrypted, &other_key).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("auth")
                || err.to_string().to_lowercase().contains("decrypt")
        );
    }

    #[test]
    fn empty_cipher_list_round_trips() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let encrypted = encrypt_index(vault_id, &[], &index_key, 1).unwrap();
        let decrypted = decrypt_index(vault_id, &encrypted, &index_key).unwrap();
        assert!(decrypted.is_empty());
    }
}
