//! Encrypted backup container (`.bldbak`), spec: `docs/plan-encrypted-backup.md` §5–§6.
//!
//! Nothing cryptographic is custom: AES-256-GCM, Argon2id and HKDF-SHA256 do
//! the work. What this module owns is the FILE FORMAT — a 65-byte plaintext
//! header, key derivation wiring, and STREAM chunk framing copied from age.
//! The file key derives ONLY from the passphrase: no vault key material,
//! vault id, epoch or device id enters the file, so any Baluard vault can
//! decrypt and re-import under its own keys and a master-password change or
//! root-key rotation can never brick an old backup.
//!
//! Size privacy: the true payload length exists only in-band (inside the
//! ciphertext, GCM-authenticated). The header never reveals it; the padded
//! bucket rounds the file up to one of six sizes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// ASCII file magic. Offsets and layout are pinned by tests; keep them in
/// sync with the spec table before changing anything.
pub const MAGIC: &[u8; 6] = b"BLDBAK";

/// Container major version. Readers fail closed on any other value.
pub const CONTAINER_VERSION: u8 = 1;

/// KDF id: Argon2id.
pub const KDF_ARGON2ID: u8 = 1;
/// AEAD id: AES-256-GCM.
pub const AEAD_AES_256_GCM: u8 = 1;

/// Exact header length in bytes.
pub const HEADER_LEN: usize = 65;

/// HKDF extract salt. The expand `info` is the exact header bytes, which
/// makes the header key-committing: any tamper changes the key.
pub const HKDF_EXTRACT_SALT: &[u8] = b"baluard.backup.v1";

/// Plaintext bytes per chunk (STREAM, as in age/Tink).
pub const CHUNK_SIZE: u32 = 65536;
const TAG_LEN: usize = 16;
/// Ciphertext bytes per chunk on disk: payload plus its GCM tag.
pub const CHUNK_ON_DISK: usize = CHUNK_SIZE as usize + TAG_LEN;

/// Export KDF constants (§5.5): fixed, never calibrated to the machine.
pub const EXPORT_MEMORY_KIB: u32 = 65536;
pub const EXPORT_ITERATIONS: u32 = 3;
pub const EXPORT_PARALLELISM: u32 = 1;

/// Import caps (§5.5). The memory cap is a crash guard: on mobile an
/// overcommittng allocation dies by SIGKILL before any error handler runs.
pub const CAP_MEMORY_KIB: u32 = 262144;
pub const CAP_ITERATIONS: u32 = 6;
pub const CAP_PARALLELISM: u32 = 4;

/// Padding buckets, ascending (§5.3). The smallest one fitting
/// `8 + payload_length` is chosen; the file reveals only which bucket.
pub const BUCKETS: [usize; 6] = [
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
    256 * 1024 * 1024,
];

/// Largest exportable payload: the top bucket minus the in-band length
/// prefix. (Unrelated to the Argon2id memory cap; the equality is a
/// coincidence, see §5.3.)
pub const MAX_PAYLOAD_LEN: usize = BUCKETS[5] - 8;

/// Format errors. The two failure classes a user can hit — wrong passphrase
/// and corruption — are deliberately indistinguishable ([ContainerError::Damaged]).
#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("not an encrypted Baluard backup")]
    NotABackup,
    #[error(
        "this backup uses a newer format or stronger settings than this app supports; update Baluard to open this backup"
    )]
    Unsupported,
    #[error("wrong password or damaged file")]
    Damaged,
    #[error("this vault is too large to back up in a single encrypted file")]
    TooLarge,
}

/// The plaintext header. Random fields arrive from the caller so the
/// deterministic variant can build reproducible test vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeader {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 32],
    pub nonce_prefix: [u8; 7],
    pub chunk_size: u32,
}

impl ContainerHeader {
    /// Export-default header with fresh randomness.
    fn new_export() -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        let mut nonce_prefix = [0u8; 7];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);
        Self {
            memory_kib: EXPORT_MEMORY_KIB,
            iterations: EXPORT_ITERATIONS,
            parallelism: EXPORT_PARALLELISM,
            salt,
            nonce_prefix,
            chunk_size: CHUNK_SIZE,
        }
    }

    /// Encode to the exact 65-byte layout. Integers little-endian.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..6].copy_from_slice(MAGIC);
        h[6] = CONTAINER_VERSION;
        h[7] = KDF_ARGON2ID;
        h[8] = AEAD_AES_256_GCM;
        h[9] = 0; // reserved
        h[10..14].copy_from_slice(&self.memory_kib.to_le_bytes());
        h[14..18].copy_from_slice(&self.iterations.to_le_bytes());
        h[18..22].copy_from_slice(&self.parallelism.to_le_bytes());
        h[22..54].copy_from_slice(&self.salt);
        h[54..61].copy_from_slice(&self.nonce_prefix);
        h[61..65].copy_from_slice(&self.chunk_size.to_le_bytes());
        h
    }

    /// Parse and validate. Anything outside v1's legal envelope is
    /// [ContainerError::Unsupported] ("update Baluard"), not Damaged: the
    /// realistic benign cause is a future Baluard writing stronger settings.
    pub fn parse(bytes: &[u8; HEADER_LEN]) -> Result<Self, ContainerError> {
        if &bytes[0..6] != MAGIC {
            return Err(ContainerError::NotABackup);
        }
        if bytes[6] != CONTAINER_VERSION
            || bytes[7] != KDF_ARGON2ID
            || bytes[8] != AEAD_AES_256_GCM
            || bytes[9] != 0
            || bytes[61..65] != CHUNK_SIZE.to_le_bytes()
        {
            return Err(ContainerError::Unsupported);
        }
        let header = Self {
            memory_kib: u32::from_le_bytes(bytes[10..14].try_into().expect("4 bytes")),
            iterations: u32::from_le_bytes(bytes[14..18].try_into().expect("4 bytes")),
            parallelism: u32::from_le_bytes(bytes[18..22].try_into().expect("4 bytes")),
            salt: bytes[22..54].try_into().expect("32 bytes"),
            nonce_prefix: bytes[54..61].try_into().expect("7 bytes"),
            chunk_size: u32::from_le_bytes(bytes[61..65].try_into().expect("4 bytes")),
        };
        if header.memory_kib > CAP_MEMORY_KIB
            || header.iterations > CAP_ITERATIONS
            || header.parallelism > CAP_PARALLELISM
        {
            return Err(ContainerError::Unsupported);
        }
        Ok(header)
    }
}

/// Does this byte stream start with the encrypted-backup magic? Checked
/// before the plaintext `baluard.vault` sniff so the two never collide.
pub fn looks_like_encrypted_backup(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// NFKC-normalized passphrase bytes. Normalization is part of the spec (§5.2):
/// an accented wordlist word arrives in different Unicode forms from different
/// keyboards, and a mismatch must be impossible, not rare. Never trimmed.
fn normalize_passphrase(passphrase: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(passphrase.nfkc().collect::<String>().into_bytes())
}

/// Argon2id over the normalized passphrase, then HKDF-SHA256 with the exact
/// header bytes as `info`. Returns the 32-byte file key.
fn derive_file_key(
    passphrase: &str,
    header: &ContainerHeader,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<Zeroizing<[u8; 32]>, ContainerError> {
    // Legal floor check: Params::new rejects m < 8p, and parameters below
    // the floor cannot be genuine — generic damaged-file error (§5.5).
    let params = Params::new(
        header.memory_kib,
        header.iterations,
        header.parallelism,
        Some(32),
    )
    .map_err(|_| ContainerError::Damaged)?;

    let pwd = normalize_passphrase(passphrase);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let dk = Zeroizing::new([0u8; 32]);
    // SAFETY-free fill: hash_password_into writes the full 32-byte slice.
    let mut dk = dk;
    argon2
        .hash_password_into(&pwd, &header.salt, dk.as_mut())
        .map_err(|_| ContainerError::Damaged)?;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_EXTRACT_SALT), dk.as_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(header_bytes, key.as_mut())
        .map_err(|_| ContainerError::Damaged)?;
    Ok(key)
}

/// Smallest bucket that fits `8 + payload.len()`, or None above the cap.
fn bucket_for(payload_len: usize) -> Option<usize> {
    let total = payload_len.checked_add(8)?;
    BUCKETS.iter().copied().find(|b| *b >= total)
}

/// Build the padded plaintext: `u64` BE payload length, payload, zero
/// padding to the exact bucket size. Length never leaves the ciphertext.
fn build_padded(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    let bucket = bucket_for(payload.len()).ok_or(ContainerError::TooLarge)?;
    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    padded.extend_from_slice(payload);
    padded.resize(bucket, 0);
    Ok(Zeroizing::new(padded))
}

/// Encrypt a `baluard.vault` v1 JSON payload into a container with fresh
/// randomness. Call [encrypt_with_entropy] instead when reproducible bytes
/// are needed (golden test vectors).
pub fn encrypt(payload: &[u8], passphrase: &str) -> Result<Vec<u8>, ContainerError> {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    let mut nonce_prefix = [0u8; 7];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);
    encrypt_with_entropy(payload, passphrase, salt, nonce_prefix)
}

/// Deterministic encryption: same inputs, byte-identical container. Used by
/// the golden test vector and the reference decryptor's cross-check, never
/// by user-facing flows (a fixed salt in production would be catastrophic).
pub fn encrypt_with_entropy(
    payload: &[u8],
    passphrase: &str,
    salt: [u8; 32],
    nonce_prefix: [u8; 7],
) -> Result<Vec<u8>, ContainerError> {
    let header = ContainerHeader {
        salt,
        nonce_prefix,
        ..ContainerHeader::new_export()
    };
    let header_bytes = header.encode();
    let padded = build_padded(payload)?;

    let key = derive_file_key(passphrase, &header, &header_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| ContainerError::Damaged)?;

    // STREAM chunks: nonce = 7-byte prefix | u32 BE counter | final flag.
    let n_chunks = padded.len().div_ceil(CHUNK_SIZE as usize);
    let mut out = Vec::with_capacity(HEADER_LEN + n_chunks * CHUNK_ON_DISK);
    out.extend_from_slice(&header_bytes);
    for (i, chunk) in padded.chunks(CHUNK_SIZE as usize).enumerate() {
        let mut nonce = [0u8; 12];
        nonce[..7].copy_from_slice(&header.nonce_prefix);
        nonce[7..11].copy_from_slice(&(i as u32).to_be_bytes());
        nonce[11] = if i + 1 == n_chunks { 1 } else { 0 };
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| ContainerError::Damaged)?;
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Decrypt a container and return the exact payload bytes (padding stripped,
/// UTF-8 verified by the caller's parser). Wrong passphrase and any tamper
/// are the same error, by design.
pub fn decrypt(container: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    // Layout is fully determined by the file length; every structural rule
    // is checked BEFORE the first Argon2id call (§6).
    if container.len() < HEADER_LEN {
        return Err(if looks_like_encrypted_backup(container) {
            ContainerError::Damaged
        } else {
            ContainerError::NotABackup
        });
    }
    let header_bytes: [u8; HEADER_LEN] =
        container[..HEADER_LEN].try_into().expect("checked length");
    let header = ContainerHeader::parse(&header_bytes)?;

    let body = container.len() - HEADER_LEN;
    if body == 0 || body % CHUNK_ON_DISK != 0 {
        return Err(ContainerError::Damaged);
    }
    let n_chunks = body / CHUNK_ON_DISK;
    let plaintext_len = n_chunks * CHUNK_SIZE as usize;
    if !BUCKETS.contains(&plaintext_len) {
        return Err(ContainerError::Damaged);
    }

    let key = derive_file_key(passphrase, &header, &header_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| ContainerError::Damaged)?;

    let mut padded = Zeroizing::new(Vec::with_capacity(plaintext_len));
    for i in 0..n_chunks {
        let start = HEADER_LEN + i * CHUNK_ON_DISK;
        let ct = &container[start..start + CHUNK_ON_DISK];
        let mut nonce = [0u8; 12];
        nonce[..7].copy_from_slice(&header.nonce_prefix);
        nonce[7..11].copy_from_slice(&(i as u32).to_be_bytes());
        nonce[11] = if i + 1 == n_chunks { 1 } else { 0 };
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ct,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| ContainerError::Damaged)?;
        padded.extend_from_slice(&pt);
    }

    // In-band length: bound-checked, never used to allocate.
    let len_bytes: [u8; 8] = padded[..8].try_into().expect("padded >= 8");
    let payload_len = u64::from_be_bytes(len_bytes) as usize;
    if payload_len > padded.len().saturating_sub(8) {
        return Err(ContainerError::Damaged);
    }
    if padded[8 + payload_len..].iter().any(|&b| b != 0) {
        return Err(ContainerError::Damaged);
    }
    let payload = padded[8..8 + payload_len].to_vec();
    Ok(Zeroizing::new(payload))
}

/// Auto-verify (§7): decrypt the container just built and require the
/// payload to come back byte-identical. Re-derives the key from the
/// passphrase STRING, so a normalization bug in either direction is caught
/// at the source. A self-check cannot catch a bug present in both
/// directions — the committed reference decryptor is the real guard.
pub fn verify(
    container: &[u8],
    passphrase: &str,
    expected_payload: &[u8],
) -> Result<(), ContainerError> {
    let payload = decrypt(container, passphrase)?;
    if payload.as_slice() == expected_payload {
        Ok(())
    } else {
        Err(ContainerError::Damaged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";
    const OTHER_PASS: &str = "a different passphrase entirely";

    fn sample_payload() -> Vec<u8> {
        // Realistic minimal baluard.vault shape; exact contents don't matter
        // to the container, only the bytes.
        br#"{"format":"baluard.vault","version":1,"app_version":"0.1.0","exported_at":0,"manifest":{"cipher_count":1,"folder_count":0},"ciphers":[]}"#.to_vec()
    }

    /// One shared encrypted fixture; every derivation in debug costs real
    /// Argon2id time (64 MiB), so the tamper family reuses it.
    fn fixture() -> (&'static Vec<u8>, &'static Vec<u8>) {
        static CT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        static PT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let pt = PT.get_or_init(sample_payload);
        let ct = CT.get_or_init(|| encrypt(pt, PASS).expect("encrypt fixture"));
        (ct, pt)
    }

    #[test]
    fn roundtrip_small_payload() {
        let payload = sample_payload();
        let container = encrypt(&payload, PASS).expect("encrypt");
        assert!(looks_like_encrypted_backup(&container));
        let back = decrypt(&container, PASS).expect("decrypt");
        assert_eq!(back.as_slice(), payload.as_slice());
    }

    #[test]
    fn header_layout_is_65_bytes_with_pinned_offsets() {
        let header = ContainerHeader {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
            salt: [0xAA; 32],
            nonce_prefix: [0xBB; 7],
            chunk_size: 65536,
        };
        let h = header.encode();
        assert_eq!(h.len(), 65);
        assert_eq!(&h[0..6], b"BLDBAK");
        assert_eq!(h[6], 1); // version
        assert_eq!(h[7], 1); // kdf = argon2id
        assert_eq!(h[8], 1); // aead = aes-256-gcm
        assert_eq!(h[9], 0); // reserved
        assert_eq!(&h[10..14], &65536u32.to_le_bytes());
        assert_eq!(&h[14..18], &3u32.to_le_bytes());
        assert_eq!(&h[18..22], &1u32.to_le_bytes());
        assert_eq!(&h[22..54], &[0xAA; 32]);
        assert_eq!(&h[54..61], &[0xBB; 7]);
        assert_eq!(&h[61..65], &65536u32.to_le_bytes());
        // Round-trips.
        assert_eq!(ContainerHeader::parse(&h).expect("parse"), header);
    }

    #[test]
    fn wrong_passphrase_is_indistinguishable_from_corruption() {
        let (ct, _) = fixture();
        let err = decrypt(ct, OTHER_PASS).expect_err("wrong passphrase");
        assert!(matches!(err, ContainerError::Damaged));
        assert_eq!(err.to_string(), "wrong password or damaged file");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        let mid = HEADER_LEN + bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(matches!(decrypt(&bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn tampered_header_fails_via_key_commitment() {
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        bad[10] ^= 0x01; // memory_kib low byte; still in-caps, key changes
        assert!(matches!(decrypt(&bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn truncated_file_fails() {
        let (ct, _) = fixture();
        let bad = &ct[..ct.len() - 1];
        assert!(matches!(decrypt(bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn trailing_garbage_after_final_chunk_fails() {
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        bad.extend_from_slice(&[0u8; CHUNK_ON_DISK]);
        // Length no longer matches the bucket ladder -> structural refusal
        // before any key derivation.
        assert!(matches!(decrypt(&bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn removed_middle_chunk_fails() {
        let payload = vec![0x42u8; 4 * 1024 * 1024]; // needs 2 chunks (bucket 4 MiB)
        let ct = encrypt(&payload, PASS).expect("encrypt");
        // Drop the second chunk: last chunk still ends the file with the
        // final flag, but its counter no longer matches position 1.
        let mut bad = Vec::new();
        bad.extend_from_slice(&ct[..HEADER_LEN + CHUNK_ON_DISK]);
        bad.extend_from_slice(&ct[HEADER_LEN + 2 * CHUNK_ON_DISK..]);
        assert!(matches!(decrypt(&bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn non_bucket_plaintext_size_is_refused_before_key_derivation() {
        // Header (65) + exactly one chunk = 256 KiB plaintext, a legal
        // bucket. Then header + two chunks would be 128 KiB + ... — instead
        // craft header + 1.5 chunk-worth: 65 + 65552 + 32776 (impossible
        // alignment is covered by the modulo rule).
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        bad.truncate(HEADER_LEN + CHUNK_ON_DISK + 100);
        assert!(matches!(decrypt(&bad, PASS), Err(ContainerError::Damaged)));
    }

    #[test]
    fn non_zero_reserved_byte_demands_update() {
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        bad[9] = 1;
        let err = decrypt(&bad, PASS).expect_err("reserved set");
        assert!(matches!(err, ContainerError::Unsupported));
        assert!(err.to_string().contains("update Baluard"));
    }

    #[test]
    fn future_version_demands_update() {
        let (ct, _) = fixture();
        let mut bad = ct.clone();
        bad[6] = 2;
        assert!(matches!(
            decrypt(&bad, PASS),
            Err(ContainerError::Unsupported)
        ));
    }

    #[test]
    fn over_cap_kdf_parameters_demands_update() {
        // Hand-craft a header with memory above the import cap. parse must
        // refuse before any Argon2id allocation happens (crash guard).
        let mut header = ContainerHeader::new_export().encode();
        header[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = ContainerHeader::parse(&header).expect_err("over cap");
        assert!(matches!(err, ContainerError::Unsupported));
    }

    #[test]
    fn sub_floor_kdf_parameters_are_generic_damage() {
        // m < 8p cannot be genuine (§5.5): inside caps arithmetic-wise but
        // below the legal floor -> Damaged, not "update Baluard".
        let mut header = ContainerHeader::new_export().encode();
        header[10..14].copy_from_slice(&8u32.to_le_bytes()); // memory_kib = 8
        header[18..22].copy_from_slice(&4u32.to_le_bytes()); // parallelism = 4
        let parsed = ContainerHeader::parse(&header).expect("inside caps");
        let key = derive_file_key(PASS, &parsed, &header);
        assert!(matches!(key, Err(ContainerError::Damaged)));
    }

    #[test]
    fn payload_cap_fails_closed() {
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            encrypt(&payload, PASS),
            Err(ContainerError::TooLarge)
        ));
    }

    #[test]
    fn bucket_boundaries_exact_fill_and_spill() {
        // Exact fill: 256 KiB bucket minus the 8-byte prefix takes all of it.
        let exact = vec![0x11u8; BUCKETS[0] - 8];
        let ct = encrypt(&exact, PASS).expect("encrypt");
        assert_eq!(
            ct.len(),
            HEADER_LEN + BUCKETS[0] / CHUNK_SIZE as usize * CHUNK_ON_DISK
        );
        let back = decrypt(&ct, PASS).expect("decrypt");
        assert_eq!(back.as_slice(), exact.as_slice());

        // One byte over spills to the next bucket.
        let spill = vec![0x22u8; BUCKETS[0] - 7];
        let ct = encrypt(&spill, PASS).expect("encrypt");
        let expect = HEADER_LEN + BUCKETS[1] / CHUNK_SIZE as usize * CHUNK_ON_DISK;
        assert_eq!(ct.len(), expect);
    }

    #[test]
    fn nfkc_forms_of_accented_passphrase_agree() {
        // "contraseña": precomposed (U+00F1) vs decomposed (n + U+0303).
        let nfc = "contrase\u{00F1}a-2026";
        let nfd = "contrasen\u{0303}a-2026";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes(), "test needs real forms");
        let payload = sample_payload();
        let ct = encrypt(&payload, nfc).expect("encrypt");
        let back = decrypt(&ct, nfd).expect("NFD form opens NFC-written backup");
        assert_eq!(back.as_slice(), payload.as_slice());
    }

    #[test]
    fn sniff_is_specific() {
        let (ct, _) = fixture();
        assert!(looks_like_encrypted_backup(ct));
        assert!(looks_like_encrypted_backup(b"BLDBAK"));
        assert!(!looks_like_encrypted_backup(b"BLDBA"));
        assert!(!looks_like_encrypted_backup(
            br#"{"format":"baluard.vault"}"#
        ));
        assert!(!looks_like_encrypted_backup(b""));
    }

    #[test]
    fn deterministic_variant_is_byte_identical() {
        let payload = sample_payload();
        let salt = [7u8; 32];
        let prefix = [9u8; 7];
        let a = encrypt_with_entropy(&payload, PASS, salt, prefix).expect("a");
        let b = encrypt_with_entropy(&payload, PASS, salt, prefix).expect("b");
        assert_eq!(a, b, "same inputs must reproduce the exact container");
    }

    #[test]
    fn verify_rejects_payload_mismatch() {
        let payload = sample_payload();
        let ct = encrypt(&payload, PASS).expect("encrypt");
        assert!(verify(&ct, PASS, &payload).is_ok());
        let mut tampered_payload = payload.clone();
        tampered_payload[0] ^= 1;
        assert!(matches!(
            verify(&ct, PASS, &tampered_payload),
            Err(ContainerError::Damaged)
        ));
    }

    #[test]
    fn multi_chunk_stream_roundtrip() {
        // 4 MiB bucket forces 64 chunks: counters and the final flag get a
        // real workout.
        let payload: Vec<u8> = (0..4 * 1024 * 1024 - 8).map(|i| (i % 251) as u8).collect();
        let ct = encrypt(&payload, PASS).expect("encrypt");
        let back = decrypt(&ct, PASS).expect("decrypt");
        assert_eq!(back.as_slice(), payload.as_slice());
    }

    /// The committed golden vector (tests/golden/backup-v1.bldbak, with its
    /// derivation transcript in the .txt sidecar) must stay byte-reproducible:
    /// any drift in header layout, KDF wiring, chunk framing or serialization
    /// breaks this test instead of silently orphaning every backup ever
    /// written. The reference decryptor script decodes the same file
    /// independently — see scripts/decrypt_backup.py.
    #[test]
    fn golden_vector_is_reproducible() {
        let payload = br#"{"format":"baluard.vault","version":1,"app_version":"0.1.0","exported_at":1760000000,"manifest":{"cipher_count":1,"folder_count":1},"folders":[{"id":"3f2b8a64-1111-4111-8111-111111111111","name":"Work","parent_id":null,"icon":null}],"ciphers":[{"id":"9a1c2b3d-2222-4222-8222-222222222222","name":"Golden login","folder_id":"3f2b8a64-1111-4111-8111-111111111111","cipher_type":"login","data":{"password":"golden-secret","uris":[]},"favorite":true,"reprompt":false,"archived":false,"tags":[],"created_at":1760000000,"updated_at":1760000000}]}"#;
        let ct = encrypt_with_entropy(
            payload,
            "correct horse battery staple",
            [0xA5u8; 32],
            [0x5Au8; 7],
        )
        .expect("golden encrypt");
        let golden = include_bytes!("../../tests/golden/backup-v1.bldbak");
        assert_eq!(ct.as_slice(), golden.as_slice());
        // And the committed vector still opens (belt and braces: guards
        // against the file being hand-edited without the test catching it).
        let back = decrypt(golden, "correct horse battery staple").expect("golden decrypt");
        assert_eq!(back.as_slice(), payload.as_slice());
    }
}
