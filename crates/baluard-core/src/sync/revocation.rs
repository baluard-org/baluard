//! P8b: append-only revocation manifests.
//!
//! A rejected or smuggled commit cannot be force-pushed away under
//! branch protection. The recovery path is an append-only manifest:
//! an enrolled device signs an entry naming the bad commit; every
//! client that pulls the manifest restores the affected paths from
//! the commit's first-parent tree (the last clean state) and commits
//! the restore, burying the bad content without history rewriting.
//!
//! Trust model: entries are signed with the revoking device's Ed25519
//! key and verified against the roster snapshot in force at the
//! manifest commit (same first-parent rule as P2 commit verification).
//! There are no roles yet — every enrolled device is admin-equivalent;
//! role gating tightens at S1a. A vault with no roster at all
//! (pre-enrollment) has no trust anchor, so manifests are ignored
//! there with a warning rather than failing every pull.
//!
//! The manifest file `meta/revocations.json` is git-tracked and
//! append-only by convention: entries are only ever added, never
//! edited or removed, and each manifest commit is itself signed and
//! roster-verified like any other commit.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Path of the manifest inside the vault (git-tracked).
pub const REVOCATIONS_PATH: &str = "meta/revocations.json";

/// Domain-separation tag for entry signatures. The signed payload is
/// this tag plus the entry fields joined with newlines; the reason is
/// last, so trailing content cannot be confused with other fields.
const SIG_DOMAIN: &str = "baluard-revoke/v1";

/// One append-only manifest entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Monotonic sequence number (max existing + 1, starts at 1).
    pub seq: u64,
    /// Full 40-hex commit hash being revoked.
    pub commit: String,
    /// Free-text reason (surfaced in Activity later).
    pub reason: String,
    /// Unix seconds at revocation time.
    pub revoked_at: u64,
    /// Revoking device's UUID (must be in the roster snapshot).
    pub device_id: String,
    /// Base64 Ed25519 signature over [`RevocationEntry::signed_payload`].
    pub sig: String,
}

impl RevocationEntry {
    /// Canonical bytes covered by the signature. Both signer and
    /// verifier build this from parsed fields, so JSON serialization
    /// order never affects validity.
    pub fn signed_payload(&self) -> Vec<u8> {
        format!(
            "{SIG_DOMAIN}\n{}\n{}\n{}\n{}\n{}",
            self.seq, self.commit, self.revoked_at, self.device_id, self.reason
        )
        .into_bytes()
    }

    /// Verify this entry's signature against a roster device key.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.sig)
                .map_err(|e| format!("sig base64: {e}"))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig shape: {e}"))?;
        verifying_key
            .verify(&self.signed_payload(), &sig)
            .map_err(|e| format!("signature verify: {e}"))
    }
}

/// The whole manifest: parsed `meta/revocations.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevocationManifest {
    pub entries: Vec<RevocationEntry>,
}

impl RevocationManifest {
    /// Parse the manifest from raw JSON bytes. Present-but-unparseable
    /// is a hard error (tamper, fail closed) — callers turn this into
    /// `SyncError::RevocationInvalid`.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut manifest: RevocationManifest =
            serde_json::from_slice(bytes).map_err(|e| format!("manifest JSON: {e}"))?;
        for entry in &mut manifest.entries {
            Self::validate_shape(entry)?;
        }
        Ok(manifest)
    }

    /// Shape checks that do not need the roster: full-length hex
    /// commit, non-empty device id without delimiters, bounded reason,
    /// seq headroom (next_seq must never overflow).
    fn validate_shape(entry: &mut RevocationEntry) -> Result<(), String> {
        if entry.commit.len() != 40 || !entry.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "entry seq {}: commit must be 40 hex chars",
                entry.seq
            ));
        }
        // Comparisons are against git's lowercase oid strings; an uppercase
        // entry would pass shape checks yet silently never match a head.
        entry.commit.make_ascii_lowercase();
        if entry.device_id.is_empty() || entry.device_id.contains(['\n', '\r']) {
            return Err(format!(
                "entry seq {}: device_id must be non-empty without line breaks",
                entry.seq
            ));
        }
        if entry.reason.len() > 512 {
            return Err(format!("entry seq {}: reason too long", entry.seq));
        }
        if entry.seq == 0 || entry.seq == u64::MAX {
            return Err("entry seq must be in 1..u64::MAX".to_string());
        }
        Ok(())
    }

    /// Next sequence number (max + 1, saturating — shape validation
    /// keeps u64::MAX out of the file, so this cannot wrap).
    pub fn next_seq(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.seq)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// Whether a commit hash is already revoked.
    pub fn contains_commit(&self, commit: &str) -> bool {
        self.entries.iter().any(|e| e.commit == commit)
    }

    /// Serialize to pretty JSON for the git-tracked file.
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| format!("manifest serialize: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (ed25519_dalek::SigningKey, VerifyingKey) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sign_entry(entry: &RevocationEntry, sk: &ed25519_dalek::SigningKey) -> String {
        use base64::Engine;
        use ed25519_dalek::Signer;
        base64::engine::general_purpose::STANDARD
            .encode(sk.sign(&entry.signed_payload()).to_bytes())
    }

    fn sample_entry() -> RevocationEntry {
        RevocationEntry {
            seq: 1,
            commit: "a".repeat(40),
            reason: "smuggled content".into(),
            revoked_at: 1_700_000_000,
            device_id: "01234567-1234-1234-1234-0123456789ab".into(),
            sig: String::new(),
        }
    }

    #[test]
    fn signed_payload_is_field_bound() {
        let e1 = sample_entry();
        let mut e2 = e1.clone();
        e2.reason = "different".into();
        assert_ne!(e1.signed_payload(), e2.signed_payload());
        let mut e3 = e1.clone();
        e3.seq = 2;
        assert_ne!(e1.signed_payload(), e3.signed_payload());
        // Domain tag present so revocation sigs cannot be replayed in
        // another protocol context.
        assert!(e1.signed_payload().starts_with(SIG_DOMAIN.as_bytes()));
    }

    #[test]
    fn signature_roundtrip_and_rejection() {
        let (sk, vk) = test_keypair();
        let mut entry = sample_entry();
        entry.sig = sign_entry(&entry, &sk);
        assert!(entry.verify_signature(&vk).is_ok());

        // Any field change breaks the signature.
        let mut tampered = entry.clone();
        tampered.reason = "evil".into();
        assert!(tampered.verify_signature(&vk).is_err());

        // Wrong key fails.
        let (_sk2, vk2) = test_keypair();
        let mut sk2_bytes = [7u8; 32];
        sk2_bytes[0] = 8;
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&sk2_bytes);
        entry.sig = sign_entry(&entry, &sk2);
        assert!(entry.verify_signature(&vk2).is_err());
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        let (sk, _vk) = test_keypair();
        let mut entry = sample_entry();
        entry.sig = sign_entry(&entry, &sk);

        let ok = RevocationManifest {
            entries: vec![entry.clone()],
        };
        assert!(RevocationManifest::parse(&ok.to_json().unwrap()).is_ok());

        // Short commit hash refused.
        let mut short = entry.clone();
        short.commit = "abc123".into();
        let m = RevocationManifest {
            entries: vec![short],
        };
        assert!(RevocationManifest::parse(&m.to_json().unwrap()).is_err());

        // Empty device id refused.
        let mut empty_dev = entry.clone();
        empty_dev.device_id = String::new();
        let m = RevocationManifest {
            entries: vec![empty_dev],
        };
        assert!(RevocationManifest::parse(&m.to_json().unwrap()).is_err());

        // Garbage JSON refused.
        assert!(RevocationManifest::parse(b"{not json").is_err());

        // Empty manifest is valid.
        let empty = RevocationManifest::default();
        assert_eq!(empty.entries.len(), 0);
        assert_eq!(empty.next_seq(), 1);
    }

    #[test]
    fn seq_and_dedup_helpers() {
        let (sk, _vk) = test_keypair();
        let mut entry = sample_entry();
        entry.sig = sign_entry(&entry, &sk);
        let mut second = entry.clone();
        second.seq = 5;
        let m = RevocationManifest {
            entries: vec![entry.clone(), second],
        };
        assert_eq!(m.next_seq(), 6);
        assert!(m.contains_commit(&entry.commit));
        assert!(!m.contains_commit(&"b".repeat(40)));
    }
}
