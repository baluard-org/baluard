//! S1b-3 signed head gossip — rollback detection (plan security note 10).
//!
//! Each device announces the newest main-branch head it produced or
//! observed on a dedicated `baluard-gossip` branch. The branch is a side
//! channel: force-rewinding main does NOT touch it, so the evidence of a
//! discarded head survives the rollback that destroyed it. Every
//! announcement is Ed25519-signed by the announcing device's key and
//! carries the announced commit as a second parent, so the announced
//! history stays REACHABLE from the gossip branch — a fresh clone of a
//! rolled-back vault receives both the rewound main AND the proof that a
//! later head existed.
//!
//! Enforcement runs on every pull and every clone: an announcement whose
//! head exists in the object store but is NOT contained in the fetched
//! main history means someone moved main backwards — refused outright
//! (fail closed) and recorded locally via the S1b-1 refusal log.
//!
//! Gossip is a DENY-ONLY channel: it can refuse a pull, never admit
//! content. Only a signature verifying against a roster key grants any
//! refusal power — unparseable and unverifiable files are equally inert
//! (the branch is writable by any device, so treating junk as
//! authoritative would be a one-file pull DoS).
//!
//! Boundaries (documented, priced in the plan): an attacker with full
//! push access can force-push the gossip branch too — that escalation is
//! quorum-signed rewind territory (P8c/S4), not this layer. Concurrent
//! gossip publishers race on the branch push; the loser retries on the
//! next sync cycle (announcements are advisory telemetry — a missed one
//! only delays detection).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::SyncError;

/// LEGACY side branch written by pre notes-ref versions. New code never
/// creates it; the constant names the ref so the migration can find,
/// consume, and delete it on repos upgraded in place.
pub const GOSSIP_BRANCH: &str = "baluard-gossip";

/// The gossip channel: a ref under refs/notes, invisible to the forge
/// branch and tag lists, so the user's repository carries exactly one
/// branch (main, or master on older setups). Notes refs fetch and push
/// through explicit refspecs like any other ref.
pub const GOSSIP_REF: &str = "refs/notes/baluard-gossip";

/// Tracking-ref short name under refs/remotes/<remote>/.
pub const GOSSIP_TRACKING: &str = "gossip";

/// Directory inside the gossip branch tree.
pub const GOSSIP_DIR: &str = "heads";

/// Domain separator for announcement signatures.
const DOMAIN: &str = "baluard-head-gossip/v1";

/// One device's claim: "I observed main at `head`".
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HeadAnnouncement {
    /// Announcing device id (registry key).
    pub device_id: String,
    /// Announced main-branch commit oid (40-hex).
    pub head: String,
    /// Unix seconds at announcement.
    pub at: u64,
    /// Hex Ed25519 signature over the canonical payload.
    pub sig: String,
}

/// Canonical, domain-separated signing payload. `vault_tag` is the root
/// commit oid of the vault's main history — immutable, unique per vault,
/// and computable from any clone (a stable vault identity without the KDF).
fn canonical_payload(vault_tag: &str, device_id: &str, head: &str, at: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(DOMAIN.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(vault_tag.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(device_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(head.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(at.to_string().as_bytes());
    buf
}

impl HeadAnnouncement {
    /// Sign a fresh announcement for `head` observed now.
    pub fn sign(
        vault_tag: &str,
        device_id: &str,
        head: &str,
        at: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let payload = canonical_payload(vault_tag, device_id, head, at);
        let sig = signing_key.sign(&payload);
        Self {
            device_id: device_id.to_string(),
            head: head.to_string(),
            at,
            sig: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify against the announcing device's roster pubkey. Any mismatch
    /// (vault, device, head, timestamp, signature) fails closed.
    pub fn verify(&self, vault_tag: &str, device_pubkey: &[u8; 32]) -> Result<(), SyncError> {
        let payload = canonical_payload(vault_tag, &self.device_id, &self.head, self.at);
        let vk = VerifyingKey::from_bytes(device_pubkey)
            .map_err(|_| SyncError::Git("gossip: bad device pubkey".into()))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or_else(|| SyncError::Git("gossip: malformed signature".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&payload, &sig)
            .map_err(|_| SyncError::Git("gossip: announcement signature invalid".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let ann = HeadAnnouncement::sign("roottag", "dev-1", &"a".repeat(40), 1234, &key);
        ann.verify("roottag", &key.verifying_key().to_bytes())
            .unwrap();
    }

    #[test]
    fn verify_refuses_tampered_fields() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let other = crate::crypto::signature::generate_ed25519_keypair().0;
        let ann = HeadAnnouncement::sign("roottag", "dev-1", &"a".repeat(40), 1234, &key);
        let vk = key.verifying_key().to_bytes();

        // Wrong vault tag.
        assert!(ann.verify("othertag", &vk).is_err());
        // Wrong device key.
        assert!(
            ann.verify("roottag", &other.verifying_key().to_bytes())
                .is_err()
        );
        // Tampered head.
        let mut tampered = ann.clone();
        tampered.head = "b".repeat(40);
        assert!(tampered.verify("roottag", &vk).is_err());
        // Tampered timestamp.
        let mut tampered = ann.clone();
        tampered.at = 9999;
        assert!(tampered.verify("roottag", &vk).is_err());
        // Malformed signature.
        let mut tampered = ann;
        tampered.sig = "zz".into();
        assert!(tampered.verify("roottag", &vk).is_err());
    }
}
