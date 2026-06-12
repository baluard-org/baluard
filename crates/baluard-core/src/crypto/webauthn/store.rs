//! Credential store backed by Baluard's decrypted cipher envelopes.
//!
//! Implements `passkey_authenticator::CredentialStore` so the passkey-rs
//! Client can look up, save, and update passkey credentials.
//!
//! Uses `Arc<Mutex<>>` internally so the daemon can extract ceremony
//! results (new credential or counter update) after the passkey-rs
//! `Client::register()` / `Client::authenticate()` call completes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use passkey::authenticator::{CredentialStore, DiscoverabilitySupport, StoreInfo};
use passkey::types::{
    Passkey,
    ctap2::{
        StatusCode,
        get_assertion::Options,
        make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
    },
    webauthn::PublicKeyCredentialDescriptor,
};
use uuid::Uuid;
use base64::Engine;
use coset::CborSerializable;

use crate::types::{Cipher, CipherKind, PasskeyData};

/// A passkey item that the `passkey-rs` authenticator can use,
/// tagged with its Baluard cipher ID for write-back.
#[derive(Clone, Debug)]
pub struct BaluardPasskeyItem {
    /// The passkey-rs native passkey.
    pub passkey: Passkey,
    /// Baluard cipher UUID.
    pub cipher_id: Uuid,
}

/// Read-only snapshot of passkey ciphers from the vault.
/// The daemon constructs this from decrypted ciphers before each ceremony.
pub struct PasskeyIndex {
    /// credential_id bytes → (Passkey, PasskeyData, cipher_id)
    entries: HashMap<Vec<u8>, (Passkey, PasskeyData, Uuid)>,
}

impl PasskeyIndex {
    /// Build from decrypted ciphers. Skips imported BW passkeys
    /// (private_key_missing) and malformed entries.
    pub fn from_ciphers(ciphers: &[Cipher]) -> Self {
        Self::from_cipher_refs(ciphers.iter())
    }

    /// Build from a slice of boxed ciphers (convenience for daemon).
    pub fn from_boxed_ciphers(ciphers: &[Box<Cipher>]) -> Self {
        Self::from_cipher_refs(ciphers.iter().map(|b| b.as_ref()))
    }

    fn from_cipher_refs<'a, I: Iterator<Item = &'a Cipher>>(iter: I) -> Self {
        let mut entries = HashMap::new();
        for cipher in iter {
            match &cipher.kind {
                CipherKind::Login(data) => {
                    if let Some(ref fido2_list) = data.fido2_credentials {
                        for data in fido2_list {
                            if data.private_key_missing || data.private_key.is_none() {
                                continue;
                            }
                            let cred_id = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(&data.credential_id)
                            {
                                Ok(b) => b,
                                Err(_) => continue,
                            };
                            let pk = match passkey_data_to_passkey(data) {
                                Some(pk) => pk,
                                None => continue,
                            };
                            entries.insert(cred_id, (pk, data.clone(), cipher.id));
                        }
                    }
                }
                _ => {}
            }
        }
        Self { entries }
    }

    /// All entries for a given RP (for discoverable credential queries).
    pub fn by_rp(&self, rp_id: &str) -> Vec<&(Passkey, PasskeyData, Uuid)> {
        self.entries
            .values()
            .filter(|(pk, _, _)| pk.rp_id == rp_id)
            .collect()
    }

    /// All entries.
    pub fn entries(&self) -> &HashMap<Vec<u8>, (Passkey, PasskeyData, Uuid)> {
        &self.entries
    }
}

/// Convert `PasskeyData` → `passkey_types::Passkey`.
pub(crate) fn passkey_data_to_passkey(data: &PasskeyData) -> Option<Passkey> {
    let private_key_bytes = data.private_key.as_ref()?;
    let cose_key = coset::CoseKey::from_slice(private_key_bytes).ok()?;
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&data.credential_id)
        .ok()?
        .into();

    Some(Passkey {
        key: cose_key,
        credential_id,
        rp_id: data.rp_id.clone(),
        user_handle: data.user_handle.clone().map(Into::into),
        username: data.user_name.clone(),
        user_display_name: data.user_display_name.clone(),
        counter: Some(data.counter),
        extensions: Default::default(),
    })
}

/// Convert a `passkey_types::Passkey` (from ceremony result) to `PasskeyData`
/// for vault storage. The COSE key pair is serialized to CBOR bytes.
pub fn passkey_to_passkey_data(
    pk: &Passkey,
    rp_name: Option<&str>,
) -> Option<PasskeyData> {
    let private_key = pk.key.clone().to_vec().ok()?;
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&*pk.credential_id);
    // key_value stores the full COSE key (CBOR-encoded, same bytes as private_key).
    // In Phase 2, extract just the public key (x || y coordinates) for interop.
    let key_value = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&private_key);

    Some(PasskeyData {
        rp_id: pk.rp_id.clone(),
        rp_name: rp_name.map(|s| s.to_string()),
        credential_id,
        key_type: "public-key".to_string(),
        key_algorithm: "ECDSA".to_string(),
        key_curve: "P-256".to_string(),
        key_value,
        user_handle: pk.user_handle.as_ref().map(|h| h.to_vec()),
        user_name: pk.username.clone(),
        user_display_name: pk.user_display_name.clone(),
        private_key: Some(private_key),
        counter: pk.counter.unwrap_or(0),
        aaguid: Uuid::nil(), // Self-attestation (empty AAGUID)
        creation_date: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        private_key_missing: false,
        prf_key: None,
        linked_login_id: None,
    })
}

// ── Inner store (shared behind Arc<Mutex>) ──

struct StoreInner {
    credentials: HashMap<Vec<u8>, Passkey>,
    /// New credentials saved during this ceremony (registration).
    new_credentials: Vec<Passkey>,
    /// Counter updates during this ceremony (credential_id → new counter).
    counter_updates: HashMap<Vec<u8>, u32>,
}

/// In-memory credential store for a single ceremony.
///
/// Built from the vault's passkey index. Uses `Arc<Mutex<>>` internally
/// so the daemon can extract ceremony results after the passkey-rs
/// `Client::register()` / `Client::authenticate()` call completes.
///
/// Clone shares the underlying data — keep a clone for post-ceremony
/// extraction, move the original into the passkey-rs `Authenticator`.
pub struct BaluardCredentialStore {
    inner: Arc<Mutex<StoreInner>>,
}

impl Clone for BaluardCredentialStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl BaluardCredentialStore {
    pub fn from_index(index: &PasskeyIndex) -> Self {
        let credentials = index
            .entries()
            .iter()
            .map(|(id, (pk, _, _))| (id.clone(), pk.clone()))
            .collect();
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                credentials,
                new_credentials: Vec::new(),
                counter_updates: HashMap::new(),
            })),
        }
    }

    /// Create an empty store (for registration with no existing passkeys).
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                credentials: HashMap::new(),
                new_credentials: Vec::new(),
                counter_updates: HashMap::new(),
            })),
        }
    }

    /// Extract and clear new credentials saved during ceremony.
    /// Call after `client.register()` to get the new passkey(s).
    pub fn take_new_credentials(&self) -> Vec<Passkey> {
        std::mem::take(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()).new_credentials)
    }

    /// Extract and clear counter updates from ceremony.
    /// Call after `client.authenticate()` to get updated counters.
    pub fn take_counter_updates(&self) -> HashMap<Vec<u8>, u32> {
        std::mem::take(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()).counter_updates)
    }
}

impl Drop for BaluardCredentialStore {
    fn drop(&mut self) {
        // Best-effort: clear key material. Only effective when this is
        // the last Arc reference. Otherwise the Mutex is still shared.
        if let Ok(mut inner) = self.inner.lock() {
            inner.credentials.clear();
            inner.new_credentials.clear();
            inner.counter_updates.clear();
        }
    }
}

#[async_trait]
impl CredentialStore for BaluardCredentialStore {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        _user_handle: Option<&[u8]>,
    ) -> Result<Vec<Passkey>, StatusCode> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut results: Vec<Passkey> = Vec::new();
        match ids {
            Some(descriptors) => {
                for desc in descriptors {
                    if let Some(pk) = inner.credentials.get(&*desc.id) {
                        if pk.rp_id == rp_id {
                            results.push(pk.clone());
                        }
                    }
                }
            }
            None => {
                for pk in inner.credentials.values() {
                    if pk.rp_id == rp_id {
                        results.push(pk.clone());
                    }
                }
            }
        }
        Ok(results)
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: Options,
    ) -> Result<(), StatusCode> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.new_credentials.push(cred.clone());
        inner.credentials.insert(cred.credential_id.to_vec(), cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: &Passkey) -> Result<(), StatusCode> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let new_counter = cred.counter.unwrap_or(0);
        inner.counter_updates.insert(cred.credential_id.to_vec(), new_counter);
        inner.credentials.insert(cred.credential_id.to_vec(), cred.clone());
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}
