//! Credential store backed by Baluard's decrypted cipher envelopes.
//!
//! Implements `passkey_authenticator::CredentialStore` so the passkey-rs
//! Client can look up, save, and update passkey credentials.

use std::collections::HashMap;

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
        let mut entries = HashMap::new();
        for cipher in ciphers {
            if let CipherKind::Passkey(data) = &cipher.kind {
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
fn passkey_data_to_passkey(data: &PasskeyData) -> Option<Passkey> {
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
        counter: if data.counter > 0 { Some(data.counter) } else { None },
        extensions: Default::default(),
    })
}

/// In-memory credential store for a single ceremony.
///
/// Built from the vault's passkey index. After the ceremony, the daemon
/// writes back any changes (new credential or counter update).
pub struct BaluardCredentialStore {
    inner: HashMap<Vec<u8>, Passkey>,
}

impl BaluardCredentialStore {
    pub fn from_index(index: &PasskeyIndex) -> Self {
        let inner = index
            .entries()
            .iter()
            .map(|(id, (pk, _, _))| (id.clone(), pk.clone()))
            .collect();
        Self { inner }
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
        let mut results: Vec<Passkey> = Vec::new();
        match ids {
            Some(descriptors) => {
                for desc in descriptors {
                    if let Some(pk) = self.inner.get(&*desc.id) {
                        if pk.rp_id == rp_id {
                            results.push(pk.clone());
                        }
                    }
                }
            }
            None => {
                for pk in self.inner.values() {
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
        self.inner.insert(cred.credential_id.to_vec(), cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: &Passkey) -> Result<(), StatusCode> {
        self.inner.insert(cred.credential_id.to_vec(), cred.clone());
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}
