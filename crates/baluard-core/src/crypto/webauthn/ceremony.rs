//! WebAuthn ceremony types and state cache.
//!
//! The daemon builds a `BaluardCredentialStore` from the vault's passkey
//! index, passes it to the `passkey-rs` Client for the ceremony, then
//! writes back any changes. Ceremony state lives in a TTL cache (300s).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::types::PasskeyData;

/// TTL for pending ceremony states.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Pending ceremony state.
#[derive(Debug)]
pub enum CeremonyState {
    Registration {
        rp_id: String,
        rp_name: String,
        user_name: String,
        user_display_name: String,
        user_id: Vec<u8>,
        created_at: Instant,
    },
    Assertion {
        rp_id: String,
        created_at: Instant,
    },
}

impl CeremonyState {
    pub fn is_expired(&self) -> bool {
        let at = match self {
            Self::Registration { created_at, .. } => created_at,
            Self::Assertion { created_at, .. } => created_at,
        };
        at.elapsed() > CEREMONY_TTL
    }
}

/// Opaque handle returned by start_* and passed to finish_*.
/// Must be generated from CSRNG (32 bytes hex minimum) when wired.
pub type CeremonyId = String;

/// Ceremony state cache. Lives in the daemon's VaultState.
pub struct CeremonyCache {
    states: RwLock<HashMap<CeremonyId, CeremonyState>>,
}

impl CeremonyCache {
    pub fn new() -> Self {
        Self { states: RwLock::new(HashMap::new()) }
    }

    pub async fn insert(&self, id: CeremonyId, state: CeremonyState) {
        self.states.write().await.insert(id, state);
    }

    pub async fn remove(&self, id: &str) -> Option<CeremonyState> {
        self.states.write().await.remove(id)
    }

    /// Evict expired entries.
    pub async fn evict_expired(&self) {
        self.states.write().await.retain(|_, s| !s.is_expired());
    }
}

/// Result of a successful registration ceremony.
pub struct RegistrationResult {
    pub passkey_data: PasskeyData,
    pub credential_id_b64: String,
}

/// Result of a successful assertion ceremony.
pub struct AssertionResult {
    pub credential_id_b64: String,
    pub new_counter: u32,
}
