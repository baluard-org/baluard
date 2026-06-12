//! WebAuthn authenticator ceremony module.
//!
//! Uses `passkey-rs` as the authenticator. Baluard acts as a software
//! platform authenticator: generates passkeys at registration, serves
//! them at assertion. Private keys encrypted under the cipher item key.
//!
//! See `docs/plan-passkey-support.md` Phase 1 and
//! `docs/adr/0007-passkey-rs-evaluation.md` for the evaluation.

pub mod ceremony;
pub mod store;

pub use ceremony::{
    BaluardUserValidation, CeremonyCache, CeremonyId, CeremonyState, CEREMONY_TTL,
    RegistrationResult, AssertionResult, run_registration, run_assertion,
};
pub use store::{BaluardCredentialStore, PasskeyIndex};
