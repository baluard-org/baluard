//! WebAuthn authenticator ceremony module.
//!
//! Uses `passkey-rs` as the authenticator. Baluard acts as a software
//! platform authenticator: generates passkeys at registration, serves
//! them at assertion. Private keys encrypted under the cipher item key.
//!
//! See `docs/plan-passkey-support.md` Phase 1 and
//! `docs/plan-passkey-rs-evaluation.md` for the evaluation.

pub mod ceremony;
pub mod store;

pub use ceremony::{
    AssertionResult, BaluardUserValidation, CEREMONY_TTL, CeremonyCache, CeremonyId, CeremonyState,
    ProviderAssertionResult, ProviderRegistrationResult, RegistrationResult, run_assertion,
    run_provider_assertion, run_provider_registration, run_registration,
};
pub use store::{BaluardCredentialStore, PasskeyIndex};
