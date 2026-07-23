package xyz.actitud.baluard.data

import xyz.actitud.baluard.generateRecoveryPhrase
import xyz.actitud.baluard.MobileRecoveryPhrase

/**
 * Thin wrapper over the UniFFI-generated Kotlin bindings.
 *
 * Phase 1: exposes the spike fn (recovery phrase generation) so the hello-world
 * screen can prove the Rust round-trip. Phase 2+ grows this into the full
 * vault/cipher/sync surface (see plan §3.3 API draft).
 *
 * NOTE: the generated binding functions (e.g. `generateRecoveryPhrase()`) are
 * top-level Kotlin fns produced by uniffi-bindgen from the Rust
 * `#[uniffi::export] pub fn generate_recovery_phrase()`. They land in package
 * `xyz.actitud.baluard` (set in uniffi.toml). Commit the generated sources;
 * regenerate only when the Rust API changes.
 */
class VaultRepository {
    fun generateRecoveryPhrase(): MobileRecoveryPhrase =
        generateRecoveryPhrase()
}
