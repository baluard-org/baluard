# ADR 0001. Rust Core and Memory Security

> Status: Accepted

## Context

Baluard handles cryptographic operations, Git operations, padding, and secret loading. These operations require control over secret memory and protection against secrets being paged to disk or exposed in core dumps.

## Decision

The `baluard-core` crate will implement all cryptographic operations, Git operations through `git2-rs`, padding, and secret loading in compiled Rust. Secret values, including decrypted keys and entries, will use `Zeroize`-derived structures. The daemon will keep vault data in locked memory regions.

**Zeroization.** All wiping uses `zeroize::Zeroize`, which performs volatile writes. Hand-written wipe loops are forbidden because the compiler can eliminate them as dead stores in release builds. Key types implement a redacting `Debug` so a key cannot reach a log line through formatting.

**Locked memory.** Root Key (64 bytes), Space Group Key (32 bytes), and Item Keys (32 bytes) are heap-allocated in a `Box` so their address stays stable across moves, and each is locked with `mlock` at construction. `Clone` re-locks the new copy, and the region is unlocked on drop. Locking is best-effort: a failure (for example `RLIMIT_MEMLOCK` exhaustion) is silent and never blocks unlock. The implementation calls `libc::mlock` directly on Unix. Non-Unix targets compile the lock calls as no-ops, so Windows relies on zeroization alone for key material in the daemon.

**Residency budget.** With several vaults unlocked at once, resident key bytes scale with the vault count. After every unlock the host logs the fixed baseline (96 bytes per vault: Root Key plus SGK) against the soft `RLIMIT_MEMLOCK` and warns when the baseline is within twice the limit; older Linux defaults are 64 KB. The baseline is a floor, not the full footprint: it excludes transient Item Keys, and the KEK and device private key may also be resident while a vault is unlocked.

**Limits of the guarantee.** `mlock` addresses paging to swap. It does not defend against a process-memory read by malware running with the daemon's privileges or with OS root, and source contains no separate core-dump suppression. The mitigation for dumps and memory scraping is a short key lifetime: auto-lock, lock-all on focus loss, and zeroize on drop. Key-process isolation from the UI is covered by ADR 0009, and threat actor E in `docs/security/threat-model.md` carries the residual risk.

## Consequences

Secrets remain in memory only for the operations that need them and are zeroized afterward. Locked memory reduces exposure through swap, with the cost of platform-specific memory limits: on low-limit systems many unlocked vaults can exhaust the lock budget, in which case locking degrades silently and only the log line makes it visible. The mobile client hosts the same runtime in-process, so the same key types and the same best-effort locking apply there (ADR 0010).

## References

- `crates/baluard-core/src/keys/hierarchy.rs`
- `crates/baluard-runtime/src/host.rs` (`VaultHost::log_mlock_budget`)
- `docs/security/threat-model.md` (T6, T15, actor E)
