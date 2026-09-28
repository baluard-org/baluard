//! Baluard daemon library surface.
//!
//! Thin shell over [`baluard_runtime`] (Phase 0 extraction,
//! `docs/plan-mobile-apps.md`). The vault-session orchestration — host, state,
//! autosync coordinator, PIN escrow, bridge registry, rate limiting — now lives
//! in the runtime crate so both this daemon (desktop) and a future mobile app
//! can host it in-process. This crate re-exports those modules at the daemon's
//! crate root so existing `crate::state::VaultState`-style paths inside
//! `handler.rs` / `main.rs` keep resolving unchanged.
//!
//! What stays daemon-only: the Unix-socket listener (`main.rs`), protobuf
//! request routing (`handler.rs`), and socket-path discovery. The protobuf
//! schema lives in the `proto` module below.

// Re-export the runtime's public modules at the crate root. This keeps the
// daemon's internal paths (`crate::state`, `crate::host`, …) working without
// touching every call site in handler.rs / main.rs.
pub use baluard_runtime::{autosync, bridge, crypto, host, pin, rate_limit, state};

pub mod handler;
pub mod socket_path;

pub mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
    include!(concat!(env!("OUT_DIR"), "/baluard.vault.rs"));
}
