//! Baluard daemon library surface.
//!
//! The daemon is structured as a library + thin binary so the host, state,
//! and handler modules are unit/integration-testable. `main.rs` only wires
//! CLI parsing + the tokio runtime + signal handling; everything else
//! lives here.

pub mod autosync;
pub mod crypto;
pub mod handler;
pub mod host;
pub mod rate_limit;
pub mod socket_path;
pub mod state;

pub mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
    include!(concat!(env!("OUT_DIR"), "/baluard.vault.rs"));
    include!(concat!(env!("OUT_DIR"), "/baluard.space.rs"));
}
