//! Shared protobuf wire types (`GatewayRequest` / `GatewayResponse` and the
//! reference vault schema), generated once from `proto/*.proto`.
//!
//! Lives outside `baluard-daemon` so every transport (Unix-socket daemon,
//! CLI client, NMH proxy, mobile UniFFI surface) speaks the identical
//! request/response shape — ADR 0114 work item 0: the bridge dispatch
//! contract must be implementable without linking the daemon.

#![allow(clippy::doc_markdown)]

/// `auth.proto`: the IPC envelope messages.
pub mod auth {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
}

/// `vault.proto`: the reference vault schema.
pub mod vault {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.vault.rs"));
}

pub use auth::{GatewayRequest, GatewayResponse};
