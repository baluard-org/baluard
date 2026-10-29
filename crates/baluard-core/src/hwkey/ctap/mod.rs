//! Transport-agnostic CTAP2 client (plan slices 4A-4D).
//!
//! Pure Rust so phones can use it where hidapi cannot exist. The desktop real
//! adapter stays ctap-hid-fido2; this module is the mobile backend and the
//! hermetic test harness (software authenticator + scripted transports).

pub mod apdu;
pub mod authenticator;
pub mod cbor;
pub mod ctaphid;
pub mod pinproto;
pub mod protocol;
pub mod token;
