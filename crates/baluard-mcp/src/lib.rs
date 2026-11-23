//! Transport-free MCP agent-access primitives (ADR 0116).
//!
//! Everything the MCP transports need to make a policy decision lives here:
//! the tool registry, request-to-capability mapping, the field-allowlist
//! projections, cap math, and the pairing/read-grant/yolo state. The crate
//! depends on core types only; rmcp, tokio, and every transport detail stay
//! in the daemon and CLI front-ends.
//!
//! Boundary facts that shape this module:
//! - Pairing tokens are stored hashed (SHA-256, constant-time compared) and
//!   carry the `blrd_mcp_` prefix so secret scanners catch leaked copies.
//! - Yolo windows and read grants are strictly volatile: an in-memory
//!   monotonic-clock expiry, never persisted, cleared on vault lock and
//!   daemon restart. Nothing on disk can resurrect them.
//! - Search projections return metadata only; get projections return the
//!   0083 injection set with seed-like values stripped. Secrets never ride
//!   a search row.

pub mod policy;
pub mod registry;
pub mod tools;

pub use policy::{
    CapMeter, CapOutcome, LadderChoice, READ_LADDER_MINUTES, SEARCH_RESULT_CAP, SearchRow,
    filter_rows, is_seed_like, project_login, project_search_row, validate_search_query,
};
pub use registry::{
    MCP_SESSION_PREFIX, MCP_TOKEN_PREFIX, McpRegistry, Pairing, PairingView, READ_APPROVAL_WAIT,
    ReadGrantKey, RegistryError, SESSION_APPROVAL_WAIT, SessionPeer, SessionVerdict,
};
pub use tools::{
    McpAction, TOOL_GET_LOGIN, TOOL_GET_TOTP, TOOL_SEARCH, ToolDesc, mcp_action_for_tool,
    tool_definitions,
};
