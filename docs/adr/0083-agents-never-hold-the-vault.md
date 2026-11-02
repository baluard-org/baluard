# ADR 0083. Agents Never Hold the Vault

> Status: Accepted (2026-10-30)

## Context

Once a vault is unlocked, any local process can access it through the daemon socket. Cooperative local agents need credentials, but their access must be distinguishable from the user's session. This decision governs agents that use the agent flow. A same-user agent can bypass it by using the CLI's stored session token from the OS keyring, or its 0600 file fallback. That path is outside scope and shares the OS trust boundary with malware. `BALUARD_AGENT=1` lets cooperative agents refuse stored tokens; audit records are the only post-hoc evidence on the bypass path.

## Decision

Provide separate, human-approved, read-only agent sessions, with confirmation by default and a per-vault opt-out. Pending requests live on `VaultHost`, including requests made before a vault is active or while its target is locked. Approved grants live in `AgentGrants` on `VaultState` beside the session token. Grants have a constant-time verifier, a dedicated route allowlist following `CONTACT_VIEW_ALLOWED`, and an absolute 15-minute TTL from approval; reapproval renews it. Bind each grant to peer PID, executable path, and process start time using SO_PEERCRED, never a bearer token. Scope grants to one vault; do not permit them to hold key material, vault files, folder structure, or activity that feeds `touch_activity`. Grants end on explicit lock, auto-lock, or daemon restart. They survive lock-on-blur and never cross devices.

Expose `baluard run -- <cmd>` in daemon mode only. Fail closed with a plain message if no daemon is reachable. Pin agent flows to the default socket path. Pass secrets through `Command::env`, never arguments; scrub inherited `BALUARD_*` variables. Return machine-readable `denied`, `timeout`, and `locked` outcomes. In the 0.1.0 scope, inject Login username, password, custom fields, and the current derived TOTP code at spawn, never the TOTP seed. Refuse Login URIs, cards, identities, SSH keys, passkeys, notes, and attachments.

Require per-item approval naming both the self-declared requested name and daemon-resolved executable path. Rate-limit and cap requests per executable and overall; silently deny excess. Deny requests for locked vaults without waking an unlock prompt. Approval is approve or deny only, with no password field. Desktop polls every two seconds while unlocked, notifies when unfocused or in tray, and shows a modal. A CLI approver must be outside the requester's process tree. Provide user-token-gated `agents.revoke`, running-grant management, and batch approval. Scrub child stdout and stderr for injected values and their base64, URL-encoded, and JSON-escaped forms, including chunk boundaries, replacing matches with `[REDACTED]`.

Append device-local, tamper-evident hash-chain audit records for every grant and use. Record metadata only: executable path, run command `argv[0]`, verdict, exit status, and denial reasons. Cap and rotate records; show them in Settings. Audit sync is deferred past 1.0. Store the per-vault allow-all option on the device only, gate writes with reprompt, warn on every enable, and treat absent, `None`, `Some(false)`, or malformed values as confirmation-required. For 0.1.0, support Linux and macOS only; Windows has no daemon IPC. Defer MCP stdio until after beta. MCP elicitation may carry only a pointer to approve in Baluard; daemon-side desktop or CLI approval remains the trust root.

## Consequences

This controls cooperative agents using the agent flow, not same-user processes that use the stored CLI token. The output scrubber prevents accidental disclosure but not deliberate encoding or reads from `/proc/<pid>/environ`. Agent calls do not extend auto-lock. Grants and audit records are device-local. Implemented daemon, CLI, desktop, and audit slices use a 15-minute absolute TTL, poll pending requests every two seconds, retain 1 MiB current and 1 MiB rotated audit history, serialize appends, verify retained-chain anchors after pruning, and fail closed before approval or command execution if required audit writes fail. MCP remains post-beta.

## References

- `baluard run -- <cmd>`
- `AgentGrants`
- `CONTACT_VIEW_ALLOWED`
- `reprompt_verify`
