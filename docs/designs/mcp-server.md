# MCP agent server

> Status: Implemented (2026-11-22). Folded from two agy review passes (session 0dace454). Extends ADR 0083 (agents never hold the vault); ADR 0116 records the decision and ships as `crates/baluard-mcp`.

## Summary

Baluard ships an MCP (Model Context Protocol) server so people using coding agents (Claude Code, Cursor, and similar) can connect those agents to their vault without hand-editing JSON config files. The desktop app hosts a loopback HTTP endpoint with a pairing flow in Settings; the CLI offers the classic stdio transport. Both front-ends share one set of MCP primitives and land on the same permission stack ADR 0083 built for `baluard run`: human approval, scoped grants, caps, and the hash-chain audit.

## Goals

- Less-technical users connect a coding agent in under a minute from the desktop app.
- The agent gets read access to logins and TOTP codes only, under human-gated secret reads (per-read approval by default, with optional user-chosen time-boxed grants).
- Every secret read is capped and audited; nothing about the design trusts the agent.
- One implementation of tool schemas and policy serves CLI and desktop.

## Non-goals

- No writes (create, update, delete) from agents in v1.
- No SSH keys, passkeys, secure notes, cards, identities, or attachments over MCP; SSH keys already flow through the SSH agent to git.
- No 0083 per-vault allow-all opt-out for MCP in v1; yolo (below) is the sanctioned shortcut.
- No remote MCP hosting; the server binds loopback only.
- No folder structure, vault files, key material, seeds, or master/recovery secrets through any tool.
- No auto-editing of third-party agent config files in v1; the desktop ships copy-ready snippets only.

## Relationship to ADR 0083

0083's invariants stand unless named below: agents never hold the vault, human approve-or-deny per named agent, grants die on lock, auto-lock, and daemon restart, machine-readable `denied` / `timeout` / `locked` outcomes, per-executable rate limits, hash-chain audit of metadata only, fail-closed refusal when an audit write fails, and the same-user-malware boundary (cooperative agents only; the stored CLI token path stays outside scope).

ADR 0116 amends exactly these 0083 statements, each named for the fold:

- Grant granularity: the fixed 15-minute TTL becomes an approval-time duration chosen by the user per secret read (just this read, 5, 15, 30, or 60 minutes, absolute TTL, never sliding). `baluard run` keeps the fixed 15-minute TTL unchanged; only MCP grants change.
- Bearer tokens: 0083 binds grants to peer PID, executable path, and start time and forbids bearer tokens. The desktop HTTP transport cannot see the agent's process, so it uses a pairing token instead (loopback-only, hashed at rest, one-tap revocation). The stdio transport keeps the full executable binding. 0116 scopes the bearer-token exception to the desktop transport only.
- Search metadata: 0083 refuses Login URIs for `baluard run` injection. `search_items` returns usernames and URIs as metadata (never secrets), a deliberate extension recorded in 0116.
- Platform scope: 0083's "Linux and macOS only; Windows has no daemon IPC" is stale; Windows named-pipe daemon IPC ships today (`baluard-core/src/ipc.rs`). 0114-era reality supersedes that line, and this design relies on it.
- The MCP deferral ("after beta") is retired by 0116.

0083's elicitation rule stands: MCP elicitation may only point at Baluard's approval UI; daemon-side approval remains the trust root.

## Architecture

`baluard-mcp` is a new crate holding the transport-free primitives: the tool registry (names, JSON schemas, descriptions), request-to-capability mapping, policy decision functions, cap math, and response shaping as a strict field-allowlist projection (stripping anything outside the per-tool allowlist, never called "redaction" since get responses intentionally carry secrets). It depends on core types only; rmcp, tokio, and all transport code stay out of it and live in the front-ends.

Transport 1, CLI: `baluard mcp serve` speaks stdio. The MCP client spawns the server process, so the server's parent process is the coding agent itself. The daemon resolves identity, never the client: the stdio process connects to the daemon like any agent-flow client, the daemon first verifies the connecting peer executable is `baluard` via SO_PEERCRED, then inspects that peer's parent chain itself in-daemon, never trusting a client-declared PPID. Grants bind to the parent's executable path, PID, and process start time. A parent PID of 1 (double-fork or parent exit) is rejected, not bound to init. macOS parent inspection uses libproc (`proc_pidpath` / `proc_pidinfo`), not /proc. Shell-wrapped snippets document `exec` so wrappers do not mask the agent's identity. The stdio session pins one vault at handshake (`--vault`, else the active vault), so desktop vault switching never widens its reach. Windows stdio is deferred to a post-v1 amendment; Windows users use the desktop transport.

`baluard mcp serve` inherits every 0083 hardening rule that applies to a spawned agent client: pinned to the default daemon socket path, inherited `BALUARD_*` variables scrubbed at startup, stored CLI session tokens refused (the `BALUARD_AGENT=1` posture is inherent, not optional), and fail-closed with a plain message when no daemon is reachable.

Transport 2, desktop: the daemon hosts Streamable HTTP on a fixed default loopback port with a pairing token minted at connect time. Fixed port keeps pasted snippets stable across restarts. On a loopback bind failure the daemon fails closed and surfaces the error in Settings rather than silently serving on a mismatched port. On multi-user hosts a fixed port can be squatted while Baluard is down to capture a future bearer token; single-user hosts are assumed, and post-theft replay against Baluard stays bounded by caps, audit, revocation, and yolo-off-by-default. The handler validates the `Host` header (`127.0.0.1:<port>` or `localhost:<port>`), rejects requests carrying a browser `Origin` header (DNS-rebinding defense per the Streamable HTTP spec), answers `404` for stale `Mcp-Session-Id`s after lock or restart so clients re-initialize cleanly, and bounds concurrent session tables and SSE buffers. Pairing tokens carry a `blrd_mcp_` prefix so secret scanners catch leaked copies, are stored hashed with constant-time verification, and revocation kills the grant immediately.

Pairing binds to one vault at pair time (0083's single-vault rule); switching the active vault never widens an agent's reach — calls against an unpaired vault answer `denied`, calls against a locked paired vault answer `locked`.

## Tool surface (v1, read-only)

| Tool | Returns | Approval |
|---|---|---|
| `search_items(query)` | ids, names, usernames, URIs (no secrets) | session grant + metadata cap |
| `get_login(item_id)` | username, password, custom fields (the 0083 injection set, seed-like custom values stripped) | per-read approval |
| `get_totp(item_id)` | current TOTP code, never the seed; a clean error when the item has no TOTP | per-read approval |

Search requires a non-empty query and caps results at 20, so no single call dumps the account inventory. The two-step shape is deliberate: search never carries a password, and only explicit get calls do. Everything else is refused with a plain `denied` result.

## Approval lifecycle

Connecting an agent is a human action: pair and name it (desktop), or approve the named parent executable (CLI stdio). Approval is approve-or-deny only, per vault, and never carries a password field.

Once connected, `search_items` runs under the session grant plus the metadata cap. The session grant is lock-bounded (it dies on lock, auto-lock, and daemon restart) and never authorizes a secret read. `get_login` and `get_totp` trigger a per-read desktop approval; each timed approval is scoped strictly to (agent, vault, item, tool) — approving one item never widens to another item or tool, and cannot silently duplicate yolo. The modal offers: just this read, 5, 15, 30, or 60 minutes. Durations are absolute TTLs from approval; re-approval starts a new one.

The tool call blocks while the request is pending. The server-side approval timeout is 30 seconds, below typical client timeouts (60 s), with `notifications/progress` keepalives when the client offers a progress token; a client `notifications/cancelled` or dropped connection dismisses the pending modal immediately and aborts grant creation, so a late human click can never activate an orphaned grant. Outcomes stay machine-readable (`denied`, `timeout`, `locked`). A locked vault answers `locked` and the agent must ask the user to unlock; agent calls never wake the vault and never extend auto-lock. With no desktop approver attached (headless), stdio approval falls back to 0083's out-of-process-tree CLI approver; otherwise requests fail closed with a plain message.

Rate limits from 0083 carry over: pending-request caps per agent and overall, silently denying excess, so a misbehaving agent cannot spam the desktop with prompts.

## Yolo (per-agent auto-approve)

Yolo is a per-agent override that auto-approves the risky tools (`get_login`, `get_totp`) without prompting. It is scoped to one named agent pairing, never global, so revoking one agent never depends on a shared switch.

Yolo state is strictly volatile: an in-memory entry on the vault state with a monotonic-clock expiry, never persisted to disk. It is enabled only from the Settings agent row, behind a user reprompt, with a duration from the same ladder (5, 15, 30, or 60 minutes; 5 is the default). The per-read approval modal never offers yolo, so modal fatigue cannot enable it by accident. There is no open-ended yolo: it expires on schedule and is cleared unconditionally on lock, auto-lock, and daemon restart. The stored state is an in-memory `Option<YoloWindow>` on the vault state keyed by agent pairing with a monotonic-clock expiry; none, expired, wrong pairing, or locked all fail closed to prompting, and no persisted toggle or config key exists, so wall-clock changes cannot resurrect it.

Yolo removes the human gate, not the backstops: per-session and per-day secret-read caps and burst limits still apply, and a tripped cap returns the same deterministic throttled `denied` result in yolo mode as otherwise — it never silently falls back to prompting. The audit records yolo enable, expiry, kill-switch, and every auto-approved call, so the trail distinguishes human-approved reads from yolo reads. UX is loud by construction: a red warning on enable ("this agent can read secrets without asking"), a persistent banner and tray indicator while active, and a one-tap kill switch on both the banner and the agent row. Internally this is `yolo_mode`; the user-facing label is "Auto-approve".

## Caps

Secret reads: 100 per 24 h per agent plus a 10-per-minute burst limiter. Search: 500 per 24 h per agent against a separate metadata cap. Pending-approval caps per agent and overall come from 0083 unchanged. Cap trips throttle and return deterministic `denied` results; they never auto-revoke the pairing (revocation stays a human action), matching the bridge precedent. The numbers are recorded in ADR 0116 so tuning is an ADR amendment, not a code drift.

## Audit

Every tool call extends the existing device-local hash-chain audit: agent identity, tool, item id, verdict (`approved`, `auto-approved`, `denied`, `timeout`), and denial reason. Metadata only; the search query text is never recorded. Yolo lifecycle events (enable, expiry, kill switch) and cap trips are audited too. An audit-append failure fails closed: no secret is returned and yolo cannot enable. Visible in the existing Settings audit view.

## SDK and dependencies

The protocol implementation is `rmcp`, the official Rust MCP SDK (modelcontextprotocol/rust-sdk), MIT/Apache-2.0, which ships stdio and Streamable HTTP. Exact-pinned per house policy in the daemon and CLI front-ends only, justified in ADR 0116 alongside a cargo-audit pass. Hand-rolling JSON-RPC was rejected: HTTP session semantics and capability negotiation are exactly the edge cases an official SDK exists to own. Pin: `=0.16.0` — the patched lines need MSRV 1.88. The pinned line's DNS-rebinding advisory (RUSTSEC-2026-0189) is covered by this design's own Host/Origin guard, and the client-side advisory (RUSTSEC-2026-0462) does not apply because no client transport is compiled; both are recorded accepted risks pending the workspace MSRV bump (ADR 0116).

## Security notes

- Prompt injection: tool results are data, not instructions. The surface returns structured JSON through strict field allowlists; search cannot smuggle secrets; get responses carry only the 0083 field set with seed-like custom values stripped. What an agent does with a secret after receiving it is outside Baluard's control and equals the `baluard run` exposure today.
- Local attackers: the HTTP endpoint binds loopback only, requires the pairing token, validates `Host`, and rejects browser origins. Any same-user process can already reach the daemon socket; 0083's boundary statement is unchanged. A pairing token pasted into an agent config file inherits that file's permissions — user-global config only in v1, never project-scoped `.mcp.json`, and Baluard-side storage is hashed so a config leak is not a credential-store leak.
- Token theft: revocation is one tap and kills the grant immediately; yolo-off-by-default bounds what a stolen token reaches without a human.
- Yolo misuse: volatile-only state, hard expiry, caps, audit marking, and the one-tap kill switch bound a careless enable.
- Headless: with no approver attached the flow fails closed — desktop HTTP requires the desktop UI, while CLI stdio falls back to 0083's out-of-process-tree CLI approver before failing closed. It never falls open.

## Work breakdown

1. ADR 0116 (fold the amendment list above verbatim) plus this design doc, peer reviewed.
2. `baluard-mcp` crate: registry, schemas, policy functions, field-allowlist projection, tests.
3. Daemon: HTTP transport (Host/Origin validation, session bounds), pairing routes, per-read approval plumbing with cancellation handling, yolo windows, caps, audit.
4. CLI: `baluard mcp serve` with daemon-side parent binding and the 0083 hardening set.
5. Desktop: AI agents settings section (pair, snippet, durations, auto-approve behind reprompt, kill switch, audit), i18n in all four locales.
6. baluard-docs page: connecting coding agents, plain-language tone, real surfaces only.
7. Gates: container sweeps, desktop vitest, hermetic MCP client fixtures, release cycle.

Hermetic tests must cover, at minimum: approval cancelled mid-modal, `Origin`/`Host` rebinding rejection, stale `Mcp-Session-Id` after lock and restart, `ppid <= 1` rejection, yolo expiry and restart clearing, cap-trip behavior in and out of yolo, and audit fail-closed on a broken audit sink. Testing is fixture-only end to end; never the host's live vault.
