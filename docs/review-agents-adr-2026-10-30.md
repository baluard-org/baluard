# Adversarial review: D80 Agents Never Hold the Vault (2026-10-30)

Verdict: implementable with changes. The product shape is right, but as written the approval gate does not bind a same-user agent, because the user's own session token sits where the agent can read it. Fix C1 and C2 before any code.

Scope note: reviewed against `handler.rs`, `state.rs`, `crates/baluard-cli/src/client.rs`, `main.rs`, `proto/vault.proto`, the desktop poll precedent, and the four competitor URLs (fetched 2026-10-30). Time budget limited the review: I did not read the desktop SettingsModal or the full CLI command tree, and I did not check Windows pipe code beyond the cfg gates.

## Critical

### C1. The user session token is readable by the agent, so the whole gate is bypassable (ADR para 1 and 2, "raw reads stay behind user session tokens")

`client.rs` lines 95-180: the CLI persists the user's per-vault session token in the OS keyring (file fallback, 0600). The agent runs as the same user in the same terminal session. On Linux the Secret Service is unlocked for the whole login session, so any process can read it. Worse, the agent does not even need to read it: `baluard get <item>` run by the agent already finds the token and returns the plaintext secret. No grant, no approval, no audit record.

The ADR's honesty clause ("not against malware") does not cover this. A coding agent is not malware; it is exactly the stated threat, and it has a one-line bypass with the normal CLI. Scoping, TTL, approval, and audit are all skipped on that path. The audit log will also show a clean record while the secret left.

Fix: the ADR must pick one of these and state it.

1. Make the CLI and MCP agent mode distinct from the user mode by credential, not by habit. The CLI used by an agent must not find the user token: user token lives only in the desktop process memory plus an explicit `baluard unlock` session scoped to the TTY (e.g. keyed by the controlling terminal / session id, not by user). An agent spawned inside that terminal still inherits it, so this only helps partially.
2. Stronger and more honest: an interactive CLI session never persists the token to a place a sibling process can read. Pass it via an inherited fd or an env var for that shell only, and tell the user "agent in this terminal can read this" in docs. The agent then needs its own explicit grant path, and the user's terminal token is the exposed surface.
3. Accept it and rewrite the claim: "approval protects against agents that use the grant path; an agent that runs the user's CLI is out of scope". If this is the ruling, say so loudly, because the headline ("Agents Never Hold the Vault") is then false. Rename the ADR.

Recommended: option 2 plus a documented `BALUARD_AGENT=1` convention that makes the CLI refuse the stored user token (cooperative agents only; a hostile one ignores it, which matches the stated boundary).

### C2. Agent identity is unauthenticated and the request route is pre-token, so any local process can mint, spoof, and flood (ADR para 3)

The agent has no credential before the first approval. `agents.request` must be reachable without a token, like `TOKEN_EXEMPT_ACTIONS` (`handler.rs` line 220), which has a test that pins the pre-token surface as a deliberate tripwire. Consequences:

- The name is self-declared. A prompt-injected agent or any script asks as "Claude Code" with item "GitHub token". The modal cannot tell it from the real one.
- Nothing rate-limits requests. A local process can open a modal every second (approval fatigue, DoS of the desktop UI), or race a real approval: the user sees two identical "Claude Code wants GitHub" prompts and approves one the attacker holds.
- The grant token's holder is whoever received the approval response. With a bearer token the first process to poll wins.

Fix:

- Bind the request to peer credentials. The daemon already reads SO_PEERCRED (`handler.rs` 7256, 7287); extend to capture pid, resolve `/proc/<pid>/exe` and the parent chain (macOS: `LOCAL_PEERPID` + `proc_pidpath`), and show the executable path and parent process in the prompt next to the self-declared name. Display "claims to be X; actually `/usr/bin/node`" when they differ.
- Do not return a bearer token. Follow the audit C12 precedent in `reprompt_verify` (`state.rs` 8899): that function deliberately mints no token because "a returned token would be a bearer capability for other same-UID processes". D80 reverses that lesson without saying so. Instead bind the grant to the pid + start time of the requester (and its connection), so `baluard run` must be the same process tree that asked. State the residual: pid reuse and same-tree children.
- Per-requester rate limit and a global cap on pending requests (e.g. 1 pending per exe path, 3 total); excess auto-denied silently. Reuse `rate_limit.rs` patterns.
- Approving one item must not widen later requests: the grant is for that peer + item, not for the name.

### C3. `baluard run` leaks the secret into the agent's transcript by default (ADR para 2, "transcript capture, and context-window leakage")

The agent chooses `<cmd>`. `baluard run -- sh -c 'echo $GITHUB_TOKEN'`, `-- env`, `-- printenv`, `-- curl -v`, a failing CLI that prints its config, or any tool with `--debug` writes the value to stdout/stderr, which `run` forwards to the agent, which puts it in its context window and logs. The ADR states this is "leak hygiene, not containment" but then lists transcript capture and context-window leakage as things the design guards against. It does not: the only guard is the agent's good behaviour, which is the very thing a prompt-injected agent lacks. Also `/proc/<child>/environ` is readable by the same user.

Fix:

- `run` pipes child stdout and stderr through a scrubber that replaces every injected value (and its base64, URL-encoded, and JSON-escaped forms; split across chunk boundaries; use a rolling buffer of max secret length) with `[REDACTED:<item>]`. Say plainly that this stops accidents, not an agent that encodes the value (rot13, hex, chunked). This is what makes "transcript capture" a true claim.
- Add a `--no-output-scrub` refusal: scrubbing is not user-optional for agent grants.
- Reword the ADR claim to match: scrubbed accidents only.

## High

### H1. The desktop approval hop has no design, and the daemon has no push channel (ADR para 3, "the desktop app as a modal")

Confirmed: there are no daemon push events. The nearest precedent is `AutoSyncContext.jsx` line 20, `POLL_MS = 10_000`, polling `sync.conflict`. A 10 second poll is wrong for an approval: the agent blocks, the user stares at a terminal, and the pending request may time out before the modal appears. Needed and not described:

- A cheap poll cadence (1-2 s) only while the app is unlocked and visible, an OS notification (Tauri notification plugin) when the window is unfocused or in the tray, and badge counts. Without a notification the desktop path is dead for tray-resident users.
- Which `VaultState` owns the pending queue? Pending requests are host-level (an agent can ask before choosing which vault is active, and vault A may be locked while B is active). Put the queue on `VaultHost`, not `VaultState`, and decide the behavior when the target vault is locked: deny immediately with a plain-language "unlock Baluard first" (do not wake an unlock prompt from an agent request; that is phishing-shaped).
- The lock-all-on-blur rule (`WindowEvent::Focused(false)` fires `vaults.lock_all`, per project notes): the user clicking the approval OS notification blurs the window and may lock the vault, killing every grant. Define the interaction: approval notification focus must not trigger lock, and lock-on-blur kills grants, which will annoy users (see M3).
- The desktop modal must be a route that needs a user session token (the desktop holds one), and the agent-side poll must be token-exempt or grant-gated. State both. `agents.pending`, `agents.approve`, `agents.deny` need user-token gating and an explicit negative test that an agent token cannot call them (the ADR claims "no agent-grant token can mint grants or alter allowlists" but names no mechanism; the existing default-deny gate verifies against exactly one per-vault token string, so the agent class needs its own verifier and an allowlist of routes, in the style of `CONTACT_VIEW_ALLOWED`).

### H2. Token broker mismatch: "mint beside session tokens" does not match the code (ADR para 2)

`VaultState` holds exactly one `session_token: RwLock<Option<String>>` with creation time and generation (`state.rs` 74-84, 9213+). `verify_session_token` is a single constant-time compare and also does sliding renewal on authenticated activity. Agent grants are N tokens, per item, per expiry, per requester, with no sliding renewal (TTL must be absolute, or an agent loop keeps it alive forever). Needed:

- A separate `AgentGrants` store on `VaultState` (map keyed by grant id, each with peer binding, allowlist, expiry), with its own verify path that never touches `touch_activity()`. Today `route_request` calls `state.touch_activity()` on every request (handler.rs after the gate), so an agent polling would hold off auto-lock indefinitely. Agent calls must not reset the auto-lock timer.
- Generation check on lock, same as the session token (`session_generation`): store the generation in each grant.
- Absolute 4 h style cap does not apply; the 15 min TTL is absolute from approval, no renewal on use. The ADR says "per-item renewal on re-approval", fine, but state "no sliding".
- Decide what `vault.lock` does to pending requests (deny all) and to a soft lock (PIN survives soft-lock: grants must not).

### H3. `baluard run` and the dual-mode CLI (ADR para 2)

`--direct` opens baluard-core in process and needs the user's credentials. Define behavior per mode:

- Daemon mode: the only valid mode for agents. `run` must fail closed with a plain message if no daemon is reachable.
- `--direct`: must be refused for `run`, or it must treat the CLI user as the human (master password prompt, no agent semantics). An agent that adds `--direct` must not skip approval; `--direct` on a TTY would prompt for the master password, and the agent can type it if it has the password. State: `run` has no `--direct`.
- The slug/token-file logic (`token_file_path_for`, per-slug files, `--socket` override) means an agent can point `--socket` at a rogue daemon it started and capture the request or spoof approval UI. The agent token and request go to whichever socket is named. Pin the socket for agent flows to the default path, or at least print the socket in the approval prompt. Low cost, closes a spoof.
- Exit codes and a stable machine-readable denial (`denied`, `timeout`, `locked`) so agents do not retry in a loop and flood prompts.

### H4. Secret kinds beyond passwords riding the same path (ADR para 2, "fetches the allowed item")

The ADR says item, not field. Items include cards, identities, SSH keys, bank accounts, passports, notes, attachments, passkeys' private keys (embedded in Login). Env injection of a whole item is undefined: which variables, what naming, what about multi-line SSH PEMs in env (size limits, newline mangling, `ARG_MAX`/`MAX_ARG_STRLEN` 128 KiB per env string on Linux), attachments (2 MB, will blow `ARG_MAX`; E2BIG on exec).

Fix: restrict the beta to Login username, password, URI, TOTP, and custom fields explicitly flagged "agent-usable" (or all custom fields, decided up front). Refuse card, identity, bank, passport, DL, SSH key, passkey private key, attachments. Name mapping: `BALUARD_<ITEMSLUG>_PASSWORD`, with collisions and non-ASCII slugs handled; or an explicit `--env NAME=item.field` map so the agent's tool reads a variable it expects. TOTP: inject the derived current code at spawn only (consistent with the GOTCHA that `cipher.totp` returns derived codes); a seed must never be injected. Child env inheritance: scrub inherited `BALUARD_*` vars so the child cannot see grant tokens, and set the child's secrets with `Command::env`, never via argv.

### H5. Audit log: "append-only" is an aspiration (ADR para 4)

Same UID can truncate or rewrite any device-local file, including the agent. A prompt-injected agent that cleans up its trail is plausible. Options, pick one and say which:

- Hash-chain each record (prev hash + HMAC under a key derived from the Root Key, so a rewrite without the vault open is detected, and a truncation shows as a chain break against a counter kept in `settings.enc`). Detect-only; state it.
- Store the log encrypted under Root Key like `profile.enc`, so an agent reading it learns nothing and a blind rewrite is detectable.
- Do not claim "append-only"; say "tamper-evident".

Also: the log must never record the secret value, and must record the peer exe path (see C2), the command line of `run` (it can contain secrets in argv; hash it or log only argv[0]), the exit status, and denials. "Readable in Settings" needs a size cap and rotation. Note that audit is the only post-hoc defense for C1, and C1 skips it.

### H6. YOLO flip is gated only by "== Some(true)" at read time; the write path is unspecified (ADR para 3, last sentence)

Where is the setting stored? In `settings.enc`, synced? It propagates to other devices through git sync, so a compromised or careless device flips allow-all for every device. For `guest_enabled` that is an accepted policy door; here the effect is silent secret access. Also: which route writes it and does it need a user token only? An agent holding a user token (see C1) flips it in one call. Fix: settings write for this key requires `reprompt_verify` (or the desktop with a fresh biometric) and is device-local (not synced), and "absent means confirm" must be tested with `None`, `Some(false)`, and a malformed value. Also scope YOLO per item set or per peer exe at minimum; vault-wide allow-all means every item, including bank and SSH key (though H4 limits kinds). A "loud one-time warning" is a modal an agent cannot click but the one-time nature means later flips are silent; show it on every enable.

### H7. MCP server blast radius (ADR para 4)

- The stdio server is spawned by the MCP client, so the daemon sees the MCP server's pid, not the agent's. Identity in the prompt is "baluard-mcp" or whatever the client launched. The parent-chain lookup in C2 must walk past the MCP server to the client; document that the name shown is the MCP client's self-reported `clientInfo`, which is spoofable, as is `elicitation` content.
- Elicitation is a UI the MCP client renders. A malicious or compromised MCP client can auto-accept the elicitation itself, and the daemon cannot tell. This breaks "an agent can never approve its own request" in the MCP path: the approve verdict comes from the client side. The only trustworthy approval is an out-of-band daemon-side one (desktop modal or CLI TTY the daemon verifies). Decision: in MCP mode, elicitation must carry only a pointer ("approve in Baluard"), and the daemon waits for the desktop or CLI approval. Or: elicitation approval is allowed only when the vault policy says so and is labeled lower-trust. Recommend the first. This also removes the "two approval surfaces" complexity.
- Any MCP client in the room that can spawn `baluard mcp` gets a credential-request tool. Tool descriptions are a prompt-injection channel to the model: keep the tool list minimal (`request_access`, `run`), no `list_items` that reveals item names to the model (item names leak sensitive context; "the allowlist" picker should happen user-side: the user picks items in the modal, the agent only describes need in free text, as 1Password does).
- The MCP `run` tool returns child output to the model, so C3 scrubbing applies there too.
- Beta scope: see Q2.

## Medium

### M1. Per-item approval and 15 minutes: approval fatigue and the "second agent" case (ADR para 3)

Per item plus 15 min means a task touching 4 services asks 4 times, then again after a coffee. Users will hit YOLO fast (and H6 makes YOLO the cliff). Consider a per-task "approve these N items for this session" batch in one modal with checkboxes, and TTL choices (this command, 15 min, until I lock). Pending queue UX for a second agent: show a list with exe path, parent, and age, not a stack of modals; the approval for agent B must never be satisfied by clicking agent A's modal (key each prompt by request id, disable the default button for the first 500 ms to defeat click-through). Fifteen minutes is a fine default if the timer shows in the UI and "revoke now" exists (ADR has no revoke route: add `agents.revoke` and a "Stop all agent access" button).

### M2. Deny on timeout and long-blocking requests

The agent blocks on a socket read. Timeout value is unspecified (say 90 s). The CLI waiting interactively needs a printed hint; MCP clients have their own tool-call timeouts (often 30-60 s) which are shorter than a human noticing a tray notification. Return a "pending" result and let the agent poll, rather than hold the connection; otherwise requests time out client-side while still pending in the daemon, and a late approval then grants an orphan. Define: late approval after the requester vanished must be discarded.

### M3. Lock-on-blur and auto-lock vs grants

Project notes: desktop fires `vaults.lock_all` when the window loses focus. An agent works in a terminal while the user is, by definition, not focused on Baluard. If lock-all-on-blur is active, every grant dies as soon as the user clicks into the terminal, so the feature is unusable for desktop users. Either exempt, or document that agent access requires the vault to stay unlocked and say how (a setting?). This is a product contradiction, not a detail. Also the 4 h session token expiry and auto-lock timer interplay (see H2).

### M4. Naming: "agent" in user copy

"Agent" is jargon for non-technical users, and "assistant" may read as Siri-like. Whatever is picked, the prompt must say the program name and path in plain words ("The program `node` (started by Terminal) asks to use your GitHub login"). Do not show the self-declared name alone (C2). Plain-language rule in AGENTS.md applies to the audit view too: no "grant", "allowlist", "TTL".

### M5. One-credential-per-life rule vs the CLI approval path

The ADR says the CLI approval is interactive. A CLI y/n on a TTY is fine, but an agent that owns the TTY (it spawned `baluard run` in a pty it controls) can type `y` itself. CLI approval is therefore not out-of-band when the requester controls the terminal. Require the CLI approval to come from a separate process (`baluard approve` in another shell, with the daemon checking that the approver is not the requester's process tree), or restrict CLI approval to a TTY that the requester's tree does not own (`/dev/tty` check of the approver against the requester's session id). Without this, the CLI path is self-approval and the ADR's "agent can never self-approve" is false for it.

### M6. Windows (ADR para 4, MCP and socket story)

The daemon cfg gates show Named Pipes on Windows but the pipe path has no equivalent of SO_PEERCRED/pid binding in the reviewed code; C2's peer binding needs `GetNamedPipeClientProcessId`. Say that agents.* and the MCP server are Linux and macOS only in 0.1.0 if the pipe work is not done, and that the desktop shows nothing about agents on Windows. Environment size limit on Windows is 32,767 chars total; H4 limits apply harder.

### M7. Proto and wire culture

`proto/vault.proto` is a reference schema; the real wire is JSON in `GatewayRequest.payload`. The `agents.*` routes follow the JSON-in-string culture; do not add proto messages. But `GatewayRequest.session_token` is a single field, and the agent grant token would ride it, so the verifier needs to distinguish token classes by prefix or a separate field (a prefix like `agt_` avoids a schema change and lets the default-deny gate route to the agent verifier). Also the agent route allowlist (see H1) and `TOKEN_EXEMPT_ACTIONS` test must be updated with justification.

## Low

### L1. Competitor claim accuracy (verified against live pages, 2026-10-30)

See the verified list at the end. Overstated or missing in the ADR: 1Password supports only Login items (with one-time codes) from Personal/Private vaults, the ADR does not say it and it matters for H4. 1Password's own pages say nothing of TTL beyond "a limited time", nothing on audit, nothing on env injection or MCP; do not imply 1Password validates this ADR's audit or MCP choices. Bitwarden's README and blog differ: README is "early preview", blog is "early alpha"; the README describes pairing via a token rather than per-request approval, the blog describes per-credential approval in the CLI. The ADR's wording "alpha, Apache-2.0, `aac run` injects as env vars" is accurate. "Whose README refuses raw secrets into models" is a stretch: the README says "We do not recommend inputting sensitive credentials directly into LLMs or AI agents", a recommendation not a refusal. Bitwarden mentions no TTL, no audit in the SDK today (explicitly future), and no MCP. So Baluard's TTL, audit, and MCP are ahead of both and un-benchmarked; that is fine but not "grounding".

### L2. The "dead on daemon restart" property is a feature, say so for the MCP server

Agents that outlive a daemon restart get a denial and may loop; the machine-readable codes in H3 cover it.

### L3. The `agents.*` namespace and the existing `agents`-adjacent words

Check no collision with provider/bridge "bridge-token" terms; mobile bridge approval (`bridge.rs`, approve-don't-type) already has a pairing and approval ceremony. Reuse its pending-approval structure rather than inventing a second one (rung 2 of the simplicity ladder). I did not read `bridge.rs`; verify the fit.

## Questions for Esteban

1. C1 ruling: do you accept option 3 (agents using the user's CLI are out of scope) or want the token-hygiene work (option 2)? The title and the "never" claim depend on it.
2. MCP in the beta: given H7 (elicitation is client-side and spoofable), do you accept MCP as a request-only front that always routes approval out-of-band to desktop/CLI? If not, MCP should slip to post-beta.
3. Should lock-on-blur kill grants (M3), or should agent access be exempt from lock-all-on-blur but still die on explicit lock, auto-lock, and restart?
4. Is YOLO device-local and reprompt-gated (H6), or synced like other settings?
5. Which item kinds and fields are in scope for 0.1.0 (H4)? Recommendation: Login only.
6. Do you want a "revoke now" and a visible running-grants list in the desktop in the beta (M1)? Recommendation: yes, it is small and makes TTL trustworthy.

## Suggested slice order (the ADR is sound after C1-C3)

1. Daemon: `AgentGrants` store, peer-bound request, pending queue on `VaultHost`, user-only approve/deny/revoke routes, route allowlist for the agent class, no activity touch. Tests: agent token cannot call user routes; approval from a requester-tree process is refused; lock kills grants and pending requests.
2. CLI `run`: Login fields only, scrubber, daemon-only, machine-readable exit codes, `BALUARD_AGENT` refusal of the stored user token.
3. Desktop: pending poll (1-2 s) plus OS notification, approval modal with exe path, running list, revoke, YOLO setting behind reprompt.
4. Audit: tamper-evident log and Settings view.
5. MCP stdio wrapper, request-and-run only, out-of-band approval (post-beta if Q2 is no).

## Claims verified as SOUND (do not re-litigate)

- The unlocked vault is readable by any same-user process through the daemon socket (SO_PEERCRED only checks UID; `vaults.list` and others are pre-token; token lives in keyring or a 0600 file).
- Tokens are per vault, constant-time compared, expire (4 h) and die on lock via generation check (`verify_session_token`).
- Tokens are not a design obstacle for a second class: the default-deny gate (`action_requires_session_token`) and the `CONTACT_VIEW_ALLOWED` precedent show a route allowlist per session class is an established pattern.
- `reprompt_verify` verifies the master password and mints no token, so "no password field in the prompt" stays consistent with it; the approval does not need to reuse it.
- Approve/deny without a password prompt matches the one-credential-per-life rule.
- Pre-1.0: adding `agents.*` routes and changing JSON payloads needs no migration.
- 1Password for Agents: announced 2026-10-22; fill happens inside a hosted browser so the agent never receives the credential; an agent cannot approve its own requests; approved items are reusable for a limited time; the app must be unlocked to approve.
- Bitwarden Agent Access: open protocol, CLI and SDK, Apache 2.0, early alpha/preview, `aac run` injects environment variables into a child process and states secrets never touch stdout or disk.
- Env injection as leak hygiene rather than containment is the correct honest framing (but see C3: the transcript claim needs the scrubber to hold).
- Device-local audit, no cross-device grants, no key material in a grant, and read-only grants are all consistent with the existing architecture.

## Dispositions (2026-10-30, Esteban rulings applied to D80)

C1 ACCEPTED AND DOCUMENTED: the stored-token CLI bypass is ruled out of scope (same trust class as malware); the BALUARD_AGENT=1 convention lets cooperative agents refuse the stored token; the audit trail is the post-hoc evidence on that path. D80 paragraph 1 carries the loud boundary statement.

C2 ACCEPTED: peer-bound requests (pid plus executable path shown in the prompt), grants bound to the requesting process instead of a bearer token, per-executable and total pending caps, rate limits, and immediate plain-language denial against a locked vault.

C3 ACCEPTED: non-optional stdout/stderr scrubber (value plus base64, URL, and JSON forms, chunk-boundary safe); the transcript claim is reworded to accidents only.

H1, H2 ACCEPTED: pending queue on VaultHost, desktop polls at 1-2 seconds plus OS notification, dedicated AgentGrants store with its own verifier and route allowlist, user-token-gated approve/deny/revoke, absolute TTL with no sliding renewal, and agent calls never touch the auto-lock timer.

H3 ACCEPTED: run is daemon-only, --direct refused, agent socket pinned to the default path, machine-readable denials.

H4 ACCEPTED WITH RULING: beta scope is Login username, password, URI, custom fields, and the derived TOTP code at spawn (never the seed); attachments, SSH keys, passkeys, and non-Login kinds are refused.

H5 ACCEPTED: tamper-evident hash-chained log that never records secret values, with rotation and a Settings view.

H6 ACCEPTED: YOLO is device-local (never synced), reprompt-gated on write, warns on every enable, and absent, None, Some(false), and malformed all mean confirm.

H7 RULING: the MCP server slips to post-beta, superseding the earlier in-beta inclusion. When it lands, elicitation carries a pointer only and the verdict stays out-of-band in the desktop or CLI.

M1 revoke plus running-grants list ship in the beta; the batch-approval modal is noted as the fatigue option. M2 machine-readable denials adopted, pending/timeout semantics to the implementation slice. M3 grants are exempt from lock-on-blur per ruling but die on explicit lock, auto-lock, and restart. M5 CLI approval requires an approver process outside the requester's tree. M6 agents surface is Linux and macOS only in 0.1.0. M7 and L1 competitor wording corrected in D80; token-class prefix and proto culture decisions belong to the implementation slice. L3 bridge.rs pending-approval reuse is noted for the implementation slice.

Slice order after dispositions: daemon grants and routes, then CLI run, then desktop approvals, then audit; MCP follows post-beta.
