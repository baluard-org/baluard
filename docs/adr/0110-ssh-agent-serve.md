# ADR 0110: The Daemon Serves Vault SSH Keys Over an OpenSSH Agent Socket

Date: 2026-11-15
Status: accepted

## Context

Vaults store SSH key pairs (`SshKeyData`: private OpenSSH text, public key, fingerprint) as cipher entries, but nothing uses them: the user must keep the same keys in an external agent, re-importing by hand on every machine. The daemon already runs per-user with the vault unlocked in memory and owns the natural home for an `SSH_AUTH_SOCK` implementation. Bitwarden ships the same shape: an agent that serves vault keys behind a master switch, a per-item opt-in, and a sign-approval policy.

## Decision

**Three switch layers, all default off, two of them device-local.** The master switch and the sign policy live in a device-local policy file (`agent-policy.json` under the daemon data directory), not in the synced vault settings: enabling the agent or auto-approve on one machine must never silently enable signing on every other machine sharing the vault. Both read as off when the file is missing or unreadable, and turning either on requires the master password, writes the audit event first, and fails closed if the audit fails. They are exposed through the `agent.policy.get` / `agent.policy.set` routes (get is token-exempt since it carries no vault data) and the desktop Settings toggles. `SshKeyData.serve_via_agent` is the per-key opt-in and stays in the synced cipher data; only opted-in keys are ever listed or used. It is a serde-default bool, so every pre-agent vault deserializes with serving off.

**The socket binds whenever the daemon runs, and its existence leaks nothing.** Settings are encrypted and unknowable pre-unlock, so binding cannot depend on them. The agent socket is `agent.sock` beside the IPC socket in the same private runtime directory, bound then chmodded to 0600 (a process-global umask wrapper would race unrelated file creation), with the same stale-socket connect probe as the IPC listener (a connectable path means another daemon owns it and startup refuses loudly). A locked vault protocol-fails identities requests (bare failure opcode) rather than answering an empty list, keeping "cannot serve" distinguishable from "no keys"; the master switch off answers the empty-list form. Sign requests against locked or disabled vaults protocol-fail.

**Approval reuses the D80 agent pipeline.** A manual sign pushes a PendingQueue entry with the synthetic `claimed_name` "SSH agent client", surfaces through the existing `agents.pending` / `agents.approve` / `agents.deny` routes and desktop UI, and inherits the queue's caps (4 pending per executable, 6 total, 120-second approval window). The client polls and protocol-fails on deny, timeout, or queue-full. Peer identity comes from the same per-platform resolvers as agent grants (Linux SO_PEERCRED plus `/proc`, macOS LOCAL_PEERPID), degrading to an unresolved binding without ever blocking the serve.

**Every gate is evaluated per request.** The listener never caches an earlier scan: identities and sign requests re-walk the open vaults, re-check unlocked state, the master switch, and the per-key flag, and re-derive the public blob from the stored private text for identity matching (signature flags are parsed and ignored; only ed25519 and P-256 are served, matching the daemon's generators). Key material is loaded for signing at sign time, never held across an approval wait, and decrypted plaintext rides `Zeroizing`. Only SSH-key ciphers are decrypted during a scan; logins, cards, and notes are never touched. A key present in more than one vault resolves deterministically (vaults sorted by slug) to the strictest policy, so auto-approve becomes false if any vault holding the key wants an approval, and the master switch is re-read after an approval wait elapses so a switch turned off mid-wait refuses the sign. The listener rejects peers whose uid differs from the daemon's, caps concurrent connections, idles out silent connections, and caps the approval label length. Encrypted private keys are refused outright (`KeyError::Encrypted`): there is no passphrase prompt flow.

**`serve_via_agent` is sticky across edits.** Clients that predate the agent (mobile, older desktops) re-serialize `kind.data` without the key, and the wholesale kind replacement in `update_cipher` would flip it off via serde's bool default. The merge carries the stored value forward when the payload omits the key; an explicit false still wins.

**Unix only.** Windows named pipes are an explicit follow-up; the listener does not compile into the Windows service path.

## Consequences

- The daemon answers `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/baluard/agent.sock` for `ssh-add -l`, git over ssh, and every other OpenSSH client, so vault keys sign without leaving the vault.
- A sign request names the entry, not the key bytes: the desktop prompt and the audit trail (`requested`, `approved`, `denied`) carry the entry name and id, and no private material ever appears in an error, a log line, or an approval payload.
- ssh-add cannot distinguish "agent answered empty" from "agent answered failure" (both print "no identities"); clients that care must speak the protocol. The wire-level distinction is pinned by daemon unit tests.
- Grant rules stay untouched: the serve path borrows the PendingQueue for human decisions but requests carry the `SshSign` purpose, so an approved sign releases the sign alone and mints no `agt_` grant; grant TTL, generation-lock, and touch-activity rules are unaffected. The wire failure answer is opcode 5 (`SSH_AGENT_FAILURE`), distinct from the zero-count identities answer.
- Machine wiring is additive on hosts with an existing ssh-agent bridge: point `SSH_AUTH_SOCK` per session, or add an `IdentityAgent` line to a `Host` stanza; the bridges coexist because each is a separate socket.
