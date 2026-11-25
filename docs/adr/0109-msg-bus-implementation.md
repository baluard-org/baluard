# ADR 0109. baluard-msgs Implementation Constants and Activation Record

> Status: Accepted (2026-11-14).
Amends: [ADR 0107](0107-side-channel-message-bus.md)

## Context

ADR 0107 specifies the side-channel message bus and defers two things to an implementing record: the constant values, and the trigger decision. The standard names the constants (TTL, skew, per-topic cap, `cap_total`, `hard_cap`, `max_chain`, size and depth limits) but fixes none of them, and it gates the build on a qualifying consumer passing four tests. On 2026-11-14 Esteban ordered the bus implemented before any consumer exists, overriding the trigger deliberately.

## Decision

**Constants, pinned here and in `crates/baluard-core/src/sync/msgbus.rs`.**

| Constant | Value | Role |
|---|---|---|
| `MSG_TTL_SECS` | 2592000 (30 days) | Entries older than this are dropped by reader and pruner. |
| `CLOCK_SKEW_SECS` | 86400 (24 hours) | Entries dated further in the future than this are dropped. |
| `PER_TOPIC_CAP` | 50 | Write-time prune keeps at most this many entries per topic. |
| `CAP_TOTAL` | 200 | Write-time prune target and the compaction low watermark: after compaction the board holds at most this many entries, so adding the one `cleanup.board-compacted` message cannot retrigger compaction at rest. |
| `HARD_CAP` | 256 | Reader ceiling: a board with more conforming entries than this is ignored whole. Also the compaction trigger: a fetched board above this count compacts. Greater than `cap_total` plus one, per the standard. |
| `MAX_CHAIN` | 128 | Compaction also triggers when the fetched board's first-parent chain from tip to its root exceeds this many commits. |
| `MAX_MSG_BYTES` | 16384 (16 KiB) | Parse-time size limit per entry; larger blobs are skipped unread. |
| `MAX_BODY_DEPTH` | 8 | JSON nesting limit for a message body; deeper bodies are skipped. |

**Activation record.** The four trigger tests of ADR 0107 have no passing consumer today; the build proceeds on the explicit owner order above, and the bus ships dormant. Concretely: the publish, reader, and compaction surfaces exist and are fully tested, the push-order slot is wired (messages publish last, best-effort, after gossip), and an empty pending set short-circuits before any network fetch, so the dormant board costs one function call per push and nothing else. The first feature that wants to publish a message must still pass the four trigger tests and record them as an amendment, and until then the only active writer is the board's own `cleanup.board-compacted` message, which can only exist after a flood or a long chain, and a flood cannot be cleaned by a device that never fetches. That residual is accepted: no vault ships a hostile board unless a writer deliberately creates one, and the first consumer-bearing build cleans it on its first publish.

## Consequences

- The engine's push order is now line, main, gossip, messages, with the messages leg a no-op until a consumer exists.
- Manual compaction (2026-11-14): `SyncEngine::compact_message_board` prunes expired and over-cap entries, resets the first-parent chain, and records one `cleanup.board-compacted` message, so other devices both detect the rewrite and learn the numbers. A board that does not exist is a zero-report no-op — the transport never writes a genesis carrying only the cleanup message. The compaction commit is signed, parented on the vault root, and force-pushed; the constants above guarantee the result sits under `HARD_CAP` so compaction cannot retrigger at rest.
- Second-device detection (2026-11-14): `SyncEngine::msg_board_status` classifies the fetched tip against a per-device acknowledgment (machine-local `msg-board/<vault_id>.json`) into rewritten / foreign plus roster-signature attribution, and reads the cleanup message from the vault-root-parented compaction commit's own tree, never the tip, because later publishes chain on it unsigned. `compacted_entries` counts messages REMOVED, not survivors. Detection needs no unlock; the daemon routes `vault.msg_status`, `vault.msg_ack`, and `vault.msg_compact` work on a locked vault.
- Reader-side classification rules from ADR 0107 (classification wins, words not data, mandatory non-message fallback) bind consumers, not the transport; none exist yet to bind.
- The constants live in one place in code and one table here; changing either means changing both in the same commit.
