# ADR 0107: Side-Channel Message Bus, Standard and Trigger

Date: 2026-11-14
Status: accepted (standard specified; implementation deferred behind the trigger below)
Review: three adversarial design review rounds folded in (2026-11-14); findings zero-trust verified against the tree

## Context

Baluard already runs two side channels on `refs/notes`, both invisible in forge branch and tag UIs: `refs/notes/baluard-gossip` (deny-only rollback detection, roster-signed head announcements) and `refs/notes/baluard-attachments` (content transport, content-addressed blob line, pins validated from `main` metadata). A third need surfaced while building the compaction notice: telling other devices, before any pull, that shared storage was cleaned up. The first proposal was a generic per-vault message board on `refs/notes/baluard-msgs`, published immediately. The reviews found a spoofable-override flaw in the first consumer, an envelope design that mixed-version fleets could neither prune nor safely merge, and a trigger too vague to test. This ADR records the standard that came out of those reviews, and the trigger that decides when it gets built.

## Decision

**The standard is specified now; the bus is built later.** A future advisory channel `refs/notes/baluard-msgs` follows the contract below. It is implemented only when the trigger fires. Until then, event facts ride the channel they describe. The compaction notice enrichment travels as a `compaction.json` entry inside the attachments compaction genesis. It has a `v` field plus numeric fields only, mirroring the compaction report fields (`v`, `reclaimed`, `reclaimed_bytes`, `kept`). It sits inside a commit that the compacting device signs, so it needs no second ref. Old clients never parse it. A later compaction replaces the genesis, so a device that was offline across two compactions sees only the last one. The UI reads `compaction.json` only after the classifier verifies the genesis signature against roster keys (see Standing improvement). Before that, the UI shows the generic notice. The `compaction.json` parse path has the same size and depth limits as the bus.

**Envelope, versioned from day one.** Canonical JSON: UTF-8, sorted keys, no insignificant whitespace, integers only, no floats. Fields:

| Field | Rule |
|---|---|
| `v` | Integer, 1. |
| `type` | Namespaced, dot-separated. The first segment is the topic. |
| `from` | Device uuid. Never rendered as identity. Unauthenticated on unsigned messages. |
| `at` | Epoch seconds. Informational only. Must equal the `at` in the file name. |
| `id` | Hex SHA-256 over the canonical envelope with `id` and `sig` excluded. |
| `body` | Numeric and enum fields only. |
| `enc` | Reserved for a future HPKE-boxed body. A v1 reader skips any message that has `enc`. |
| `sig` | Lowercase hex ed25519 signature by the device's commit-signing key over the context string `baluard-msgs-v1`, a zero byte, and the 32 raw SHA-256 digest bytes of `id`. Publishers sign when a key exists and skip publish when it does not, as the attachments line does. |

**Layout.** `msgs/<topic>/<at>-<id>.json`. The topic charset is `[a-z0-9-]`, which blocks path injection. `<at>` is decimal epoch seconds. This prefix is frozen for all versions, so any version can prune and cap by path alone. A reader skips a message when the topic differs from the first segment of `type`, when the path `at` differs from the body `at`, or when the recomputed `id` differs from the path `id`.

**Time window.** Reader and pruner drop a message whose `at` is older than now minus TTL or newer than now plus skew. They do not clamp. A clamp to a moving `now` renews a future-dated message at every read, so it never expires.

**Unknown fields.** A v1 reader ignores unknown top-level fields. The `id` covers them, so no one can strip them. A change that readers cannot ignore needs a new `v`. A message with an unknown enum value in `body` is skipped.

**Dedup.** `at` is part of the `id`, so only a byte-identical re-send dedups. A consumer that needs once-per-event must carry an event nonce in `body`.

**The contract.**

- Advisory only. The litmus test for "belongs on the bus": could a hostile message of this type cause the device to do work, move data, or deny or reschedule a sync? If yes, it is not a bus message. Content belongs on content channels where `main`-referenced validation makes junk inert; denial belongs nowhere.
- Classification always wins. Implicit tip-rewrite classification sets severity. Today it is signature-blind; see Standing improvement. Messages may only enrich inside the class the classification already found. Only messages whose signatures verify against roster keys may reach the UI. The reader tries each key in the roster at the fetched `main` tip, so a removed key fails. `from` is never shown as an identity, because any rostered key can sign for any device.
- Bodies carry fields, never prose the UI copies. The interface renders fixed localized templates interpolating whitelisted fields. This rule, not signatures, is the channel's actual boundary.
- Merge preserves the unknown. The union merge walks raw tree entries and never drops one. It does not validate. Validation happens at consumption: path shape, topic charset, id format, per-message size, and the checks in the Layout paragraph. A merge that validated would let a v1 publisher silently delete v2 topics.
- Caps bind the reader, not just honest publishers. Reading is work, so the parse path carries size and depth limits. The reader also stops at a hard entry count. A board over that count is ignored whole, and the consumer uses its non-message fallback.
- Write-time prune, by path only. It drops entries outside the time window, non-conforming paths, then the oldest entries above per-topic and total caps (ties break on `id`). Flooding can evict honest messages; that loss is accepted. Message loss is accepted by contract, so the attachments rule against write-time pruning does not transfer.
- Publish is best-effort and last in the push order (line, main, gossip, then messages). It chains on the fetched tip with the standard reject-reconcile pass. Devices fetch the board with a force refspec. Board compaction is the only force-replace. It triggers when the entry count passes the hard cap. It builds a commit parented on the vault root commit, preserving root-of-history classification. The tree contains the union of all entries that survive the path-based prune to a low watermark below the hard cap, unknown topics and versions included. It adds one `cleanup.board-compacted` message in the same commit. A force push overwrites concurrent compaction pushes; a racing non-force publisher fails push, fetches the compacted tip, and reconciles by chaining. Readers use the tip tree only and never walk board history.
- Unknown `type` or `v`: skipped. Forward compatibility is new types, never new refs.
- Every consumer keeps a mandatory non-message fallback. Compaction can prune a board before a device reads it, so no message may be the only detection path, and no message class may need guaranteed delivery.
- Banned by review gate: presence and liveness messages (they leak activity patterns to any repo reader and bloat the board), sync-scheduling hints (a denial primitive), and schema-update flags (old clients are the only audience that needs those, and old clients never read the ref; that signal belongs in `main`-visible data).

**The trigger.** Implement the bus only when a real consumer passes all four tests below. Real means a feature in the tree or an accepted ADR. The compaction notice enrichment counts as the first consumer, so one qualifying proposal is the second.

- No natural carrier. Name each channel the consumer's reader already fetches. For each, state why the event cannot ride it. A carrier is natural when the data is validated from `main` or signed in a commit, and it is atomic with the event.
- No mixed-fleet blocker. State the minimum client version that must read the message. The feature must stay correct when older clients never read it.
- Litmus passed. A hostile message of this type cannot cause work, data movement, or a sync denial.
- Fallback named. The consumer has a non-message detection path.

The proposer records the four answers in an amendment to this ADR or in a new ADR. The bus work item starts only after that record is accepted. Until then the ADR is the standard, not a work item.

**Conformance tests.** The implementation writes these tests before the code. A v1 merge keeps a v2 topic. A v1 prune removes an expired v2 entry by path. A future-dated `at` is dropped. Topic, path-`at`, and id mismatches are skipped. A board over the hard entry count is ignored. A key removed from the roster fails verification. The reader limits hold on a large or deeply nested body. A compacted board tip roots on the vault root. Compaction prunes below the hard cap, so it does not retrigger at rest.

**Standing improvement, independent of the bus.** Side-channel rewrite classification should learn roster-signature verification. The compaction genesis is already a signed commit, and the roster public keys are in vault metadata. So the data for "rewritten by a rostered key" versus "rewritten by an unknown signer" exists. The verification code does not exist yet, and no one has run it on a locked vault. Verify against the roster at the fetched `main` tip. This work blocks any UI use of `compaction.json` or of a bus message. It uses the same roster trust root as the bus and needs no second ref.

## What was rejected

- Building the bus now with one customer. The trigger exists because the notice shipped without it and works.
- Piggybacking on the gossip ref. It pollutes the deny-only security channel with advisory chatter under compaction semantics that do not match.
- One ref per feature. This is the proliferation the standard exists to prevent.
- Real `git notes` attached to `main` commits. Entries dangle on rewritten history and bind vault-level messages to commit granularity.
- Message-driven notice migration. The classification-wins rule rejects it. The enrichment rides the compaction genesis instead.

## Consequences

- The two shipped channels stay the only ones until the trigger fires; every future signal proposal is tested against the litmus and the trigger before it earns a ref or a type.
- The compaction notice enrichment is carried by the attachments genesis, so it needs no fetch, adds no growth, and cannot precede its own event.
- Plaintext event metadata (device ids, event types, timing) is readable by anyone with repo access, the same exposure as gossip heads. Force-replaced refs leave old objects on the forge until provider garbage collection, so event timing persists forge-side; nothing timing-sensitive may become a message body.
- Roster-verified reading on locked vaults is an open verification item. Roster public keys live in vault metadata readable without unlock, but no shipped code verifies a signature against them. The classification upgrade is a prerequisite for any UI use of `compaction.json` or of a message.
- Until that upgrade lands, classification is signature-blind. A holder of forge write access can cause a rewrite classification. This is a known, recorded limitation.
- Caps bound parse work, not transfer. A device fetches the whole board before any cap applies. Board compaction is the only bound on transfer size.
