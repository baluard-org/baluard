# ADR 0107: Side-Channel Message Bus, Standard and Trigger

Date: 2026-11-14
Status: accepted (standard specified; implementation deferred behind the trigger below)
Review: adversarial design review folded in (2026-11-14); three findings reshaped the decision, zero-trust verified against the tree

## Context

Baluard already runs two side channels on `refs/notes`, both invisible in forge branch and tag UIs: `refs/notes/baluard-gossip` (deny-only rollback detection, roster-signed head announcements) and `refs/notes/baluard-attachments` (content transport, content-addressed blob line, pins validated from `main` metadata). A third need surfaced while building the compaction notice: telling other devices, before any pull, that shared storage was cleaned up. The first proposal was a generic per-vault message board on `refs/notes/baluard-msgs`, published immediately. The review found the first consumer had a spoofable-override flaw, one candidate use (an update flag) structurally cannot work on any bus, and the board's merge needed a preserve-unknown rule to survive mixed-version fleets. This ADR records the standard that came out of that review, and the trigger that decides when it gets built.

## Decision

**The standard is specified now; the bus is built later.** A future advisory channel `refs/notes/baluard-msgs` follows the contract below. It is implemented only when the trigger fires. Until then, event facts ride the channel they describe: the compaction notice enrichment travels as a `compaction.json` entry inside the attachments compaction genesis (numeric fields only, signed with the genesis commit, impossible to prune before it is read, ignored harmlessly by old clients that never parse it).

**Envelope, versioned from day one.** JSON: `v` (1), `type` (namespaced, dot-separated; topic is the first segment), `from` (device uuid, never rendered as identity), `at` (epoch seconds, informational only, clamped at prune and read to `[now minus TTL, now plus skew]` so a future-dated message cannot pin bloat forever), `id` (hex SHA-256 over the canonical envelope with `id` and `sig` excluded; identical re-sends dedup for free), `body` (numeric and enum fields only), `enc` (reserved for a future HPKE-boxed body), `sig` (ed25519 by the device's commit-signing key; publishers sign when a key exists and skip publish when it does not, mirroring the attachments line). Canonical form: integers only, maps serialized in sorted key order. Tree layout `msgs/<topic>/<id>.json` with topic charset `[a-z0-9-]`, blocking path injection.

**The contract.**

- Advisory only. The litmus test for "belongs on the bus": could a hostile message of this type cause the device to do work, move data, or deny or reschedule a sync? If yes, it is not a bus message. Content belongs on content channels where `main`-referenced validation makes junk inert; denial belongs nowhere.
- Classification always wins. Implicit, signature-blind detection (tip-rewrite classification) sets severity. Messages may only enrich inside the class the classification already found. Only messages whose signatures verify against roster keys may reach the UI, and `from` is never shown as an identity, because any rostered key can sign for any device.
- Bodies carry fields, never prose the UI copies. The interface renders fixed localized templates interpolating whitelisted fields. This rule, not signatures, is the channel's actual boundary.
- Merge preserves the unknown. Union merges walk raw tree entries; structural validation (path shape, topic charset, id format, per-message and per-topic size caps) happens at consumption, never inside the merge, or a v1 publisher would silently delete v2 topics.
- Caps bind the reader and the merge, not just honest publishers. Reading is work, so the parse path carries size and depth limits.
- Write-time TTL prune with the clamped `at`, plus per-topic and per-`from` caps. Message loss is accepted by contract, so the attachments rule against write-time pruning does not transfer.
- Publish is best-effort and last in the push order (line, main, gossip, then messages), chained on the fetched tip with the standard reject-reconcile pass; board compaction is the only force-replace, and it publishes its own `cleanup.compacted` in the same commit it builds.
- Unknown `type` or `v`: skipped. Forward compatibility is new types, never new refs.
- Every consumer keeps a mandatory non-message fallback. Compaction can prune a board before a device reads it, so no message may be the only detection path, and no message class may need guaranteed delivery.
- Banned by review gate: presence and liveness messages (they leak activity patterns to any repo reader and bloat the board), sync-scheduling hints (a denial primitive), and schema-update flags (old clients are the only audience that needs those, and old clients never read the ref; that signal belongs in `main`-visible data).

**The trigger.** Implement the bus only when a second real consumer exists that (a) has no natural carrier on a channel it already uses, and (b) has no mixed-fleet blocker. Until then the ADR is the standard, not a work item.

**Standing improvement, independent of the bus.** Side-channel rewrite classification should learn roster-signature verification: the compaction genesis is already a signed commit, so "rewritten by a rostered key" versus "rewritten by an unknown signer" is derivable today and is stronger attribution than any bus message.

## What was rejected

Building the bus now with one customer: the trigger exists precisely because the notice shipped without it and works. Piggybacking on the gossip ref: pollutes the deny-only security channel with advisory chatter under compaction semantics that do not match. One ref per feature: the proliferation this standard exists to prevent. Real `git notes` attached to `main` commits: entries dangle on rewritten history and bind vault-level messages to commit granularity. Message-driven notice migration: rejected per the classification-wins rule; the enrichment rides the compaction genesis instead.

## Consequences

- The two shipped channels stay the only ones until the trigger fires; every future signal proposal is tested against the litmus and the trigger before it earns a ref or a type.
- The compaction notice enrichment is carried by the attachments genesis, so it needs no fetch, adds no growth, and cannot precede its own event.
- Plaintext event metadata (device ids, event types, timing) is readable by anyone with repo access, the same exposure as gossip heads. Force-replaced refs leave old objects on the forge until provider garbage collection, so event timing persists forge-side; nothing timing-sensitive may become a message body.
- Roster-verified reading on locked vaults stays an open verification item: roster public keys live in vault metadata readable without unlock, but the shipped classifier does not verify signatures yet, and that upgrade is a prerequisite for any UI-consumed message.
- The signature-verification gap in implicit classification is a known, recorded limitation until the classification upgrade lands.
