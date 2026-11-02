# ADR 0041. Request-Access JIT + Collection Catalog (S3-6)

> Status: Accepted (2026-09-24)

## Context

A member should be able to ask for collection access instead of waiting for an admin to notice them. A hostile member can seal to the approvers' public wrap keys, and a request file lives in a self-service subtree where it can be copied. The design must keep approval an admin commit and must not let a crafted ask mint more than it claims. The work is slice S3-6 and was recorded as D38. A high-effort external review round accepted 8 findings, including 2 blockers, and declined 1.

## Decision

**Request file.** The ask lives at `meta/members/<m>/requests/<id>.json`. The members own-subtree Any policy row makes writing it self-service at any role, and another member's subtree stays Admin-only. Approval and denial (which deletes the file) are therefore an admin commit by construction. `collection_id` and `access` ride as plaintext (plan rule: plaintext is UUIDs, names, and trust). The free-text note is HPKE-sealed to the approver set (live Owner and Admin rows that carry identity wrap pubkeys) through one random payload key wrapped per approver. The plaintext fields are bound inside the sealed payload, so a tampered file decrypts to a mismatch and counts as inert instead of granting what the plaintext claims.

**Catalog.** The optional `meta/collections/catalog.json` is the plan's explicit opt-in. Publishing it exposes display names to requesters, whose alternative view is an opaque id. It lives inside `meta/collections/`, so the Admin policy row gates it and the UUID-stem walkers skip it inertly.

**Approval re-derives from the seal, never the client.** The admin's approve call decrypts the ask with their own identity. Everything granted (collection, requester, requested access) comes from that sealed row. Only `access` (read or write) and `expires_at` are admin overrides. `upsert_grant` rules apply unchanged (tombstoned targets, viewer plus write unmintable, expiry sanity). Approval consumes the request file in the same commit. Denial consumes it without granting. The grant list is the member-visible outcome surface, because verification is clock-free and decisions land through sync. New activity events `access-granted` and `access-denied` land on the admin's local log.

**Accepted review findings**

- Blocker 1: a crafted `access: manage` ask (consistent plaintext and seal) would have minted delegated-admin powers at approval. Manage is now refused at submit, at decrypt, and at approve, and the route parser never produces it. Manage grants go through `collections.grant`.
- Blocker 2: the seals did not bind the requester, so a pending file copied into another member's requests directory redirected the grant. The HPKE context and sealed payload now pin the requester, and a transplanted file counts as inert.
- The inbox walk is deterministic with a per-member cap, because submit-side caps are not enforceable at verification and a crafted flood must not starve the inbox.
- Submit is grant-aware. An ask covered by a live grant refuses, expired grants lapse, upgrade asks are legitimate, and viewer plus write is unmintable at ask time too.
- The desktop ADR 0024 allowlist additions.
- Zeroizing on the decrypted payload key.
- Read-side validation: the sealed note is re-validated, and catalog rows are capped, validated, and filtered against deleted collections.

## Consequences

Approvals are admin-only by construction. A delegated manager consuming another member's request file would wedge, per the first-denied-commit rule. A pending ask sealed only to a since-rotated approver counts as inert. Multi-admin vaults keep surviving seals, and the asker can withdraw and re-ask.

There is no notices-surface integration yet. The inbox route is the admin surface, and the badge rides the §4.8 wave. CLI and UI surfaces are later waves.

Declined: forcing catalog names from decrypted collection names. Curation is the point of an explicit catalog.
