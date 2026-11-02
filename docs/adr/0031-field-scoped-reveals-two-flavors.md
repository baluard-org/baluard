# ADR 0031. Field-Scoped Reveals, Two Flavors (IS-6)

> Status: Accepted (2026-09-22)

## Context

Users need to share a few fields of a Login with an expiring, view-only file, either with a known contact or with someone who has no identity or vault. The work is slice S2-2 and was recorded as D28. Two review findings shaped the design. A captured signature could re-seal a stale or relabeled send, and the guest envelope's Argon2id parameters are attacker-controlled. Without a clamp, a hostile file could set `memory_kib` to terabytes and abort the daemon on allocation the moment the victim types the passphrase (a blocker).

## Decision

A Login's fields (url, username, password, and TOTP as opt-in) export as a self-contained expiring file (`crates/baluard-core/src/vault/reveals.rs`) in two flavors.

- **Contact-key (Level 1).** HPKE-wrapped to a contact card's wrap pubkey and sender-attributed.
- **Passphrase-guest (Level 0).** Argon2id over an app-generated 7-word passphrase, with no identity involved. The Baluard app opens it without a vault, through "Open a shared file" on first run.

Reveals are view-only. Unlike IS-3 packages, opening never mutates the recipient's vault.

Daemon routes: `reveals.export_contact`, `reveals.export_guest`, and `reveals.open_contact` (token-gated), and `reveals.open_guest` (host-level, tokenless, pure compute). The TOTP seed never crosses IPC. Open returns the current code and its validity window.

**Expiry binding.** The envelope carries `expires_at` in plaintext, and it feeds the seal's AAD marker (`item-reveal-payload-v1/exp/<unix>`). An edited date breaks the GCM tag, and the sealed copy must equal it. Expired files refuse in plain language and the recipient asks for a fresh reveal.

**Sender attribution.** The identity key signs `recipient_wrap_pub ‖ expires_at ‖ created_at ‖ item_name ‖ fields`. That covers everything a captured signature could otherwise re-seal. The label and freshness timestamp are signed so a stale capture cannot pass as a new send under a new name. A card's self-signature is copyable and HPKE Base mode authenticates neither party.

**Untrusted KDF parameters.** The open path clamps the guest envelope's Argon2id parameters to 128 MiB, 6 iterations, and 4 lanes. The DesktopStd seal path uses 64 MiB, 3, and 2. Legitimate files verify, and hostile ones collapse to a normal-cost derivation that fails the GCM tag.

## Consequences

The generator's passphrase pool is bilingual (EFF English plus Spanish BIP-39, 16,380 words, about 98 bits at 7 words). Voice delivery of a mixed-language passphrase is a known wrinkle, deferred to the UI wave. The app also shows the words on screen. A language-scoped draw needs a generator option.

There is no UI or CLI yet. The share sheet and "Open a shared file" belong to the §4.8 wave. Error strings inside core stay technical until that wave maps them to plain copy, which matches packages. Route-level tests for the three gated actions remain blocked by the harness, which cannot mint session tokens for vault routes. The P6 pin covers their gating.

## References

- `docs/adr/0085-sharing.md` §4.6 (IS-6) and the S2 tracking row for the wave context
