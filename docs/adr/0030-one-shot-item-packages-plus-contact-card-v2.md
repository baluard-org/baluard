# ADR 0030. One-Shot Item Packages (IS-3) + Contact Card v2

> Status: Accepted (2026-09-22)

## Context

Sharing needs a way to hand a single entry to another person without a live link. A contact card's self-signature only proves the card is self-consistent. Anyone can copy a public card verbatim, and HPKE Base mode authenticates neither party. Without more, anyone holding a target's public card could seal a malicious item that opens as "from" any identity. This was found in the review round as a blocker. The work is slice S2-1 and was recorded as D27.

## Decision

**Package.** A cipher exports as a self-contained encrypted file (`crates/baluard-core/src/vault/packages.rs`), HPKE-wrapped to a contact's identity X25519 wrap pubkey and delivered out of band (chat, email, USB). The recipient opens it and gets a fresh entry with a new id and their own vault's item keys. The copy is inert and one-shot. There is no live link, no revocation, and it cannot be un-shared. Level 1 (Channel) trust suffices because packages wrap no live keys. Daemon routes: `packages.export` and `packages.import`, both token-gated. Import is in `COVER_MUTATION_ACTIONS`.

**Card v2.** The signed contact card carries the identity X25519 wrap pubkey inside the signed payload (`baluard-contact-v2` domain). The Level 2 verification-code check therefore covers the wrap key, and a swapped wrap key breaks the card signature. Address-book rows stored before v2 load with an empty key (serde default). Package export refuses them with re-share guidance instead of failing cryptically.

**Sender attribution.** The sender's identity Ed25519 key signs `recipient_wrap_pub || sent_at || item bytes` (`PackagePayload::signing_payload`), and the signature is verified at open. Re-wrapping a package to a different recipient fails the signature.

**Metadata hygiene.** The envelope carries key material only. The item, sender card, and timestamp all live inside the `secret_file`-sealed payload, with purpose-bound AAD, so an intercepted file leaks nothing.

**Size caps.** The payload cap is 2 MB. It matches the XL cipher tier, so a sealed package survives base64 and JSON expansion under the 4 MB daemon socket frame limit. The seal and open size limits were reconciled in review. The route applies a pre-decode length bound.

**Import stripping.** The recipient's entry drops attachments (bytes never travel), password history, folder assignment, the archived flag, and the sender's creation date. Stripping happens on both export and import, so a hand-built payload cannot resurrect them.

## Consequences

Recipients can receive an entry from any channel without a live trust relationship. They cannot be given revocation or updates for it.

Packages have no expiry. Expiry in AAD belongs to the IS-6 guest flavor.

There is no CLI or UI yet. The share sheet and "open a shared file" belong to the §4.8 wave. The feature is tested against a scripted second vault and not over a live transport.

## References

- `docs/adr/0085-sharing.md` §4.6 (IS-3) and the S2 tracking row for the wave context
