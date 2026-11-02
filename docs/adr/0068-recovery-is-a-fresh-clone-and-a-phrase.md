# ADR 0068. Recovery Is a Fresh Clone and a Phrase

> Status: Accepted (2026-09-29)

## Context

The Space Recovery Kit requires a disaster recovery ceremony for a fresh clone. A fresh multi-device clone cannot open a `VaultHandle`: device resolution needs a local keystore to match keywraps, and the clone has none.

## Decision

Implement path-only `recover_device_with_kit`, like `create_introduction`. It unwraps the Root Key with the phrase, verifies the vault canary, creates fresh device keypairs, seals the keystore under the vault-salt devkey subkey, wraps the key under root-key-keywrap, adds the registry entry, and binds the device to the live Owner row. It never wipes the roster. The KEK uses the vault-level KDF parameters without a fresh salt, so the device uses the ordinary admin unlock path. Identity adoption uses the existing cross-device heal. The host-level, pre-token route is `vault.recover_kit`, like `join.introduce`.

Run deterministic refusals before disk mutation, in this order: brick guard, kit presence, phrase, Root Key canary, KEK canary, and live Owner resolution. Verify all three canaries: the phrase proves the kit, the Root Key canary proves the vault, and the KEK canary proves the password. Put kit enable, disable, and status behind one Owner/Admin gate, including status. Render a refusal as unknown rather than as an off state.

## Consequences

The ceremony assumes the master password is known; the kit covers device loss, not password loss. Recovery is CLI-first through `baluard vaults recover-kit <slug>` because it runs on a fresh machine before app login. Desktop provides the ordinary admin surface; a login-screen recovery UI is deferred. Repeated recovery on new clones adds devices, each requiring the phrase.

## References

- ADR 0067
- `create_introduction`
- `join.introduce`
