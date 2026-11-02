# ADR 0027. Sync Header Refactor + Favicons

> Status: Accepted (2026-06)

## Context

The sync header showed git jargon ("push", "pull", "remote", "branch"). Multi-vault provider state also leaked across vault switches. Separately, every login in the list looked the same, and embedding a base64 icon payload in every entry would bloat the entries. The app icon set was hand-curated. This was recorded as D24.

## Decision

**Sync header.** Git jargon is replaced by a one-click sync UI. The sidebar header shows the provider and a repo link (`cc09c51`). The `AutoSyncIndicator` status pill has the states idle, syncing, dirty, and offline. The sync label is gated with `<Show>` inside `<Transition>` to silence background pulls. Provider state is scoped to the active vault (`58016d4`).

**Favicons.** Website icons are opt-in, persisted, and fetched at save time. A new `favicon` field on the cipher envelope has a 16 KB cap, a magic-byte check, and is off by default. The change is in `desktop/src/lib/cipherSchema.js` with an `Avatar` and `CipherRow` chip treatment.

**App icons.** `just app-icons SOURCE OUT` builds 48 and 128 PNG variants from a source logo for macOS, Windows, Linux, Android, and iOS, plus the monochrome tray and system tray icons. It replaces the hand-curated icon set with a deterministic pipeline. `desktop/src-tauri/icons/` is regenerated on build.

## Consequences

The sync UI no longer exposes git terms to users. Favicons solve the "every login looks the same" problem without adding a base64 payload to every entry, and the default-off setting keeps the fetch opt-in.
