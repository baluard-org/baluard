# ADR 0080. One Writer, Two Formats

> Status: Accepted (2026-10-03)

## Context

Recovery phrase export must use one secure implementation across vault creation and phrase rotation. The wizard's bare phrase file and the rotation card's webview Blob download lacked consistent formatting, a save dialog, and owner-only file permissions.

## Decision

Implement one Rust-side renderer in `recovery_sheet.rs` for TXT and one-page PDF, used by the creation wizard and ADR 0077 rotation ceremony through one Tauri command. Render in core and write through `write_secret_file`, which sets mode 0600 from the first byte, uses atomic rename, and replaces symlinks. Retire Markdown export. Keep PDF generation dependency-free: emit text-only PDF 1.4 using base-14 fonts and WinAnsi encoding. Use a fixed 2-by-12 word grid and fail closed unless the phrase has exactly 24 words. Emit no `BT`/`ET` pair for the empty warning case. Place the title at y=720 to clear the US Letter unprintable margin.

Expose the same renderer to mobile through UniFFI `recovery_sheet_bytes`; return bytes only and do not expose a filesystem path. Android saves through the SAF document picker. iOS reports unsupported until its picker is implemented. The CLI continues to print the phrase on creation and adds no export flags.

Nest rotation localization under `recovery.rotation.*` because duplicate top-level `recovery` keys silently hide the creation keys when parsed. Locale parity checks must include duplicate-key detection within each file.

## Consequences

The deterministic PDF permits exact xref-offset checks and inspection of the uncompressed content stream. Renderer checks cover the `spawn_blocking` static-borrow constraint, the more-than-24-word case, and print margins. Android can export; iOS remains unsupported. Spanish and Portuguese use the dominant in-file terms, "bóveda" and "cofre."

## References

- ADR 0077
- `recovery_sheet.rs`
- `write_secret_file`
- `RecoverySheetSaver`
