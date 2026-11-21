# ADR 0115. Dependency-Advisory Backlog Behind the Hard Audit Gate

> Status: Accepted (2026-11-21)

## Context

The release gate's audit step silently no-op'ed whenever `cargo-audit` was
missing, so months of advisory entries accumulated unseen. Making the gate
hard (ADR fold during the 0.8.0 tooling pass) surfaced 38 findings in one
run. A semver-compatible `cargo update` sweep cleared 9. The remaining 29
vulnerabilities sit behind dependency-MAJOR moves that are release-cycle
work, not lockfile work:

1. **iroh 0.35 pin (22 findings).** `hickory-proto` (16), `hickory-resolver`
   (1), and `rustls-webpki` 0.102.8 (5) are all held by iroh 0.35's own
   dependency pins; the hickory fixes ship in 0.26.x and webpki in
   0.103.16+, both outside what iroh 0.35 permits. Bumping iroh reopens the
   vendored `netwatch` patch (documented in docs/dev/release-protocol.md, build matrix) and requires a
   macOS leg rerun per the release runbook.
2. **zip 2.6 → 9 (6 findings).** The zip crate's advisories fix only in the
   9.x line. The root-lock copy is dev-only (test fixtures); the desktop's
   runtime copy parses the updater zip we download. Exposure is bounded:
   bytes are SHA256-verified against a signed manifest before extraction,
   extraction caps at 3 GiB, and symlink entries are skipped. The upgrade
   is an API-rewrite task (extraction code paths changed shape across the
   major line).
3. **crypto-bigint 0.5 (1 finding).** Held by `rsa` 0.10-rc's own pin; the
   timing-side-channel acceptance for RSA imports (ADR 0111) already covers
   the parent crate's risk posture, and this finding is part of that same
   import path.

## Decision

- The audit gate stays hard for every advisory NOT listed in
  `.cargo/audit.toml`; the ignore list there cites this ADR and groups the
  IDs by family.
- Each family carries an unblocking condition: the iroh bump (with netwatch
  rebase and macOS leg rerun), the zip 9 extraction rewrite, and the rsa
  0.10 final release (which frees crypto-bigint and, when it fixes Marvin,
  may retire ADR 0111's acceptance).
- New advisories in dependencies NOT on the ignore list fail the gate
  immediately; an ignore entry without a citation in an accepted ADR is a
  policy violation.

## Consequences

- `just check` runs a real audit on hosts with `cargo-audit` installed and
  fails loudly on hosts without it (escape: `BALUARD_SKIP_AUDIT=1`, for
  container runs that have no advisory DB access).
- The backlog is reviewable: re-triage whenever iroh, zip, or rsa move, and
  prune ignore entries as their unblocking conditions land.
- The zbus/paste/instant unmaintained warnings stay non-blocking warnings;
  unmaintained status is tracked upstream by their parents, not by us.
