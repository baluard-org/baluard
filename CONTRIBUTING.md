# Contributing to Baluard

Thank you for your interest in contributing!

## Quick Start

```bash
cargo install just      # Build runner
git clone https://github.com/baluard-org/baluard.git
cd Baluard
just                    # List all targets
just check              # Full CI parity (fmt + clippy + test + build)
just seed-demo          # Create demo vault with 31 test entries (password: demo)
```

See **[docs/dev-setup.md](docs/dev-setup.md)** for prerequisites, platform-specific setup, and all build commands.

## Guidelines

This document provides community guidelines for a safe, respectful, productive, and collaborative place for any person who is willing to contribute to this project. It applies to all "collaborative space", which is defined as community communications channels (such as mailing lists, submitted patches, commit comments, etc.).

Participants will be tolerant of opposing views.
Participants must ensure that their language and actions are free of personal attacks and disparaging personal remarks.
When interpreting the words and actions of others, participants should always assume good intentions.
Behaviour which can be reasonably considered harassment will not be tolerated.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure tests pass (`just test`)
5. Ensure no warnings (`just lint`)
6. Format code (`just fmt`)
7. Submit a pull request

## Testing

### Rust

- `just test` — full suite (core + daemon + CLI + desktop-driver bits)
- `just test-core` — `baluard-core` only (~400 tests, ~5s)
- `just test-cli` — CLI integration tests (`crates/baluard-cli/tests/`)
- `just test-nmh` — native messaging host tests (`crates/baluard-nmh/`, ~14 tests)
- `just test-verbose` — pass `--nocapture` to see stdout

CLI tests spawn the `baluard` binary via `assert_cmd` against a
`tempfile::TempDir` vault path and use `BALUARD_PASSWORD` (recognized by
`init`, `unlock`, `add`, `list`, `archive`, `unarchive` in direct mode) to
bypass the master-password prompt and the recovery-phrase verification
step. `BALUARD_DATA_DIR` is redirected into the same `TempDir` so the
global registry never leaks into the developer's real config.

CLI tests cover init, unlock, list, and add today. `lock` is deferred to
the daemon-spawn-fixture PR (it is daemon-only by design). PRs adding a
new CLI command should add at least one happy-path + one error-path test
in the matching `tests/<command>.rs` file using the helpers in
`tests/common/mod.rs`.

### JavaScript / SolidJS

Desktop uses Vitest (jsdom). Run via `npm test` from `desktop/`. The
browser extension (`browser/shared/`) also uses Vitest + jsdom; run via
`just test-browser` or `cd browser/shared && npm test`. The mock for
`chrome.*` lives in `browser/shared/tests/setup.js` and is loaded via
vitest `setupFiles` so it exists before any source IIFE runs.

## Code Standards

### Rust
- Edition 2024, MSRV 1.85
- `thiserror` for library errors, `anyhow` for CLI/bin
- Feature flags: `git-sync`, `org`, `emergency`
- `zeroize` crate for all sensitive memory (never `write_bytes`)
- `proptest` for property-based tests
- Strict backwards compatibility

### JavaScript/SolidJS
- ES modules, named exports
- `===` only
- Biome for linting

### CSS
- Tailwind v4
- CSS variables for theming
- BEM naming
- No `!important`

### Protobuf
- proto3 syntax, `baluard.vault` package

## Security

This is a password manager. Security issues take priority over everything else.

- **Never** log passwords, keys, or decrypted secrets
- **Always** use `zeroize` for sensitive memory
- **Always** validate input at trust boundaries
- **Never** introduce duplicate crypto implementations
- Report security vulnerabilities privately to the maintainers

## Commit Messages

```
type: short description

Longer explanation if needed.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`

## PR Review

All PRs require review. Reviewers check for:
- Correctness and edge cases
- Security implications
- Test coverage
- Doc accuracy
- No unnecessary complexity
