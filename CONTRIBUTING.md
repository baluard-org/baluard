# Contributing to Baluard

Thank you for your interest in contributing!

## Quick Start

```bash
cargo install just      # Build runner
git clone https://github.com/EstebanForge/Baluard.git
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
