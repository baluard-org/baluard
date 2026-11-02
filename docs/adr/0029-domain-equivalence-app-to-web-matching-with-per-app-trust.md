# ADR 0029. Domain Equivalence & App-to-Web Matching with Per-App Trust

> Status: Accepted (2026-09-17)

## Context

Related sites such as `google.com` and `youtube.com` should match each other without manual alias setup. Native app fill targets (`androidapp://<package>`) cannot safely auto-match web credentials, because a malicious package name could be crafted to request them. This was recorded as D26.

## Decision

**Bundled equivalence groups.** `baluard-core` embeds the Bitwarden equivalent domain groups in `crates/baluard-core/src/resources/global_equivalent_domains.json`. Under the `Domain` match strategy, entries for equivalent domains match bi-directionally without manual alias configuration.

**Custom equivalent domains.** Users configure custom groups in mobile Settings. Groups persist in `meta/settings.enc` as `custom_equivalent_domains: Option<Vec<Vec<String>>>`. Each entry is sanitized to strip pasted schemes and paths, then folded to its registrable domain. `UriMatchStrategy::matches_with` evaluates custom groups alongside global groups.

**App-to-web matching with trust on first use (Path B).** When `suggest_app_logins` is enabled, candidate domains are reversed from package labels (`com.mybank.app` becomes `mybank.com`) and validated against public suffixes. Candidates surface under `app_suggestions` in `VaultState::autofill_query`.

**Explicit trust boundary.** The first time a native app encounters matching web credentials, `AutofillActivity` shows an explicit trust banner ("Trust this app for <domain>?"). The decision is recorded through `MobileVault::autofill_app_trust` or `autofill_app_reject` into `trusted_app_packages` or `rejected_app_packages` in `settings.enc`. Trust is scoped strictly per `(package, domain)` pair.

## Consequences

Package lookalikes such as `com.mybank.evil` cannot inherit trust from legitimate packages. They must pass the explicit trust prompt independently.

App-to-web suggestions are opt-in through `suggest_app_logins`, and untrusted apps never receive an automatic match.

## References

- `docs/adr/0090-android-autofill.md` for background and verification
