# Baluard mobile

Compose Multiplatform (Android + iOS) client for Baluard.

**Status: Phase 1 scaffold (UNTESTED).** The Rust FFI surface is proven (see the Phase 1 spike log in `docs/plan-mobile-apps.md`). The Kotlin/Gradle code here is blind scaffold — compile it on a macOS host per `docs/mobile-dev-setup.md`.

## Structure

- `shared/` — KMP module: Compose UI + `VaultRepository` (wraps UniFFI bindings)
- `androidApp/` — Android shell (single-Activity Compose host)
- `iosApp/` — iOS shell (create the Xcode project on-host; sources only in-repo)

## Build

See [`docs/mobile-dev-setup.md`](../docs/mobile-dev-setup.md).

## What works today

- `crates/baluard-uniffi/` compiles, links `baluard-core` + `baluard-runtime`, exports FFI symbols.
- `generate_recovery_phrase()`, `derive_kek()`, `mobile_version()` cross the FFI boundary (2 unit tests pass).
- The async-runtime bridge (tokio + uniffi 0.28 + runtime) compiles and runs.

## What needs the host

- APK build (Android NDK)
- iOS sim app + credential-extension linking (Xcode)
- UniFFI Kotlin binding generation (0.28 has no standalone bindgen binary)
