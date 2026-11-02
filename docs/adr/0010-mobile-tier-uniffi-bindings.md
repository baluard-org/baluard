# ADR 0010. Mobile Tier: UniFFI Bindings

> Status: Accepted

## Context

Mobile applications need access to the Rust vault engine from Kotlin on Android and Swift on iOS, without duplicating the core implementation or introducing another implementation language. Mobile operating systems do not support the long-lived daemon of the desktop tier (ADR 0008), so the runtime must be embeddable in the app process.

## Decision

The mobile apps will use Mozilla UniFFI through the `baluard-uniffi` crate, which exposes `baluard-runtime` and `baluard-core`. The crate builds as a `cdylib` and uses UniFFI proc-macro mode (`uniffi::setup_scaffolding!()` and `#[uniffi::export]`), so no UDL interface file exists. UniFFI generates the Kotlin bindings from the compiled library's metadata, and the generated file is committed and regenerated only when the exported Rust API changes (`just android-bindings`). The Android native library is built for four ABIs into `mobile/androidApp/src/main/jniLibs/` (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`), and the APK packages only the ABIs named by the `baluard.abis` Gradle property, with `arm64-v8a` as the alpha default. The Android build vendors OpenSSL so libgit2 cross-compiles without a system library. iOS bindings are intended to be generated as a Swift xcframework; that build is not yet present in the repository.

The Rust core remains the single source of truth. The design uses no Go, cgo, or gomobile. The mobile client hosts `baluard-runtime` directly in-process and does not use a background daemon or the socket gateway (ADR 0007).

**Boundary rules.** Errors cross the boundary as a typed `BaluardError` enum, so the UI can distinguish a wrong password, a network failure, and an unpaired device without parsing strings. Asynchronous Rust methods are exported with the Tokio async runtime and surface in Kotlin as `suspend` functions, running off the UI thread. Secret-bearing values cross the boundary only when the user explicitly selects them: the autofill query returns match metadata without passwords, and a password is fetched only for the entry about to be filled (ADR 0090). Memory ownership stays with Rust, which zeroizes key material on drop (ADR 0001); foreign code receives only opaque handles and the values it was explicitly given.

**Process model.** Each OS process that opens a vault owns an independent runtime and unlock state, so the main app and the Android autofill process never share key material (ADR 0089, ADR 0090).

## Consequences

The bindings provide a memory boundary between Rust and foreign code while keeping vault logic in Rust. Android Phases 0 through 6 are complete, including Compose Multiplatform onboarding, home, filtered entry lists, eight cipher types, detail and edit at desktop parity, deep search, generator, TOTP, biometric ceremony, auto-lock, synchronization, conflict panel, multi-vault, R8 build, Android Autofill Service with inline suggestions, save prompt, and quick-settings tile accessibility fill. The iOS credential extension is deferred beyond 1.0 (2026-09-27), and iOS platform-specific implementations remain pending. Because the generated Kotlin file is committed, an exported-API change that is not followed by regeneration leaves the app and the library out of step. Android API 32 (Android 12L) is the minimum platform.

## References

- `crates/baluard-uniffi/`
- `crates/baluard-uniffi/src/uniffi.toml`
- `mobile/androidApp/src/main/jniLibs/`
- `mobile/scripts/regen-bindings.sh`
- ADR 0089, ADR 0090
