//! TLS root configuration for libgit2 on platforms without an
//! OpenSSL-visible CA store.
//!
//! Android ships no `/etc/ssl/certs`: the device roots live under the
//! Conscrypt apex (`/apex/com.android.conscrypt/cacerts`, Android 14+) with
//! a legacy copy in `/system/etc/security/cacerts`. Vendored OpenSSL inside
//! libgit2 consults neither, and its file-based cert loading
//! (`SSL_CTX_load_verify_locations`) proved unreliable on-device, so
//! `ensure_tls_roots()` registers each device root directly through
//! `GIT_OPT_ADD_SSL_X509_CERT` — no file I/O in the trust chain at all.
//! Desktop platforms keep their system defaults (no-op).

#[cfg(target_os = "android")]
use foreign_types::ForeignType as _;
#[cfg(target_os = "android")]
use std::sync::Mutex;

#[cfg(target_os = "android")]
const CA_DIRS: &[&str] = &[
    "/apex/com.android.conscrypt/cacerts", // Android 14+
    "/system/etc/security/cacerts",        // legacy location
];
#[cfg(any(target_os = "android", test))]
const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
#[cfg(any(target_os = "android", test))]
const PEM_END: &str = "-----END CERTIFICATE-----";

/// GIT_OPT_ADD_SSL_X509_CERT from libgit2 1.9.4 include/git2/common.h
/// (git_libgit2_opt_t, index 45). libgit2-sys 0.18.5's hand-written Rust
/// bindings stop at index 44 and omit this member; re-verify the number
/// when bumping libgit2-sys, a new C-side enum member would shift it.
#[cfg(target_os = "android")]
const GIT_OPT_ADD_SSL_X509_CERT: std::ffi::c_int = 45;

/// Point libgit2 at a working CA store. Cheap to call before every remote
/// operation: registration results are cached behind the process Once.
pub fn ensure_tls_roots() {
    #[cfg(target_os = "android")]
    android_tls_roots();
}

#[cfg(target_os = "android")]
static TLS_DIAG: Mutex<Option<String>> = Mutex::new(None);

/// Record a TLS-setup outcome for the clone error surface. Success clears
/// the slot; a non-fatal note (excluded certs) survives so it still shows
/// if a later connection fails for another reason.
#[cfg(target_os = "android")]
fn tls_note(reason: Option<String>) {
    let mut slot = TLS_DIAG.lock().unwrap_or_else(|p| p.into_inner());
    *slot = reason;
}

/// One-shot diagnostic from the last TLS setup, consumed by the clone error
/// path so on-device failures name their failing step without needing adb.
#[cfg(target_os = "android")]
pub(crate) fn take_diag() -> Option<String> {
    let mut slot = TLS_DIAG.lock().unwrap_or_else(|p| p.into_inner());
    slot.take()
}

#[cfg(not(target_os = "android"))]
pub(crate) fn take_diag() -> Option<String> {
    None
}

/// Drain the thread's OpenSSL error queue into a compact string for
/// failure notes (lib/reason per entry).
#[cfg(target_os = "android")]
fn drain_err_queue() -> String {
    let mut parts = Vec::new();
    loop {
        // SAFETY: pure error-queue read; no OpenSSL state is mutated.
        let code = unsafe { openssl_sys::ERR_get_error() };
        if code == 0 {
            break;
        }
        let lib = (code >> 23) & 0xff;
        let reason = code & 0x7f_ffff;
        parts.push(format!("lib{lib}/r{reason}/{code:#x}"));
        if parts.len() >= 4 {
            break;
        }
    }
    if parts.is_empty() {
        "no queue".into()
    } else {
        parts.join(", ")
    }
}

/// Register one PEM cert block with libgit2's trust store through
/// GIT_OPT_ADD_SSL_X509_CERT (git_openssl__add_x509_cert -> the ctx store;
/// no file I/O, no BIO, no SSL_CTX_load_verify_locations).
#[cfg(target_os = "android")]
fn register_cert(pem_block: &[u8]) -> Result<(), String> {
    // The opts call below dereferences git__ssl_ctx with no NULL check
    // (libgit2 1.9.4 defect): it segfaults if git_libgit2_init never ran.
    // Raw libgit2_sys calls bypass git2-rs's internal init, so initialize
    // explicitly (refcounted, idempotent) before touching the opts.
    // SAFETY: refcounted process-global init; runs libgit2's init fns
    // (creates git__ssl_ctx) and must succeed (rc >= 0) before any opts.
    let init_rc = unsafe { libgit2_sys::git_libgit2_init() };
    if init_rc < 0 {
        return Err(format!("git_libgit2_init rc={init_rc}"));
    }
    let cert = openssl::x509::X509::from_pem(pem_block).map_err(|e| format!("pem parse: {e}"))?;
    // SAFETY: variadic libgit2 opt; passes one X509* matching the C side's
    // va_arg(ap, X509*). The store uprefs the cert (x509_lu.c X509_OBJECT_up_ref),
    // so the local wrapper may drop right after the call.
    let rc = unsafe { libgit2_sys::git_libgit2_opts(GIT_OPT_ADD_SSL_X509_CERT, cert.as_ptr()) };
    if rc != 0 {
        Err(format!("store add rc={rc} q: {}", drain_err_queue()))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "android")]
fn android_tls_roots() {
    // The X509s are added to libgit2's process-global trust store; do the
    // scan + registration at most once per process. A first run with no
    // readable store consumes the Once; retrying could not help (the store
    // does not appear mid-process).
    static ANDROID_TLS_INIT: std::sync::Once = std::sync::Once::new();
    ANDROID_TLS_INIT.call_once(|| {
        let dir = crate::paths::data_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tls_note(Some(format!("data dir unwritable {}: {e}", dir.display())));
            return;
        }
        // Remove the abandoned file-based bundle + probe leftovers from the
        // previous design; the store no longer reads any file.
        let _ = std::fs::remove_file(dir.join("ca-bundle.pem"));
        let _ = std::fs::remove_file(dir.join("ca-bundle.tmp"));

        let mut seen_blocks = std::collections::HashSet::new();
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for store in CA_DIRS {
            let Ok(entries) = std::fs::read_dir(store) else {
                continue;
            };
            // Names are OpenSSL subject hashes with a `.0` suffix; sort for
            // deterministic order across runs.
            let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for file in files {
                if let Ok(raw) = std::fs::read(&file) {
                    for b in split_blocks(&raw) {
                        if seen_blocks.insert(b.clone()) {
                            blocks.push(b);
                        }
                    }
                }
            }
        }
        if blocks.is_empty() {
            tls_note(Some(format!(
                "no CA certificates found in {} or {}",
                CA_DIRS[0], CA_DIRS[1]
            )));
            return;
        }

        let mut good = 0usize;
        let mut pem_failed = 0usize;
        let mut add_failed = 0usize;
        let mut samples: Vec<String> = Vec::new();
        for cert in &blocks {
            match register_cert(cert) {
                Ok(()) => good += 1,
                Err(reason) => {
                    if reason.starts_with("pem parse") {
                        pem_failed += 1;
                    } else {
                        add_failed += 1;
                    }
                    if samples.len() < 5 {
                        samples.push(format!("{}B: {reason}", cert.len()));
                    }
                }
            }
        }
        if good == 0 {
            tls_note(Some(format!(
                "every CA cert rejected ({pem_failed} pem-parse, {add_failed} store-add failures); first: {}",
                samples.first().map(String::as_str).unwrap_or("?"),
            )));
            return;
        }
        if pem_failed + add_failed > 0 {
            tls_note(Some(format!(
                "registered {good} of {} device CAs ({pem_failed} pem-parse, {add_failed} store-add failures); samples: {}",
                blocks.len(),
                samples.join(" | "),
            )));
        } else {
            tls_note(None);
        }
    });
}

/// Split a store file into individual PEM certificate blocks, dropping any
/// preamble (Android cacert files embed an OpenSSL text dump before the
/// PEM data).
#[cfg(any(target_os = "android", test))]
fn split_blocks(raw: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(PEM_BEGIN) {
        let Some(end_rel) = rest[start..].find(PEM_END) else {
            break;
        };
        let end = start + end_rel + PEM_END.len();
        out.push(rest[start..end].as_bytes().to_vec());
        rest = &rest[end..];
    }
    out
}

#[cfg(test)]
mod split_blocks_tests {
    use super::*;

    // Regression: Android cacert `.0` files embed an OpenSSL text dump
    // before the PEM block. Raw concatenation of that preamble broke
    // SSL_CTX_load_verify_locations (x509 "BIO lib") on device.
    #[test]
    fn strips_text_dump_preamble() {
        let raw = b"Certificate:\n    Data:\n        Version: 3 (0x2)\n-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
        let blocks = split_blocks(raw);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            &blocks[0],
            b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn splits_multiple_certs_in_one_file() {
        let raw = b"dump\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let blocks = split_blocks(raw);
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            &blocks[0],
            b"-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            &blocks[1],
            b"-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn strips_interstitial_text_between_certs() {
        let raw = b"dump1\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\nOpenSSL text dump 2\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let blocks = split_blocks(raw);
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            &blocks[0],
            b"-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            &blocks[1],
            b"-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
        );
    }

    // A BEGIN marker without its END must not yield a truncated block that
    // would fail OpenSSL's parser and (pre-fix) poison the whole bundle.
    #[test]
    fn skips_truncated_block_without_end_marker() {
        let raw = b"dump\n-----BEGIN CERTIFICATE-----\nQUJD\n";
        assert!(split_blocks(raw).is_empty());
    }

    #[test]
    fn no_pem_yields_no_blocks() {
        assert!(split_blocks(b"just a text dump\nno markers here\n").is_empty());
        assert!(split_blocks(b"").is_empty());
    }

    #[test]
    fn handles_crlf_line_endings() {
        let raw = b"dump\r\n-----BEGIN CERTIFICATE-----\r\nQUJD\r\n-----END CERTIFICATE-----\r\n";
        let blocks = split_blocks(raw);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            &blocks[0],
            b"-----BEGIN CERTIFICATE-----\r\nQUJD\r\n-----END CERTIFICATE-----"
        );
    }
}
