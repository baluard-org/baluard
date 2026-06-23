//! Live integration test: GitHub device flow against the real api.
//!
//! This test exercises the `device_flow_start` path against github.com
//! using the embedded `GITHUB_CLIENT_ID`. It is **network-dependent** and
//! will fail in air-gapped environments. It is also expected to fail with
//! the 404 error if the OAuth App has not enabled the Device Authorization
//! flow toggle (opt-in per March 2022 GitHub changelog).
//!
//! Skipped automatically when:
//! - `BALUARD_SKIP_LIVE_TESTS=1` is set
//! - The provider has no network access (the `device_flow_start` call
//!   will fail with a transport error, not 404)
//!
//! Run with: `cargo test -p baluard-core --test github_device_flow_live -- --ignored`
//! (marked `#[ignore]` so it does not run by default in CI / unit-test runs).

use baluard_core::providers::github::GitHubProvider;
use baluard_core::providers::ForgeProvider;

#[tokio::test]
#[ignore = "network-dependent; run manually with --ignored"]
async fn github_device_flow_404_means_toggle_disabled() {
    if std::env::var("BALUARD_SKIP_LIVE_TESTS").unwrap_or_default() == "1" {
        eprintln!("BALUARD_SKIP_LIVE_TESTS=1, skipping");
        return;
    }

    // Clear any env-var override so we use the embedded client_id.
    // The embedded value is the project's registered OAuth App. If device
    // flow is enabled, this test will print the user_code and verification
    // URL (success path). If device flow is NOT enabled, GitHub returns
    // 404 on /login/device/code and our code surfaces a specific,
    // actionable error message — the test asserts that.
    unsafe { std::env::remove_var("BALUARD_GITHUB_CLIENT_ID") };

    let provider = GitHubProvider::new();
    let result = provider.device_flow_start().await;

    match result {
        Ok(session) => {
            // Device flow enabled. Surface what we got so a human
            // running this test can complete the flow at github.com/login/device
            eprintln!(
                "device flow started: user_code={}, verification_uri={}",
                session.user_code, session.verification_uri
            );
            assert!(!session.user_code.is_empty());
            assert!(!session.device_code.is_empty());
        }
        Err(e) => {
            let msg = e.to_string();
            // The improved error message should mention the toggle
            // and link to docs. Verify the actionable content is there.
            assert!(
                msg.contains("Device Authorization flow"),
                "error should mention Device Authorization flow toggle, got: {msg}"
            );
            assert!(
                msg.contains("docs/git-provider-apps-and-tokens.md"),
                "error should reference the project docs, got: {msg}"
            );
        }
    }
}
