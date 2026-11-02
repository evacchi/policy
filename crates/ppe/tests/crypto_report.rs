// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `compiled_crypto` across the feature selections a FIPS startup check
//! cares about.
//!
//! Workspace feature unification can enable builtins through other members,
//! so the facade report is checked against the builtins crate's own report.
//! The isolated API-key-only case is gated on that exact feature combination.

use praxis_policy::CryptoSource;

#[test]
fn engine_digests_use_the_selected_provider() {
    let crypto = praxis_policy::compiled_crypto();
    #[cfg(feature = "fips-crypto")]
    assert!(
        crypto
            .iter()
            .any(|dep| dep.name == "openssl" && dep.source == CryptoSource::SystemOpenssl),
        "FIPS-selected engine hashes use platform OpenSSL: {crypto:?}",
    );
    #[cfg(not(feature = "fips-crypto"))]
    assert!(
        crypto
            .iter()
            .any(|dep| dep.name == "sha2" && dep.source == CryptoSource::Bundled),
        "normal engine hashes use RustCrypto SHA-256: {crypto:?}",
    );
}

#[test]
fn facade_report_includes_the_builtin_crates_unified_features() {
    let crypto = praxis_policy::compiled_crypto();
    let builtins = praxis_policy_builtins::compiled_crypto();

    for builtin in builtins {
        assert!(
            crypto.iter().any(|dep| {
                dep.name == builtin.name
                    && dep.source == builtin.source
                    && dep.used_by == builtin.used_by
            }),
            "the facade report omits builtin crypto {builtin:?}: {crypto:?}",
        );
    }
}

#[cfg(feature = "api-key")]
#[test]
fn builtin_reports_are_aggregated() {
    let crypto = praxis_policy::compiled_crypto();
    assert!(
        crypto
            .iter()
            .any(|dep| dep.used_by.starts_with("praxis-policy-builtins")),
        "the builtins crate's own report reaches the facade: {crypto:?}",
    );
}

#[cfg(all(
    feature = "api-key",
    not(any(
        feature = "jwt",
        feature = "oauth",
        feature = "delegator-vault",
        feature = "valkey",
        feature = "http-hyper"
    ))
))]
#[test]
fn normal_api_key_reports_bundled_sha2() {
    let crypto = praxis_policy::compiled_crypto();
    assert!(
        crypto
            .iter()
            .any(|dep| dep.name == "sha2" && dep.used_by.contains("api-key")),
        "the normal API-key selection uses RustCrypto SHA-256: {crypto:?}",
    );
}

#[cfg(all(
    feature = "api-key-fips",
    not(feature = "crypto-sha2"),
    not(any(
        feature = "api-key",
        feature = "jwt",
        feature = "oauth",
        feature = "delegator-vault",
        feature = "valkey",
        feature = "http-hyper"
    ))
))]
#[test]
fn fips_api_key_selection_reports_only_system_crypto() {
    let crypto = praxis_policy::compiled_crypto();
    assert!(
        crypto
            .iter()
            .all(|dep| dep.source == CryptoSource::SystemOpenssl),
        "API-key support must be selectable without bundled crypto: {crypto:?}",
    );
}
