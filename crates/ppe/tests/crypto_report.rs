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
fn engine_digests_use_system_openssl() {
    let crypto = praxis_policy::compiled_crypto();
    assert!(
        crypto
            .iter()
            .any(|dep| dep.name == "openssl" && dep.source == CryptoSource::SystemOpenssl),
        "the engine hashes session ids through the platform OpenSSL: {crypto:?}",
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
fn api_key_only_reports_no_bundled_crypto() {
    let crypto = praxis_policy::compiled_crypto();
    assert!(
        crypto
            .iter()
            .all(|dep| dep.source == CryptoSource::SystemOpenssl),
        "API-key support must be selectable without bundled crypto: {crypto:?}",
    );
}
