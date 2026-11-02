// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compiled-crypto reporting for this crate.
//!
//! See `praxis_policy_core::crypto` for why the crate that owns a dependency
//! edge is the one that reports it. Each entry below is gated on this crate's
//! own compiled features, so the report reflects feature unification across
//! the whole graph — a builtin enabled through another consumer's dependency
//! edge is reported here all the same.

use praxis_policy_core::crypto::CryptoDependency;

/// The crypto this crate compiled with.
///
/// Empty in the default build: no feature, no crypto.
///
/// # Examples
///
/// ```
/// let crypto = praxis_policy_builtins::compiled_crypto();
/// // With no builtin features enabled, nothing is reported.
/// # #[cfg(not(any(feature = "jwt", feature = "api-key", feature = "oauth", feature = "delegator-vault", feature = "valkey")))]
/// assert!(crypto.is_empty());
/// ```
pub fn compiled_crypto() -> Vec<CryptoDependency> {
    // Every push below is feature-gated, so a build with none of those
    // features never mutates the binding. The list mirrors the push gates;
    // a stale entry here only over-allows, never hides a dependency.
    #[cfg_attr(
        not(any(
            feature = "api-key",
            feature = "jwt",
            feature = "oauth",
            feature = "delegator-vault",
            feature = "valkey"
        )),
        allow(unused_mut)
    )]
    let mut crypto = Vec::new();
    // One `push` per feature rather than a macro over a table: each is gated on
    // a different predicate, and a table would hide that behind one more
    // indirection to check.
    #[cfg(feature = "api-key")]
    crypto.push(CryptoDependency::system_openssl(
        "openssl",
        "praxis-policy-builtins api-key: credential digests",
    ));
    #[cfg(feature = "jwt")]
    {
        // The token backend, whatever crypto it settled on (jsonwebtoken has
        // changed backends across releases); compiled in either way.
        crypto.push(CryptoDependency::bundled(
            "jsonwebtoken",
            "praxis-policy-builtins jwt: token validation",
        ));
        crypto.push(CryptoDependency::bundled(
            "sha2",
            "praxis-policy-builtins jwt: DPoP key thumbprints",
        ));
    }
    #[cfg(feature = "oauth")]
    {
        crypto.push(CryptoDependency::bundled(
            "hmac",
            "praxis-policy-builtins oauth: cache-key derivation",
        ));
        crypto.push(CryptoDependency::bundled(
            "sha2",
            "praxis-policy-builtins oauth: cache-key derivation",
        ));
    }
    #[cfg(feature = "delegator-vault")]
    crypto.push(CryptoDependency::bundled(
        "sha2",
        "praxis-policy-builtins delegator-vault: cache keys",
    ));
    #[cfg(feature = "valkey")]
    crypto.push(CryptoDependency::bundled(
        "sha2",
        "praxis-policy-builtins valkey: session key derivation",
    ));
    crypto
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "api-key")]
    use praxis_policy_core::crypto::CryptoSource;

    /// Whatever is reported names its dependency, its user, and a source —
    /// a host acting on this report cannot be handed an entry it cannot read.
    #[test]
    fn every_entry_is_fully_populated() {
        for dep in compiled_crypto() {
            assert!(!dep.name.is_empty(), "name is set");
            assert!(!dep.used_by.is_empty(), "used_by is set: {dep:?}");
        }
    }

    #[cfg(feature = "api-key")]
    #[test]
    fn api_key_reports_system_openssl_and_nothing_bundled() {
        let crypto = compiled_crypto();
        assert!(
            crypto
                .iter()
                .any(|dep| dep.name == "openssl" && dep.source == CryptoSource::SystemOpenssl),
            "api-key digests go through the platform OpenSSL: {crypto:?}",
        );
        assert!(
            !crypto
                .iter()
                .any(|dep| dep.name == "sha2" && dep.used_by.contains("api-key")),
            "api-key must not pull bundled sha2: {crypto:?}",
        );
    }
}
