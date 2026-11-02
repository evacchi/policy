// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compiled-crypto reporting for this crate.
//!
//! See `praxis_policy_core::crypto` for why the crate that owns a dependency
//! edge is the one that reports it.

use praxis_policy_core::crypto::CryptoDependency;

/// The crypto this crate compiled with.
///
/// Reports the provider selected for session ids and decision-cache keys.
///
/// # Examples
///
/// ```
/// let crypto = praxis_policy_apl_runtime::compiled_crypto();
/// assert!(crypto.iter().any(|dep| dep.name == "sha2" || dep.name == "openssl"));
/// ```
pub fn compiled_crypto() -> Vec<CryptoDependency> {
    let mut crypto = Vec::new();
    #[cfg(feature = "crypto-sha2")]
    crypto.push(CryptoDependency::bundled(
        "sha2",
        "praxis-policy-apl-runtime: session ids, decision cache keys",
    ));
    #[cfg(feature = "fips-crypto")]
    crypto.push(CryptoDependency::system_openssl(
        "openssl",
        "praxis-policy-apl-runtime: session ids, decision cache keys",
    ));
    crypto
}
