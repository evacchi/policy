// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compiled-crypto reporting for this crate.
//!
//! See `praxis_policy_core::crypto` for why the crate that owns a dependency
//! edge is the one that reports it.

use praxis_policy_core::crypto::CryptoDependency;

/// The crypto this crate compiled with.
///
/// Unconditional: session ids and decision-cache keys hash through the
/// platform OpenSSL in every build of this crate, and no feature removes
/// that edge.
///
/// # Examples
///
/// ```
/// let crypto = praxis_policy_apl_runtime::compiled_crypto();
/// assert!(crypto.iter().any(|dep| dep.name == "openssl"));
/// ```
pub fn compiled_crypto() -> Vec<CryptoDependency> {
    vec![CryptoDependency::system_openssl(
        "openssl",
        "praxis-policy-apl-runtime: session ids, decision cache keys",
    )]
}
