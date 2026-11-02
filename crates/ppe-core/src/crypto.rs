// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What crypto a compiled policy build contains.
//!
//! A host that must run under a FIPS-mode enforcement (an environment variable
//! like a `PRAXIS_REQUIRE_FIPS`, a compliance regime, or an image policy) needs
//! to know whether the policy engine it linked against compiled crypto into
//! the binary. The answer is a property of the resolved dependency graph, not
//! of any one crate's requested features: Cargo unifies features across every
//! consumer, so a build can carry the JWT backend because some unrelated
//! workspace member asked for it.
//!
//! The crates that own a crypto dependency therefore report it themselves,
//! gated on their own compiled features, and the host aggregates those reports
//! through [`crate::engine`] consumers such as the `praxis-policy` facade.
//! A report is evidence about what was compiled, which is why it lives with
//! the dependency rather than with the feature that requested it.

/// Where a crypto dependency's implementation comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSource {
    /// The platform OpenSSL, dynamically linked. The implementation lives in
    /// a system library the host and its operator control, so a FIPS-mode
    /// OpenSSL on the host is the crypto that actually runs.
    SystemOpenssl,
    /// Crypto compiled into the policy binary: the `RustCrypto` crates
    /// (`sha2`, `hmac`, ...), `ring`, `aws-lc-rs`, or a vendored OpenSSL.
    /// Present in the binary regardless of what the host's OpenSSL is
    /// configured to do, so a FIPS-mode host cannot vouch for it.
    Bundled,
}

/// One crypto dependency in the compiled graph.
///
/// Built by the crate that owns the dependency edge; see the module docs for
/// why that crate, and not the feature requester, is the reporter.
#[derive(Debug, Clone, Copy)]
pub struct CryptoDependency {
    /// The dependency's crate name, as it appears in the graph: `openssl`,
    /// `sha2`, `jsonwebtoken`.
    pub name: &'static str,
    /// Where the implementation comes from.
    pub source: CryptoSource,
    /// What compiled it in, for diagnostics: the owning crate and the use,
    /// for example `praxis-policy-builtins api-key: credential digests`.
    pub used_by: &'static str,
}

impl CryptoDependency {
    /// A dynamically linked platform OpenSSL dependency.
    ///
    /// # Examples
    ///
    /// ```
    /// use praxis_policy_core::crypto::{CryptoDependency, CryptoSource};
    ///
    /// let dep = CryptoDependency::system_openssl("openssl", "example: digests");
    /// assert_eq!(dep.source, CryptoSource::SystemOpenssl);
    /// ```
    pub const fn system_openssl(name: &'static str, used_by: &'static str) -> Self {
        Self {
            name,
            source: CryptoSource::SystemOpenssl,
            used_by,
        }
    }

    /// A dependency whose crypto is compiled into the binary.
    ///
    /// # Examples
    ///
    /// ```
    /// use praxis_policy_core::crypto::{CryptoDependency, CryptoSource};
    ///
    /// let dep = CryptoDependency::bundled("sha2", "example: cache keys");
    /// assert_eq!(dep.source, CryptoSource::Bundled);
    /// ```
    pub const fn bundled(name: &'static str, used_by: &'static str) -> Self {
        Self {
            name,
            source: CryptoSource::Bundled,
            used_by,
        }
    }
}

/// The crypto this crate compiled with.
///
/// Unconditional: payload provenance digests and the instruction digests
/// the CMF bridge takes from here hash through the platform OpenSSL in
/// every build.
///
/// # Examples
///
/// ```
/// let crypto = praxis_policy_core::crypto::compiled_crypto();
/// assert!(crypto.iter().all(|dep| dep.name == "openssl"));
/// ```
pub fn compiled_crypto() -> Vec<CryptoDependency> {
    vec![CryptoDependency::system_openssl(
        "openssl",
        "praxis-policy-core: payload provenance and instruction digests",
    )]
}

/// SHA-256 of `bytes`, via the platform OpenSSL.
///
/// Same digest the previous `RustCrypto` implementation produced, so
/// digests recorded by an older build (audit provenance, instruction pins)
/// keep comparing equal.
///
/// # Errors
///
/// When the system OpenSSL cannot hash, naming the failure. Callers that
/// can fail closed should; callers writing an optional audit or pin field
/// may omit it, but never substitute a different value.
pub fn sha256(bytes: &[u8]) -> Result<[u8; 32], String> {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), bytes)
        .map_err(|e| format!("system OpenSSL SHA-256 failed: {e}"))?;
    digest
        .as_ref()
        .try_into()
        .map_err(|error: std::array::TryFromSliceError| {
            format!("system OpenSSL returned a SHA-256 digest that is not 32 bytes: {error}")
        })
}

/// HMAC-SHA256 of `data` under `key`, via the platform OpenSSL.
///
/// Same bytes the previous `RustCrypto` implementation produced.
///
/// # Errors
///
/// When the system OpenSSL cannot initialize or run the MAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let pkey =
        openssl::pkey::PKey::hmac(key).map_err(|e| format!("system OpenSSL HMAC failed: {e}"))?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .map_err(|e| format!("system OpenSSL HMAC failed: {e}"))?;
    signer
        .update(data)
        .map_err(|e| format!("system OpenSSL HMAC failed: {e}"))?;
    signer
        .sign_to_vec()
        .map_err(|e| format!("system OpenSSL HMAC failed: {e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_the_source() {
        assert_eq!(
            CryptoDependency::system_openssl("openssl", "u").source,
            CryptoSource::SystemOpenssl,
        );
        assert_eq!(
            CryptoDependency::bundled("sha2", "u").source,
            CryptoSource::Bundled,
        );
    }

    #[test]
    fn sha256_matches_the_reference_vectors() {
        // sha256("abc") — the FIPS 180-4 test vector. Pins the digest the
        // previous `RustCrypto` implementation produced so values recorded by
        // an older build keep comparing equal.
        assert_eq!(
            sha256(b"abc").expect("digest"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ],
        );
    }

    #[test]
    fn hmac_sha256_matches_the_rfc_4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").expect("mac"),
            vec![
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ],
        );
    }
}
