//! RFC 8032 Ed448 test vectors.
//!
//! v10.6.17 (Phase 5.3f-narrow): these vectors replace the Python-side
//! boot-time cross-verification of Rust `ed448-goldilocks-plus` against
//! the C extension and the Python cryptography library.
//!
//! ## Build-time guarantee
//!
//! Run before any release:
//!
//! ```bash
//! cargo test --release --no-default-features --features pq-rust
//! ```
//!
//! If the test fails, the Rust Ed448 implementation has diverged from
//! RFC 8032 and the build is **not safe to ship**.  The previous boot
//! mechanism ran this check at every program start against the cryptography
//! library as ground-truth.  Now the ground-truth is the RFC document
//! itself, and the check is a one-time build-time gate rather than a
//! per-startup cost.
//!
//! ## Source
//!
//! RFC 8032 §7.4 "Test Vectors for Ed448":
//!   <https://www.rfc-editor.org/rfc/rfc8032#section-7.4>
//!
//! Currently includes the "Blank" test vector (empty message).  Additional
//! vectors from §7.4 can be appended to `RFC8032_VECTORS` as needed.

/// A single RFC 8032 Ed448 test vector.
///
/// - `seed`: 57-byte Ed448 private key seed
/// - `message`: bytes to be signed
/// - `signature`: expected 114-byte Ed448 signature
pub struct Rfc8032Vector {
    pub seed:      &'static [u8; 57],
    pub message:   &'static [u8],
    pub signature: &'static [u8; 114],
}

/// Ed448 "Blank" vector from RFC 8032 §7.4.
///
/// Empty message.  Seed and signature taken verbatim from the RFC.
pub const VECTOR_BLANK: Rfc8032Vector = Rfc8032Vector {
    seed: &[
        0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
        0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
        0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
        0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
        0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
        0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
        0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
        0x5b,
    ],
    message: b"",
    signature: &[
        0x53, 0x3a, 0x37, 0xf6, 0xbb, 0xe4, 0x57, 0x25,
        0x1f, 0x02, 0x3c, 0x0d, 0x88, 0xf9, 0x76, 0xae,
        0x2d, 0xfb, 0x50, 0x4a, 0x84, 0x3e, 0x34, 0xd2,
        0x07, 0x4f, 0xd8, 0x23, 0xd4, 0x1a, 0x59, 0x1f,
        0x2b, 0x23, 0x3f, 0x03, 0x4f, 0x62, 0x82, 0x81,
        0xf2, 0xfd, 0x7a, 0x22, 0xdd, 0xd4, 0x7d, 0x78,
        0x28, 0xc5, 0x9b, 0xd0, 0xa2, 0x1b, 0xfd, 0x39,
        0x80, 0xff, 0x0d, 0x20, 0x28, 0xd4, 0xb1, 0x8a,
        0x9d, 0xf6, 0x3e, 0x00, 0x6c, 0x5d, 0x1c, 0x2d,
        0x34, 0x5b, 0x92, 0x5d, 0x8d, 0xc0, 0x0b, 0x41,
        0x04, 0x85, 0x2d, 0xb9, 0x9a, 0xc5, 0xc7, 0xcd,
        0xda, 0x85, 0x30, 0xa1, 0x13, 0xa0, 0xf4, 0xdb,
        0xb6, 0x11, 0x49, 0xf0, 0x5a, 0x73, 0x63, 0x26,
        0x8c, 0x71, 0xd9, 0x58, 0x08, 0xff, 0x2e, 0x65,
        0x26, 0x00,
    ],
};

/// All published RFC 8032 vectors covered by this build.
pub const RFC8032_VECTORS: &[&Rfc8032Vector] = &[
    &VECTOR_BLANK,
];

#[cfg(test)]
mod tests {
    use super::*;
    use ed448_goldilocks_plus::SigningKey;
    use core::convert::TryFrom;

    /// Verify each RFC 8032 vector signs to the expected byte sequence.
    ///
    /// If this test fails, the Rust Ed448 implementation has drifted
    /// from RFC 8032.  Do not ship a build that fails this test.
    ///
    /// Uses the inherent `sign_ctx(context, message)` method with an
    /// empty context for RFC 8032 §5.2 pure Ed448.  This avoids the need
    /// to bring the `signature::Signer` trait into scope (the trait's
    /// origin crate is not a direct dependency of `otrv4_core`).
    #[test]
    fn ed448_rfc8032_vectors_byte_exact() {
        for (idx, v) in RFC8032_VECTORS.iter().enumerate() {
            let sk = SigningKey::try_from(v.seed.as_slice())
                .unwrap_or_else(|_| panic!(
                    "RFC 8032 vector {}: SigningKey::try_from(seed) failed", idx));

            let sig = sk.sign_ctx(b"", v.message)
                .unwrap_or_else(|_| panic!(
                    "RFC 8032 vector {}: sign_ctx returned Err", idx));
            let sig_bytes: [u8; 114] = sig.to_bytes();

            assert_eq!(
                sig_bytes.as_slice(),
                v.signature.as_slice(),
                "RFC 8032 vector {} signature mismatch.\n  \
                 Rust ed448-goldilocks-plus has drifted from RFC 8032.\n  \
                 DO NOT SHIP THIS BUILD.\n  \
                 expected: {}\n  \
                 got:      {}",
                idx,
                hex(v.signature),
                hex(&sig_bytes),
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
