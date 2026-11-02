// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! X448 (RFC 7748) for the core: the DAKE, the double ratchet's DH keys
//! (key_handles), identity keys and the voice key exchange.
//!
//! On `ed448-goldilocks-plus` (its `x448` module), the maintained crate the
//! core's Ed448 already uses. It replaced `x448 0.6` / `ed448-goldilocks 0.7`
//! (2020, unmaintained, no zeroization). Its secrets and shared secrets are
//! ZeroizeOnDrop. RFC 7748 is a fixed function, so every result is the same
//! bytes as before; the tests below pin it to the RFC's vectors.
//!
//! A peer key that is one of the low-order points is refused, as the old
//! crate refused it, and so is an all-zero (non-contributory) result: RFC
//! 7748 §6.2 says to abort rather than use it.

use ed448_goldilocks_plus::{x448 as rfc, MontgomeryPoint};
use zeroize::Zeroizing;

pub(crate) const X448_LEN: usize = 56;

/// The public key of a 56-byte private key (clamped as RFC 7748 says).
pub(crate) fn public_key(sk: &[u8; X448_LEN]) -> [u8; X448_LEN] {
    rfc::PublicKey::from(&rfc::StaticSecret::from(*sk)).to_bytes()
}

/// Whether `pk` is one of the low-order points (refused as a peer key).
pub(crate) fn is_low_order(pk: &[u8; X448_LEN]) -> bool {
    MontgomeryPoint(*pk).is_low_order()
}

/// X448(sk, pk). `None` for a low-order `pk` or an all-zero result.
pub(crate) fn diffie_hellman(sk: &[u8; X448_LEN], pk: &[u8; X448_LEN])
    -> Option<Zeroizing<[u8; X448_LEN]>>
{
    if is_low_order(pk) {
        return None;
    }
    let shared = rfc::StaticSecret::from(*sk).diffie_hellman(&rfc::PublicKey::from(*pk));
    if !shared.was_contributory() {
        return None;
    }
    Some(Zeroizing::new(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; X448_LEN] {
        // `(0..len).step_by(2)` is std's StepBy<Range<usize>>, not PyO3's
        // BoundListIterator/BoundTupleIterator: no Python sequence, constant
        // step -> GHSA-36hh-v3qg-5jq4 is not reachable here (see SECURITY.md).
        let v: Vec<u8> = (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    /// RFC 7748 §5.2: X448(k, u) for the two given (k, u).
    #[test]
    fn rfc7748_section_5_2_vectors() {
        let k = h("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        let u = h("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        assert_eq!(*diffie_hellman(&k, &u).unwrap(),
            h("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));
        let k = h("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
        let u = h("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
        assert_eq!(*diffie_hellman(&k, &u).unwrap(),
            h("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"));
    }

    /// RFC 7748 §5.2: k = u = 5, iterated; the values after 1 and 1000.
    #[test]
    fn rfc7748_section_5_2_iterated() {
        let mut k = [0u8; X448_LEN];
        k[0] = 5;
        let mut u = k;
        for i in 1..=1000 {
            let next = *diffie_hellman(&k, &u).unwrap();
            u = k;
            k = next;
            if i == 1 {
                assert_eq!(k, h("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"));
            }
        }
        assert_eq!(k, h("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"));
    }

    /// RFC 7748 §6.2: both public keys and the shared secret.
    #[test]
    fn rfc7748_section_6_2_diffie_hellman() {
        let a = h("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        let b = h("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        let (pa, pb) = (public_key(&a), public_key(&b));
        assert_eq!(pa, h("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"));
        assert_eq!(pb, h("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"));
        let k = h("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
        assert_eq!(*diffie_hellman(&a, &pb).unwrap(), k);
        assert_eq!(*diffie_hellman(&b, &pa).unwrap(), k);
    }

    /// The low-order points (u = 0, 1, p - 1) are refused as peer keys.
    #[test]
    fn low_order_peer_keys_are_refused() {
        let sk = [7u8; X448_LEN];
        // p = 2^448 - 2^224 - 1 = 2^224 (2^224 - 2) + (2^224 - 1), so p - 1
        // in little-endian is fe ff..ff (28 bytes), then fe ff..ff (28).
        let mut p_minus_1 = [0xffu8; X448_LEN];
        p_minus_1[0] = 0xfe;
        p_minus_1[28] = 0xfe;
        let mut one = [0u8; X448_LEN];
        one[0] = 1;
        for pk in [[0u8; X448_LEN], one, p_minus_1] {
            assert!(is_low_order(&pk), "{pk:02x?}");
            assert!(diffie_hellman(&sk, &pk).is_none());
        }
    }
}
