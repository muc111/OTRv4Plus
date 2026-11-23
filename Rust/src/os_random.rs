// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Random bytes from the operating system, and nothing else.
//!
//! Every key, nonce, salt and secret exponent in this crate comes from here.
//! There is one source on purpose: the OS CSPRNG (`getrandom(2)` on Linux
//! and Android), with no user-space generator in between that could be
//! seeded badly, forked, or left in a snapshot.
//!
//! [`fill`] panics if the OS cannot supply randomness. That is the behaviour
//! the crate had with `rand::rngs::OsRng::fill_bytes`, and it is the right
//! one: there is no safe fallback for a key. Callers that can report an
//! error instead use [`try_fill`].
//!
//! Non-secret randomness (the voice masks' pitch and formant draws) uses a
//! seeded `StdRng` whose seed comes from [`fill`].

/// Fill `buf` from the OS CSPRNG. Panics if the OS has none to give.
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("the operating system's random number generator failed");
}

/// Fill `buf` from the OS CSPRNG, or say that it could not.
pub fn try_fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buf)
}

/// An array of `N` random bytes.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// A random `u64`.
pub fn u64() -> u64 {
    u64::from_le_bytes(bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        assert_ne!(bytes::<32>(), bytes::<32>());
        assert_ne!(u64(), u64());
    }

    #[test]
    fn fill_writes_every_byte() {
        // A 4 KiB buffer left at zero anywhere would mean a short write.
        let mut buf = vec![0u8; 4096];
        fill(&mut buf);
        let zeros = buf.iter().filter(|&&b| b == 0).count();
        assert!(zeros < 64, "{zeros} zero bytes in 4096");
    }

    #[test]
    fn try_fill_succeeds() {
        let mut buf = [0u8; 16];
        assert!(try_fill(&mut buf).is_ok());
    }
}
