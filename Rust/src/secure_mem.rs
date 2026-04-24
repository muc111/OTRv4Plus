// src/secure_mem.rs — Deterministic zeroization for all secret key material
//
// Every struct that holds key bytes MUST derive ZeroizeOnDrop.
// Use SecretBytes<N> for fixed-size keys, SecretVec for variable-length.
// Never clone secret material — the Clone impl is deliberately omitted.

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Fixed-size secret buffer ─────────────────────────────────────────────────
/// A fixed-size buffer that is zeroized when dropped.
/// Use for: root keys, chain keys, brace keys, message keys (32 bytes),
/// nonces (12 bytes), MAC keys (64 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() != N {
            return None;
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(src);
        Some(Self(arr))
    }

    #[inline(always)]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    #[inline(always)]
    pub fn expose_slice(&self) -> &[u8] {
        &self.0
    }
}

// No Clone, no Debug (in release), no Display
#[cfg(debug_assertions)]
impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes<{N}>[REDACTED]")
    }
}

// ── Variable-size secret buffer ──────────────────────────────────────────────
/// A heap-allocated secret buffer zeroized on drop.
/// Use for: private keys of variable size, SMP secrets, passwords.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    pub fn from_slice(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    #[inline(always)]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec(len={})[REDACTED]", self.0.len())
    }
}

// ── Session key bundle ───────────────────────────────────────────────────────
/// All session keys derived from a completed DAKE handshake.
/// Passed directly into RustDoubleRatchet::new_from_dake() — never exposed to Python.
#[derive(ZeroizeOnDrop)]
pub struct DakeSessionKeys {
    pub root_key:        SecretBytes<64>,
    pub chain_key_send:  SecretBytes<64>,
    pub chain_key_recv:  SecretBytes<64>,
    pub brace_key:       SecretBytes<32>,
    pub ssid:            SecretBytes<8>,
    pub extra_sym_key:   SecretBytes<32>,
}

// ── Message key ──────────────────────────────────────────────────────────────
/// Single-use AES-256-GCM key derived per message from the chain key.
/// Zeroized immediately after use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    pub key:   SecretBytes<32>,
    pub nonce: SecretBytes<12>, // AES-GCM nonce pre-derived from counter
}

// ── DAKE ephemeral key pair ──────────────────────────────────────────────────
/// X448 ephemeral DH key pair — private key zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct EphemeralX448 {
    pub private_key: SecretBytes<56>,
    pub public_key:  [u8; 56],  // public half is not secret
}

// ── Ed448 identity key pair ──────────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct Ed448IdentityKey {
    pub private_key: SecretBytes<57>,
    pub public_key:  [u8; 57],
}

// ── SMP secret material ──────────────────────────────────────────────────────
/// Holds the user's SMP passphrase and all ZKP exponents.
/// Every field is a SecretVec so they're wiped the moment SMP completes/aborts.
#[derive(ZeroizeOnDrop)]
pub struct SmpSecrets {
    pub secret:  SecretVec,      // raw passphrase bytes
    pub a2:      SecretVec,      // ZKP exponents (arbitrary-precision)
    pub a3:      SecretVec,
    pub r2:      SecretVec,
    pub r3:      SecretVec,
    pub r4:      SecretVec,
    pub r5:      SecretVec,
    pub r6:      SecretVec,
    pub pa:      SecretVec,      // intermediate values
    pub qa:      SecretVec,
}

impl SmpSecrets {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: SecretVec::from_slice(secret),
            a2: SecretVec::new(vec![]),
            a3: SecretVec::new(vec![]),
            r2: SecretVec::new(vec![]),
            r3: SecretVec::new(vec![]),
            r4: SecretVec::new(vec![]),
            r5: SecretVec::new(vec![]),
            r6: SecretVec::new(vec![]),
            pa: SecretVec::new(vec![]),
            qa: SecretVec::new(vec![]),
        }
    }
}

// ── Constant-time byte comparison ────────────────────────────────────────────
/// Always runs in constant time regardless of where the first difference is.
/// Uses the `subtle` crate's ConstantTimeEq under the hood.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
