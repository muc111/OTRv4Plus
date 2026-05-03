// src/secure_mem.rs — Deterministic zeroization for all secret key material

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Fixed-size secret buffer ──────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self { Self(bytes) }
    pub fn zeroed() -> Self { Self([0u8; N]) }

    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() != N { return None; }
        let mut arr = [0u8; N];
        arr.copy_from_slice(src);
        Some(Self(arr))
    }

    #[inline(always)] pub fn expose(&self)       -> &[u8; N] { &self.0 }
    #[inline(always)] pub fn expose_slice(&self) -> &[u8]    { &self.0 }

    pub fn replace(&mut self, src: &[u8; N]) { self.0.copy_from_slice(src); }
}

#[cfg(debug_assertions)]
impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes<{N}>[REDACTED]")
    }
}

// ── Variable-length secret buffer ────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn new(v: Vec<u8>)      -> Self { Self(v) }
    pub fn from_slice(s: &[u8]) -> Self { Self(s.to_vec()) }

    #[inline(always)] pub fn expose(&self) -> &[u8] { &self.0 }
    pub fn len(&self)      -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool  { self.0.is_empty() }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec(len={})[REDACTED]", self.0.len())
    }
}

// ── Session key bundle from DAKE ──────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct DakeSessionKeys {
    pub root_key:       SecretBytes<32>,
    pub chain_key_send: SecretBytes<32>,
    pub chain_key_recv: SecretBytes<32>,
    pub brace_key:      SecretBytes<32>,
    pub ssid:           SecretBytes<8>,
    pub extra_sym_key:  SecretBytes<32>,
}

// ── Per-message key ───────────────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    pub key:   SecretBytes<32>,
    pub nonce: SecretBytes<12>,
}

// ── DAKE ephemeral X448 key pair ──────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct EphemeralX448 {
    pub private_key: SecretBytes<56>,
    pub public_key:  [u8; 56],
}

// ── Ed448 long-term identity key pair ────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct Ed448IdentityKey {
    pub private_key: SecretBytes<57>,
    pub public_key:  [u8; 57],
}

// ── Constant-time equality ────────────────────────────────────────────────────
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() { return false; }
    a.ct_eq(b).into()
}
