// src/error.rs — Unified error type for otrv4_core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OtrError {
    #[error("DAKE state machine: {0}")]
    Dake(&'static str),

    #[error("Double ratchet: {0}")]
    Ratchet(&'static str),

    #[error("SMP protocol: {0}")]
    Smp(&'static str),

    #[error("AES-GCM authentication failed")]
    AeadDecrypt,

    #[error("Ed448 signature invalid")]
    SignatureInvalid,

    #[error("ML-KEM operation failed")]
    MlKem,

    #[error("ML-DSA operation failed")]
    MlDsa,

    #[error("Key derivation failed")]
    Kdf,

    #[error("Input too short: need {need}, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("Input too long: max {max}, got {got}")]
    TooLong { max: usize, got: usize },

    #[error("Truncated wire message")]
    TruncatedMessage,

    #[error("Length prefix exceeds policy cap: {0}")]
    LengthCapExceeded(usize),

    #[error("Invalid wire format")]
    WireFormat,

    #[error("SMP value out of range")]
    SmpRange,

    #[error("Fragment: {0}")]
    Fragment(&'static str),

    #[error("Rate limit exceeded")]
    RateLimit,

    #[error("Key storage: {0}")]
    Storage(String),

    #[error("Internal assertion failed")]
    Internal,
}

pub type Result<T> = std::result::Result<T, OtrError>;

use pyo3::exceptions::PyValueError;
use pyo3::PyErr;

impl From<OtrError> for PyErr {
    fn from(e: OtrError) -> PyErr {
        PyValueError::new_err(e.to_string())
    }
}

// ── Bounded slice helper (audit V1 fix) ──────────────────────────────────────
// Replaces panicking `&data[a..b]` with `data.try_slice(a..b)?`.
pub trait SafeSlice {
    fn try_slice(&self, range: std::ops::Range<usize>) -> Result<&[u8]>;
    fn try_slice_from(&self, start: usize) -> Result<&[u8]>;
    fn try_byte(&self, idx: usize) -> Result<u8>;
}

impl SafeSlice for [u8] {
    #[inline]
    fn try_slice(&self, range: std::ops::Range<usize>) -> Result<&[u8]> {
        self.get(range).ok_or(OtrError::TruncatedMessage)
    }
    #[inline]
    fn try_slice_from(&self, start: usize) -> Result<&[u8]> {
        self.get(start..).ok_or(OtrError::TruncatedMessage)
    }
    #[inline]
    fn try_byte(&self, idx: usize) -> Result<u8> {
        self.get(idx).copied().ok_or(OtrError::TruncatedMessage)
    }
}

/// Cap for any length-prefix field on the wire (64 KiB).
pub const MAX_WIRE_FIELD_LEN: usize = 65536;

#[inline]
pub fn check_wire_length(len: usize, remaining: usize) -> Result<()> {
    if len > MAX_WIRE_FIELD_LEN {
        return Err(OtrError::LengthCapExceeded(len));
    }
    if len > remaining {
        return Err(OtrError::TruncatedMessage);
    }
    Ok(())
}
