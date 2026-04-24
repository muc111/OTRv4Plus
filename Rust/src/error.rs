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