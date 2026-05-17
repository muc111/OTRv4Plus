//! OTRv4+ cryptographic core — Rust/PyO3.
//!
//! All features (DAKE, SMP, double ratchet, ring signature, key handles)
//! are unconditionally compiled.  The `pq-rust` Cargo feature is retained
//! for downstream crates that want to opt-in; it is listed in
//! `[features] default` so ordinary builds include everything without
//! an explicit `--features` flag.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

pub mod error;
pub mod secure_mem;
pub mod kdf;
pub mod header;
pub mod dake;
pub mod smp;
pub mod smp_vault;
pub mod ratchet;
pub mod ring_sig;
pub mod key_handles;
pub mod test_vectors;     // v10.6.17: RFC 8032 Ed448 test vectors (Phase 5.3f-narrow)

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

#[pymodule]
fn otrv4_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // DAKE
    m.add_class::<dake::PyDake>()?;
    // SMP
    m.add_class::<smp::PySmp>()?;
    m.add_class::<smp_vault::PySMPVault>()?;
    // Ratchet
    m.add_class::<ratchet::RustDoubleRatchet>()?;
    // Ring signature (Phase 5.3c)
    m.add_function(wrap_pyfunction!(ring_sig::py_ring_sign,   m)?)?;
    m.add_function(wrap_pyfunction!(ring_sig::py_ring_verify, m)?)?;
    // Phase 5.3e (v10.6.12): Rust-owned long-term identity key handles
    m.add_class::<key_handles::Ed448KeyHandle>()?;
    m.add_class::<key_handles::X448KeyHandle>()?;
    m.add_function(wrap_pyfunction!(key_handles::generate_ed448_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(key_handles::generate_x448_keypair,  m)?)?;

    Ok(())
}
