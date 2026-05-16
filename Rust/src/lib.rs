//! OTRv4+ cryptographic core — Rust/PyO3.
//!
//! All features (DAKE, SMP, double ratchet, ring signature) are
//! unconditionally compiled.  The `pq-rust` Cargo feature is retained
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
    // Ring signature (Phase 5.3c, v10.6.9)
    m.add_function(wrap_pyfunction!(ring_sig::py_ring_sign,   m)?)?;
    m.add_function(wrap_pyfunction!(ring_sig::py_ring_verify, m)?)?;

    Ok(())
}
