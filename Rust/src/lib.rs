//! OTRv4+ cryptographic core — Rust/PyO3.
//!
//! All features (DAKE, SMP, double ratchet) are unconditionally compiled.
//! The `pq-rust` Cargo feature is retained for downstream crates that want
//! to opt-in; it is listed in `[features] default` so ordinary builds include
//! everything without an explicit `--features` flag.
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

use pyo3::prelude::*;

#[pymodule]
fn otrv4_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // DAKE
    m.add_class::<dake::PyDake>()?;
    // SMP
    m.add_class::<smp::PySmp>()?;
    m.add_class::<smp_vault::PySMPVault>()?;
    // Ratchet
    m.add_class::<ratchet::RustDoubleRatchet>()?;

    Ok(())
}
