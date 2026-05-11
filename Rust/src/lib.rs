#![forbid(unsafe_code)]

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
    m.add_class::<dake::PyDake>()?;
    m.add_class::<dake::Dakeresult>()?;
    m.add_class::<smp::PySmp>()?;
    m.add_class::<smp_vault::PySMPVault>()?;
    m.add_class::<ratchet::RustDoubleRatchet>()?;
    Ok(())
}
