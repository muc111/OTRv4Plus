#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub mod error;
pub mod secure_mem;
pub mod kdf;
#[cfg(feature = "pq-rust")]
pub mod dake;
#[cfg(feature = "pq-rust")]
pub mod smp;

#[pyfunction]
fn rust_kdf_1<'py>(py: Python<'py>, usage_id: u8, value: &[u8], output_len: usize) -> Bound<'py, PyBytes> {
    let out = kdf::kdf_1(usage_id, value, output_len);
    PyBytes::new_bound(py, &out)
}

#[pyfunction]
fn rust_fingerprint<'py>(py: Python<'py>, pub_key_bytes: &[u8]) -> Bound<'py, PyBytes> {
    let fp = kdf::fingerprint_sha3_512(pub_key_bytes);
    PyBytes::new_bound(py, &fp)
}

#[pyfunction]
fn rust_hmac_sha3_512<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    let mac = kdf::hmac_sha3_512(key, data);
    PyBytes::new_bound(py, &mac)
}

#[pyfunction]
fn rust_ct_eq(a: &[u8], b: &[u8]) -> bool {
    secure_mem::ct_eq(a, b)
}

#[pyfunction]
fn rust_derive_ratchet_keys<'py>(
    py: Python<'py>,
    root_key: &[u8],
    shared_secret: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let root_arr: &[u8; 64] = root_key.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("root_key must be 64 bytes"))?;
    let (new_root, new_chain) = kdf::derive_ratchet_keys(root_arr, shared_secret);
    Ok((
        PyBytes::new_bound(py, new_root.expose_slice()),
        PyBytes::new_bound(py, new_chain.expose_slice()),
    ))
}

#[pymodule]
fn otrv4_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "pq-rust")]
    m.add_class::<dake::PyDake>()?;
    #[cfg(feature = "pq-rust")]
    m.add_class::<smp::PySmp>()?;

    m.add_function(wrap_pyfunction_bound!(rust_kdf_1, m)?)?;
    m.add_function(wrap_pyfunction_bound!(rust_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction_bound!(rust_hmac_sha3_512, m)?)?;
    m.add_function(wrap_pyfunction_bound!(rust_ct_eq, m)?)?;
    m.add_function(wrap_pyfunction_bound!(rust_derive_ratchet_keys, m)?)?;

    m.add("__version__", "0.5.0")?;
    Ok(())
}