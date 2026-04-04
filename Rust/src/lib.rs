/// OTRv4+ Double Ratchet Core
///
/// Memory-safe Rust implementation of the OTRv4 double ratchet with
/// deterministic secret zeroization.  Exposed to Python via PyO3.
///
/// All byte-returning methods return Python `bytes` objects, not lists.

pub mod kdf;
pub mod header;
pub mod ratchet;

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;

use header::RatchetHeader;
use ratchet::{DoubleRatchet, EncryptResult};

// ═══════════════════════════════════════════════════════════════════
// PyO3 wrapper types
// ═══════════════════════════════════════════════════════════════════

/// Python-visible encrypt result.
/// All fields return `bytes`, not `list[int]`.
#[pyclass(name = "RustEncryptResult")]
struct PyEncryptResult {
    inner_ciphertext: Vec<u8>,
    inner_header: Vec<u8>,
    inner_nonce: Vec<u8>,
    inner_tag: Vec<u8>,
    inner_ratchet_id: u32,
    inner_reveal_mac_keys: Vec<Vec<u8>>,
}

#[pymethods]
impl PyEncryptResult {
    #[getter]
    fn ciphertext<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner_ciphertext)
    }

    #[getter]
    fn header<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner_header)
    }

    #[getter]
    fn nonce<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner_nonce)
    }

    #[getter]
    fn tag<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner_tag)
    }

    #[getter]
    fn ratchet_id(&self) -> u32 {
        self.inner_ratchet_id
    }

    #[getter]
    fn reveal_mac_keys<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner_reveal_mac_keys
            .iter()
            .map(|k| PyBytes::new_bound(py, k))
            .collect()
    }
}

impl From<EncryptResult> for PyEncryptResult {
    fn from(r: EncryptResult) -> Self {
        Self {
            inner_ciphertext: r.ciphertext,
            inner_header: r.header,
            inner_nonce: r.nonce.to_vec(),
            inner_tag: r.tag.to_vec(),
            inner_ratchet_id: r.ratchet_id,
            inner_reveal_mac_keys: r.reveal_mac_keys,
        }
    }
}

/// Python-visible double ratchet.
#[pyclass(name = "RustDoubleRatchet")]
struct PyDoubleRatchet {
    inner: DoubleRatchet,
}

#[pymethods]
impl PyDoubleRatchet {
    /// Create a new ratchet from DAKE session keys.
    #[new]
    fn new(
        root_key: &[u8],
        chain_key_send: &[u8],
        chain_key_recv: &[u8],
        brace_key: &[u8],
        dh_pub_local: &[u8],
        is_initiator: bool,
    ) -> PyResult<Self> {
        let rk: &[u8; 32] = root_key
            .try_into()
            .map_err(|_| PyValueError::new_err("root_key must be 32 bytes"))?;
        let cks: &[u8; 32] = chain_key_send
            .try_into()
            .map_err(|_| PyValueError::new_err("chain_key_send must be 32 bytes"))?;
        let ckr: &[u8; 32] = chain_key_recv
            .try_into()
            .map_err(|_| PyValueError::new_err("chain_key_recv must be 32 bytes"))?;
        let bk: &[u8; 32] = brace_key
            .try_into()
            .map_err(|_| PyValueError::new_err("brace_key must be 32 bytes"))?;
        let pub_l: &[u8; 56] = dh_pub_local
            .try_into()
            .map_err(|_| PyValueError::new_err("dh_pub_local must be 56 bytes"))?;

        let inner = DoubleRatchet::new(rk, cks, ckr, bk, pub_l, is_initiator)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(Self { inner })
    }

    /// Encrypt plaintext.  Returns RustEncryptResult.
    fn encrypt(&mut self, plaintext: &[u8]) -> PyResult<PyEncryptResult> {
        self.inner
            .encrypt(plaintext)
            .map(PyEncryptResult::from)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Decrypt a message using the current recv chain (same DH key).
    fn decrypt_same_dh<'py>(
        &mut self,
        py: Python<'py>,
        header: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        tag: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let n: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| PyValueError::new_err("nonce must be 12 bytes"))?;
        let t: &[u8; 16] = tag
            .try_into()
            .map_err(|_| PyValueError::new_err("tag must be 16 bytes"))?;

        let result = self.inner
            .decrypt_same_dh(header, ciphertext, n, t)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(PyBytes::new_bound(py, &result))
    }

    /// Decrypt a message that carries a new DH key (DH ratchet).
    fn decrypt_new_dh<'py>(
        &mut self,
        py: Python<'py>,
        header: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        tag: &[u8],
        dh_secret_recv: &[u8],
        dh_secret_send: &[u8],
        new_local_pub: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let n: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| PyValueError::new_err("nonce must be 12 bytes"))?;
        let t: &[u8; 16] = tag
            .try_into()
            .map_err(|_| PyValueError::new_err("tag must be 16 bytes"))?;
        let nlp: &[u8; 56] = new_local_pub
            .try_into()
            .map_err(|_| PyValueError::new_err("new_local_pub must be 56 bytes"))?;

        let result = self.inner
            .decrypt_new_dh(header, ciphertext, n, t, dh_secret_recv, dh_secret_send, nlp)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(PyBytes::new_bound(py, &result))
    }

    /// Check if header contains a new DH key (needs DH ratchet).
    fn is_new_dh(&self, header: &[u8]) -> bool {
        self.inner.is_new_dh(header)
    }

    /// Extract DH public key from header.  Returns bytes.
    fn header_dh_pub<'py>(&self, py: Python<'py>, header: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let pub_key = DoubleRatchet::header_dh_pub(header)
            .ok_or_else(|| PyValueError::new_err("header too short for DH pub"))?;
        Ok(PyBytes::new_bound(py, &pub_key))
    }

    /// Check if a send-side DH rekey is needed.
    fn needs_rekey(&self) -> bool {
        self.inner.needs_rekey()
    }

    /// Perform send-side DH ratchet after Python does X448 exchange.
    fn send_ratchet(&mut self, dh_secret: &[u8], new_local_pub: &[u8]) -> PyResult<()> {
        let nlp: &[u8; 56] = new_local_pub
            .try_into()
            .map_err(|_| PyValueError::new_err("new_local_pub must be 56 bytes"))?;
        self.inner.send_ratchet(dh_secret, nlp);
        Ok(())
    }

    /// Rotate brace key with KEM shared secret.
    fn rotate_brace_key(&mut self, shared_secret: &[u8]) {
        self.inner.rotate_brace_key(shared_secret);
    }

    /// Get our current DH public key.  Returns bytes.
    fn local_pub<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.local_pub())
    }

    /// Get current ratchet ID.
    fn ratchet_id(&self) -> u32 {
        self.inner.ratchet_id()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Standalone KDF functions for Python
// ═══════════════════════════════════════════════════════════════════

/// SHAKE-256 KDF matching OTRv4 spec §3.2.  Returns bytes.
#[pyfunction]
fn rust_kdf_1<'py>(py: Python<'py>, usage_id: u8, value: &[u8], length: usize) -> Bound<'py, PyBytes> {
    let result = kdf::kdf_1(usage_id, value, length);
    PyBytes::new_bound(py, &result)
}

/// Decode a ratchet header.  Returns (bytes, int, int).
#[pyfunction]
fn rust_decode_header<'py>(py: Python<'py>, data: &[u8]) -> PyResult<(Bound<'py, PyBytes>, u32, u32)> {
    let h = RatchetHeader::decode(data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((PyBytes::new_bound(py, &h.dh_pub), h.prev_chain_len, h.msg_num))
}

/// Encode a ratchet header from components.  Returns bytes.
#[pyfunction]
fn rust_encode_header<'py>(py: Python<'py>, dh_pub: &[u8], prev_chain_len: u32, msg_num: u32) -> PyResult<Bound<'py, PyBytes>> {
    let pub_key: [u8; 56] = dh_pub
        .try_into()
        .map_err(|_| PyValueError::new_err("dh_pub must be 56 bytes"))?;
    let h = RatchetHeader::new(pub_key, prev_chain_len, msg_num);
    Ok(PyBytes::new_bound(py, &h.encode()))
}

// ═══════════════════════════════════════════════════════════════════
// Python module
// ═══════════════════════════════════════════════════════════════════

#[pymodule]
fn otrv4_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDoubleRatchet>()?;
    m.add_class::<PyEncryptResult>()?;
    m.add_function(wrap_pyfunction!(rust_kdf_1, m)?)?;
    m.add_function(wrap_pyfunction!(rust_decode_header, m)?)?;
    m.add_function(wrap_pyfunction!(rust_encode_header, m)?)?;
    Ok(())
}
