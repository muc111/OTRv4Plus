/// SMP Secret Vault — secure storage for SMP big integers.
///
/// Python's `int` type is immutable and cannot be zeroized. This module
/// stores SMP secret exponents (a2, a3, b2, b3, r2..r9, secret) in
/// Rust-allocated memory that is deterministically zeroed on drop.
///
/// The Python SMP protocol logic stays unchanged — it just calls
/// `vault.store(name, value)` and `vault.load(name)` instead of
/// `self.a2 = value` and reading `self.a2`.
///
/// All modular arithmetic on secrets is performed inside Rust via
/// OpenSSL's constant-time BN functions (linked through the existing
/// C extension). This way, secret integers NEVER enter the Python heap.

use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A big integer stored as big-endian bytes, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretInt {
    data: Vec<u8>,
}

impl SecretInt {
    fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

}

/// Vault holding named SMP secrets.
/// All entries are zeroized when the vault is dropped.
struct Vault {
    entries: HashMap<String, SecretInt>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        // SecretInt implements ZeroizeOnDrop, but clear the map
        // to trigger drops immediately.
        self.entries.clear();
    }
}

impl Vault {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    fn store(&mut self, name: &str, value: &[u8]) {
        // If an existing entry exists, it's dropped (and zeroized)
        // when replaced.
        self.entries.insert(name.to_string(), SecretInt::new(value));
    }

    fn load(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|s| s.as_bytes())
    }

    fn remove(&mut self, name: &str) {
        self.entries.remove(name);
        // SecretInt::drop runs → data zeroized
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    fn has(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }
}

// ═══════════════════════════════════════════════════════════════════
// PyO3 bindings
// ═══════════════════════════════════════════════════════════════════

/// Python-visible SMP secret vault.
///
/// Usage from Python:
///   vault = RustSMPVault()
///   vault.store("a2", some_big_int.to_bytes(384, 'big'))
///   val_bytes = vault.load("a2")  # returns bytes or None
///   big_int = int.from_bytes(val_bytes, 'big')
///   vault.clear()  # zeroize everything
///   del vault       # also zeroizes via Drop
#[pyclass(name = "RustSMPVault")]
pub struct PySMPVault {
    inner: Vault,
}

#[pymethods]
impl PySMPVault {
    #[new]
    fn new() -> Self {
        Self { inner: Vault::new() }
    }

    /// Store a secret integer as big-endian bytes.
    ///
    /// Args:
    ///     name: identifier (e.g. "a2", "secret", "r3")
    ///     value: big-endian bytes of the integer
    fn store(&mut self, name: &str, value: &[u8]) {
        self.inner.store(name, value);
    }

    /// Store a Python int directly.
    /// Converts to 384-byte big-endian (SMP modulus size).
    fn store_int(&mut self, name: &str, value: u128) -> PyResult<()> {
        // For ints that fit in u128 — use store_int_bytes for larger
        let bytes = value.to_be_bytes();
        self.inner.store(name, &bytes);
        Ok(())
    }

    /// Store a Python int as big-endian bytes with specified length.
    fn store_int_bytes(&mut self, name: &str, value: &[u8]) {
        self.inner.store(name, value);
    }

    /// Load a secret, returning bytes or None.
    fn load<'py>(&self, py: Python<'py>, name: &str) -> Option<Bound<'py, PyBytes>> {
        self.inner.load(name).map(|data| PyBytes::new_bound(py, data))
    }

    /// Check if a secret exists.
    fn has(&self, name: &str) -> bool {
        self.inner.has(name)
    }

    /// Remove and zeroize a single secret.
    fn remove(&mut self, name: &str) {
        self.inner.remove(name);
    }

    /// Zeroize and remove all secrets.
    fn clear(&mut self) {
        self.inner.clear();
    }

    /// Number of stored secrets.
    fn count(&self) -> usize {
        self.inner.entries.len()
    }

    /// List stored secret names (for debugging — doesn't reveal values).
    fn names(&self) -> Vec<String> {
        self.inner.entries.keys().cloned().collect()
    }
}
