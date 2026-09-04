//! Hardened SMP Secret Vault.
//!
//! Security model:
//!   * Secrets stored in `Vec<u8>` wrapped in `ZeroizeOnDrop`.
//!   * No `unsafe` (mlock removed; lib.rs has `#![forbid(unsafe_code)]`).
//!   * Handles are random `u64` tokens issued by `OsRng` — no enumeration.
//!   * `load*` methods are gated behind `test-only-kdf` so production builds
//!     CANNOT extract secrets to Python.  Set-secret-from-vault is the only
//!     production path: secrets flow into `RustSMP` / `RustDAKE` via Rust-
//!     internal `expose_for_smp()` and never cross the PyO3 boundary outbound.

use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};
use pyo3::prelude::*;
#[cfg(feature = "test-only-kdf")]
use pyo3::types::PyBytes;
// Not gated: store_from_bytearray is the production secret-input path.
use pyo3::types::PyByteArray;
use rand::rngs::OsRng;
use rand::RngCore;

// ── SecretEntry ──────────────────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretEntry {
    data: Vec<u8>,
}

impl SecretEntry {
    fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }

    #[inline]
    fn expose(&self) -> &[u8] { &self.data }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretEntry(len={})[REDACTED]", self.data.len())
    }
}

// ── Handle registry ──────────────────────────────────────────────────────────
struct HandleRegistry {
    forward: HashMap<u64, String>,
    reverse: HashMap<String, u64>,
}

impl HandleRegistry {
    fn new() -> Self {
        Self { forward: HashMap::new(), reverse: HashMap::new() }
    }

    fn issue(&mut self, name: &str) -> u64 {
        if let Some(&h) = self.reverse.get(name) { return h; }
        let handle = loop {
            let h = OsRng.next_u64();
            if h != 0 && !self.forward.contains_key(&h) { break h; }
        };
        self.forward.insert(handle, name.to_string());
        self.reverse.insert(name.to_string(), handle);
        handle
    }

    fn resolve(&self, handle: u64) -> Option<&str> {
        self.forward.get(&handle).map(|s| s.as_str())
    }

    fn remove_by_name(&mut self, name: &str) {
        if let Some(h) = self.reverse.remove(name) { self.forward.remove(&h); }
    }

    fn clear(&mut self) {
        self.forward.clear();
        self.reverse.clear();
    }
}

// ── Vault ────────────────────────────────────────────────────────────────────
struct Vault {
    entries:  HashMap<String, SecretEntry>,
    handles:  HandleRegistry,
    max_size: usize,
    max_value_bytes: usize,
}

impl Vault {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            handles: HandleRegistry::new(),
            max_size: 128,
            max_value_bytes: 65536,  // 64 KiB
        }
    }

    fn store(&mut self, name: &str, bytes: &[u8]) -> Result<u64, &'static str> {
        if name.is_empty()  { return Err("empty name"); }
        if bytes.is_empty() { return Err("empty secret"); }
        if name.len() > 256 { return Err("name too long"); }
        if bytes.len() > self.max_value_bytes { return Err("secret too large (>64 KiB)"); }
        if !self.entries.contains_key(name) && self.entries.len() >= self.max_size {
            return Err("vault capacity exceeded");
        }
        // Drop (ZeroizeOnDrop fires) old entry before inserting new one
        if let Some(old) = self.entries.remove(name) { drop(old); }
        self.entries.insert(name.to_string(), SecretEntry::new(bytes));
        Ok(self.handles.issue(name))
    }

    fn expose_by_name(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|e| e.expose())
    }

    fn expose_by_handle(&self, handle: u64) -> Option<&[u8]> {
        let name = self.handles.resolve(handle)?;
        self.entries.get(name).map(|e| e.expose())
    }

    fn has(&self, name: &str)     -> bool { self.entries.contains_key(name) }
    fn has_handle(&self, h: u64)  -> bool { self.handles.resolve(h).is_some() }

    fn remove(&mut self, name: &str) {
        if let Some(e) = self.entries.remove(name) { drop(e); }
        self.handles.remove_by_name(name);
    }

    fn remove_handle(&mut self, handle: u64) {
        if let Some(name) = self.handles.resolve(handle).map(|s| s.to_string()) {
            if let Some(e) = self.entries.remove(&name) { drop(e); }
            self.handles.remove_by_name(&name);
        }
    }

    fn clear(&mut self) {
        let keys: Vec<String> = self.entries.keys().cloned().collect();
        for k in keys {
            if let Some(e) = self.entries.remove(&k) { drop(e); }
        }
        self.handles.clear();
    }

    fn count(&self)  -> usize       { self.entries.len() }
    fn names(&self)  -> Vec<String> { self.entries.keys().cloned().collect() }
}

impl Drop for Vault {
    fn drop(&mut self) { self.clear(); }
}

// ── PyO3 public class ────────────────────────────────────────────────────────
#[pyclass(name = "RustSMPVault")]
pub struct PySMPVault {
    inner: Vault,
}

impl PySMPVault {
    /// Rust-internal: expose bytes by name. Lifetime bound to &self.
    /// **Never call from PyO3 paths that copy to PyBytes.**
    pub fn expose_for_smp(&self, name: &str) -> Option<&[u8]> {
        self.inner.expose_by_name(name)
    }

    /// Rust-internal: expose bytes by handle.
    pub fn expose_for_smp_by_handle(&self, handle: u64) -> Option<&[u8]> {
        self.inner.expose_by_handle(handle)
    }
}

#[pymethods]
impl PySMPVault {
    #[new]
    pub fn new() -> Self { Self { inner: Vault::new() } }

    /// Store raw bytes under `name`. Returns opaque u64 handle.
    ///
    /// Prefer `store_from_bytearray` for anything a user typed: a `bytes`
    /// argument is an immutable Python object the caller cannot wipe, so
    /// passing one here leaves a copy of the secret on the Python heap for
    /// the garbage collector to deal with whenever it feels like it.
    fn store(&mut self, name: &str, value: &[u8]) -> PyResult<u64> {
        self.inner.store(name, value)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// Store a secret from a Python `bytearray`, zeroing the caller's buffer.
    ///
    /// The wipe is the point.  `set_smp_secret` used to build a wipeable
    /// bytearray, hand `bytes(raw)` to `store()`, and then carefully zero the
    /// bytearray in a `finally` -- wiping the one object that no longer
    /// mattered, while the immutable copy it had just made survived.
    ///
    /// This takes the bytearray itself, copies it into the vault's
    /// ZeroizeOnDrop entry, and zeroes the Python buffer in place before
    /// returning.  Mirrors `RustSMP::set_secret_from_bytearray`, which has
    /// worked this way since the SMP engine moved into Rust; the vault path
    /// simply never adopted it.
    fn store_from_bytearray(
        &mut self,
        name:  &str,
        value: &Bound<'_, PyByteArray>,
    ) -> PyResult<u64> {
        let mut snapshot: Vec<u8> = value.to_vec();
        let result = self.inner.store(name, &snapshot)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e));

        // Wipe our own copy whatever happened, including on the error path:
        // a rejected secret is still a secret.
        snapshot.zeroize();
        drop(snapshot);

        let n = value.len();
        for i in 0..n {
            value.set_item(i, 0u8)?;
        }
        result
    }

    fn has(&self, name: &str)        -> bool { self.inner.has(name) }
    fn has_handle(&self, h: u64)     -> bool { self.inner.has_handle(h) }
    fn count(&self)                  -> usize { self.inner.count() }
    fn names(&self)                  -> Vec<String> { self.inner.names() }

    fn remove(&mut self, name: &str) { self.inner.remove(name); }
    fn remove_handle(&mut self, h: u64) { self.inner.remove_handle(h); }
    fn clear(&mut self)              { self.inner.clear(); }

    /// SECURITY: `load` and `load_by_handle` are gated behind `test-only-kdf`.
    /// Production builds cannot extract secrets via PyO3 — secrets flow only
    /// from `store()` → Rust internals via `expose_for_smp()`.
    #[cfg(feature = "test-only-kdf")]
    fn load<'py>(&self, py: Python<'py>, name: &str) -> Option<Bound<'py, PyBytes>> {
        self.inner.expose_by_name(name).map(|d| PyBytes::new(py, d))
    }

    #[cfg(feature = "test-only-kdf")]
    fn load_by_handle<'py>(&self, py: Python<'py>, handle: u64) -> Option<Bound<'py, PyBytes>> {
        self.inner.expose_by_handle(handle).map(|d| PyBytes::new(py, d))
    }
}
