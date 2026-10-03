// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! `RustMlsClient`: OTRv4Plus group chat, for the Python transport.
//!
//! Wraps `otrv4_mls::MlsClient`. What crosses into Python is what the
//! transport and the screen need and nothing else:
//!
//!   * MLS wire bytes (KeyPackages, commits, Welcomes, ciphertext) -- public
//!     or encrypted, made to be sent;
//!   * a received message's plaintext and its sender's identity -- the text
//!     the user is about to read;
//!   * public facts: members, epoch, group ids, fingerprints (SHA-384 of a
//!     signature PUBLIC key);
//!   * a sealed blob of the whole state, AES-256-GCM under a key derived in
//!     Rust from a `FileDek` Python never sees the bytes of.
//!
//! No epoch secret, message key, HPKE private key or signing key has a
//! getter. The sealing key goes `FileDek` -> `MlsClient` Rust to Rust.

use std::sync::Mutex;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use otrv4_mls::{Event, MlsClient, MlsError};

use crate::at_rest::FileDek;

fn err(e: MlsError) -> PyErr {
    match e {
        MlsError::Wiped => PyRuntimeError::new_err("mls: wiped"),
        MlsError::NoSuchGroup => PyValueError::new_err("mls: no such group"),
        MlsError::GroupExists => PyValueError::new_err("mls: group exists"),
        MlsError::CommitPending => PyValueError::new_err("mls: commit pending"),
        MlsError::NoSuchMember => PyValueError::new_err("mls: no such member"),
        MlsError::Malformed => PyValueError::new_err("mls: malformed"),
        MlsError::Refused(why) => PyValueError::new_err(format!("mls: refused: {why}")),
        MlsError::Failed(why) => PyRuntimeError::new_err(format!("mls: failed: {why}")),
    }
}

/// Bounds on what Python may hand in, so a hostile room cannot make this
/// allocate or parse without limit.
const MAX_MESSAGE: usize = 1 << 20;
const MAX_ID: usize = 1024;
const MAX_PLAINTEXT: usize = 256 << 10;
const MAX_BATCH: usize = 64;

fn bounded(bytes: &[u8], max: usize, what: &str) -> PyResult<()> {
    if bytes.len() > max {
        return Err(PyValueError::new_err(format!("mls: {what} too large")));
    }
    Ok(())
}

#[pyclass(name = "RustMlsClient", module = "otrv4_core")]
pub struct RustMlsClient {
    inner: Mutex<MlsClient>,
}

impl RustMlsClient {
    fn with<T>(&self, f: impl FnOnce(&mut MlsClient) -> Result<T, MlsError>) -> PyResult<T> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut guard).map_err(err)
    }
}

#[pymethods]
impl RustMlsClient {
    /// A fresh MLS identity. `identity` is what other members see (the bare
    /// JID); the ML-DSA-87 signing key is generated inside and never leaves.
    #[new]
    fn new(identity: &[u8]) -> PyResult<Self> {
        bounded(identity, MAX_ID, "identity")?;
        if identity.is_empty() {
            return Err(PyValueError::new_err("mls: empty identity"));
        }
        Ok(Self { inner: Mutex::new(MlsClient::new(identity)) })
    }

    /// Reopen state sealed by `seal`. Refuses, undifferentiated, on a wrong
    /// key, a wrong account, or any alteration.
    #[staticmethod]
    fn open_sealed(dek: PyRef<'_, FileDek>, account: &[u8], blob: &[u8]) -> PyResult<Self> {
        bounded(account, MAX_ID, "account")?;
        let client = MlsClient::import_sealed(dek.expose()?, account, blob).map_err(err)?;
        Ok(Self { inner: Mutex::new(client) })
    }

    /// The whole state, sealed. `account` is bound as associated data.
    fn seal<'py>(&self, py: Python<'py>, dek: PyRef<'_, FileDek>, account: &[u8])
        -> PyResult<Bound<'py, PyBytes>>
    {
        bounded(account, MAX_ID, "account")?;
        let key = dek.expose()?;
        let blob = self.with(|c| c.export_sealed(key, account))?;
        Ok(PyBytes::new(py, &blob))
    }

    fn identity<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = self.with(|c| Ok(c.identity().to_vec()))?;
        Ok(PyBytes::new(py, &id))
    }

    /// Our fingerprint in `group_id`: each group has its own signing key,
    /// replaced by every self-update.
    fn own_fingerprint<'py>(&self, py: Python<'py>, group_id: &[u8])
        -> PyResult<Bound<'py, PyBytes>>
    {
        let fp = self.with(|c| c.own_fingerprint(group_id))?;
        Ok(PyBytes::new(py, &fp))
    }

    /// The caller's own state (bindings, work in progress), sealed with
    /// this client's by `seal`. Opaque here; at most 1 MiB.
    fn set_app_data(&self, data: &[u8]) -> PyResult<()> {
        self.with(|c| c.set_app_data(data))
    }

    fn app_data<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.with(|c| Ok(c.app_data().to_vec()))?;
        Ok(PyBytes::new(py, &data))
    }

    fn member_fingerprint<'py>(&self, py: Python<'py>, group_id: &[u8], identity: &[u8])
        -> PyResult<Bound<'py, PyBytes>>
    {
        let fp = self.with(|c| c.member_fingerprint(group_id, identity))?;
        Ok(PyBytes::new(py, &fp))
    }

    fn key_package<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let kp = self.with(|c| c.key_package())?;
        Ok(PyBytes::new(py, &kp))
    }

    fn create_group(&self, group_id: &[u8]) -> PyResult<()> {
        bounded(group_id, MAX_ID, "group id")?;
        self.with(|c| c.create_group(group_id))
    }

    fn has_group(&self, group_id: &[u8]) -> bool {
        self.inner.lock().map(|c| c.has_group(group_id)).unwrap_or(false)
    }

    fn group_ids<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let ids = self.with(|c| Ok(c.group_ids()))?;
        Ok(ids.iter().map(|i| PyBytes::new(py, i)).collect())
    }

    /// The group's MLS ciphersuite: 0xF0A1 (hybrid X448+ML-KEM-1024 /
    /// Ed448+ML-DSA-87, every new group) or 0x0907 (the earlier PQ-only
    /// suite).
    fn ciphersuite(&self, group_id: &[u8]) -> PyResult<u16> {
        self.with(|c| c.ciphersuite(group_id))
    }

    fn epoch(&self, group_id: &[u8]) -> PyResult<u64> {
        self.with(|c| c.epoch(group_id))
    }

    fn members<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let m = self.with(|c| c.members(group_id))?;
        Ok(m.iter().map(|i| PyBytes::new(py, i)).collect())
    }

    fn has_pending_commit(&self, group_id: &[u8]) -> bool {
        self.inner.lock().map(|c| c.has_pending_commit(group_id)).unwrap_or(false)
    }

    fn add_members<'py>(&self, py: Python<'py>, group_id: &[u8], key_packages: Vec<Vec<u8>>)
        -> PyResult<Bound<'py, PyBytes>>
    {
        if key_packages.is_empty() || key_packages.len() > MAX_BATCH {
            return Err(PyValueError::new_err("mls: bad number of key packages"));
        }
        for kp in &key_packages {
            bounded(kp, MAX_MESSAGE, "key package")?;
        }
        let commit = self.with(|c| c.add_members(group_id, &key_packages))?;
        Ok(PyBytes::new(py, &commit))
    }

    fn remove_members<'py>(&self, py: Python<'py>, group_id: &[u8], identities: Vec<Vec<u8>>)
        -> PyResult<Bound<'py, PyBytes>>
    {
        if identities.is_empty() || identities.len() > MAX_BATCH {
            return Err(PyValueError::new_err("mls: bad number of members"));
        }
        let commit = self.with(|c| c.remove_members(group_id, &identities))?;
        Ok(PyBytes::new(py, &commit))
    }

    fn self_update<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let commit = self.with(|c| c.self_update(group_id))?;
        Ok(PyBytes::new(py, &commit))
    }

    fn join<'py>(&self, py: Python<'py>, welcome: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        bounded(welcome, MAX_MESSAGE, "welcome")?;
        let gid = self.with(|c| c.join(welcome))?;
        Ok(PyBytes::new(py, &gid))
    }

    fn encrypt<'py>(&self, py: Python<'py>, group_id: &[u8], plaintext: &[u8])
        -> PyResult<Bound<'py, PyBytes>>
    {
        bounded(plaintext, MAX_PLAINTEXT, "message")?;
        let ct = self.with(|c| c.encrypt(group_id, plaintext))?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Process one room message in room order. Returns a dict:
    ///   {"kind": "application", "sender": bytes, "plaintext": bytes}
    ///   {"kind": "commit", "epoch": int, "ours": bool, "welcome": bytes|None,
    ///    "removed_us": bool, "dropped_ours": bool, "committer": bytes,
    ///    "rekeyed": [(identity, old fingerprint, new fingerprint), ...]}
    ///   {"kind": "proposal"}
    fn process<'py>(&self, py: Python<'py>, group_id: &[u8], message: &[u8])
        -> PyResult<Bound<'py, PyDict>>
    {
        bounded(message, MAX_MESSAGE, "message")?;
        let ev = self.with(|c| c.process(group_id, message))?;
        let d = PyDict::new(py);
        match ev {
            Event::Application { sender, plaintext } => {
                d.set_item("kind", "application")?;
                d.set_item("sender", PyBytes::new(py, &sender))?;
                d.set_item("plaintext", PyBytes::new(py, &plaintext))?;
            }
            Event::Commit { epoch, ours, welcome, removed_us, dropped_ours, committer,
                             rekeyed } => {
                d.set_item("kind", "commit")?;
                d.set_item("epoch", epoch)?;
                d.set_item("ours", ours)?;
                d.set_item("welcome", welcome.map(|w| PyBytes::new(py, &w)))?;
                d.set_item("removed_us", removed_us)?;
                d.set_item("dropped_ours", dropped_ours)?;
                d.set_item("committer", PyBytes::new(py, &committer))?;
                let rk: Vec<_> = rekeyed.iter().map(|(who, old, new)| (
                    PyBytes::new(py, who), PyBytes::new(py, old), PyBytes::new(py, new),
                )).collect();
                d.set_item("rekeyed", rk)?;
            }
            Event::Proposal => d.set_item("kind", "proposal")?,
        }
        Ok(d)
    }

    fn forget_group(&self, group_id: &[u8]) {
        if let Ok(mut c) = self.inner.lock() {
            c.forget_group(group_id);
        }
    }

    /// Wipe & Exit: every group, secret and signing key, destroyed.
    fn wipe(&self) {
        let mut c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        c.wipe();
    }

    #[getter]
    fn wiped(&self) -> bool {
        self.inner.lock().map(|c| c.is_wiped()).unwrap_or(true)
    }

    fn stored_entries(&self) -> usize {
        self.inner.lock().map(|c| c.stored_entries()).unwrap_or(0)
    }

    fn __repr__(&self) -> &'static str {
        "<RustMlsClient [REDACTED]>"
    }
}

