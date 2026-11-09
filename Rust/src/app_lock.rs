// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The app lock: a passphrase that unlocks this device's data key.
//!
//! Design and audit: docs/APP_LOCK_PASSPHRASE.md. In short:
//!
//! ```text
//! passphrase --Argon2id(salt, params)--> P   (32 bytes)
//! H = HMAC-SHA-256(salt), computed by a non-exportable key in the
//!     platform key store (Android Keystore / StrongBox); handed in here
//! KEK = HKDF-SHA-512(ikm = P || H, salt = salt, info = LABEL_KEK)
//! record = header || nonce || AES-256-GCM(KEK, DEK, aad = header)
//! ```
//!
//! The 256-bit data key (DEK) is made here, lives here, and never crosses
//! into Python or Kotlin. While unlocked it provides:
//!
//!   * the key-wrapping key for every key file (`at_rest`), as a subkey;
//!   * [`app_lock_seal`] / [`app_lock_open`], the inner layer the Android
//!     vault adds to each record, under another subkey.
//!
//! Two record modes:
//!
//!   * `MODE_PASSPHRASE` -- the lock is on. Both P and H are needed.
//!   * `MODE_DEVICE` -- the lock was turned off after being on. H alone
//!     (from a key store key with no unlocked-device requirement): the
//!     DEK stays, only its wrapping changes, which is today's protection.
//!
//! Verification is the AEAD tag on the wrapped DEK: there is nothing to
//! compare a guess against, and a wrong passphrase and a damaged record fail
//! the same way. The passphrase, P, H and the KEK are `Zeroizing` and dropped
//! the moment the DEK is unwrapped.
//!
//! NOT DONE: `mlock`. The crate is `#![forbid(unsafe_code)]` (smp_vault
//! dropped its mlock for the same reason); the DEK is zeroized on lock, and
//! locking ends the app's process.

use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict};
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::at_rest;
use crate::secure_mem::{ct_eq, SecretBytes};

const MAGIC: &[u8; 8] = b"OTRVAL1\0";
pub const MODE_PASSPHRASE: u8 = 1;
pub const MODE_DEVICE: u8 = 2;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// magic(8) mode(1) t(4) m(4) p(4) salt(32)
const HEADER_LEN: usize = 8 + 1 + 12 + SALT_LEN;
pub const RECORD_LEN: usize = HEADER_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

const LABEL_KEK: &[u8] = b"otrv4plus app-lock v1 kek";
const LABEL_WRAP: &[u8] = b"otrv4plus app-lock v1 key-wrapping";
const LABEL_VAULT: &[u8] = b"otrv4plus app-lock v1 vault";
const VAULT_MAGIC: &[u8; 8] = b"OTRVAI1\0";

/// Bounds on the Argon2id cost a record may name. A record is read from
/// disk: an absurd cost there must not turn unlock into a memory bomb.
const T_MIN: u32 = 1;
const T_MAX: u32 = 10;
const M_MIN_KIB: u32 = 8 * 1024;
const M_MAX_KIB: u32 = 1024 * 1024;
const P_MIN: u32 = 1;
const P_MAX: u32 = 8;

/// The data key, while unlocked.
static DEK: Mutex<Option<SecretBytes<KEY_LEN>>> = Mutex::new(None);
/// A data key made by [app_lock_enrol] whose record the caller has not yet
/// stored. Nothing is sealed or wrapped under it until [app_lock_commit]:
/// a crash before the record is on disk must lose nothing but this key.
static PENDING: Mutex<Option<SecretBytes<KEY_LEN>>> = Mutex::new(None);
/// Whether this module installed the key-wrapping key (so lock clears only
/// what it installed, never a desktop key-custody KEK).
static INSTALLED_WRAP: Mutex<bool> = Mutex::new(false);

// ── pure core (tested without Python) ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    pub t: u32,
    pub m_kib: u32,
    pub p: u32,
}

impl Cost {
    fn check(self) -> Result<Self, &'static str> {
        if !(T_MIN..=T_MAX).contains(&self.t)
            || !(M_MIN_KIB..=M_MAX_KIB).contains(&self.m_kib)
            || !(P_MIN..=P_MAX).contains(&self.p)
        {
            return Err("Argon2id cost out of bounds");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub mode: u8,
    pub cost: Cost,
    pub salt: [u8; SALT_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = self.mode;
        out[9..13].copy_from_slice(&self.cost.t.to_be_bytes());
        out[13..17].copy_from_slice(&self.cost.m_kib.to_be_bytes());
        out[17..21].copy_from_slice(&self.cost.p.to_be_bytes());
        out[21..].copy_from_slice(&self.salt);
        out
    }

    pub fn parse(record: &[u8]) -> Result<Self, &'static str> {
        if record.len() != RECORD_LEN || &record[..8] != MAGIC {
            return Err("not an app-lock record");
        }
        let mode = record[8];
        let be = |i: usize| u32::from_be_bytes(record[i..i + 4].try_into().expect("4 bytes"));
        let cost = Cost { t: be(9), m_kib: be(13), p: be(17) };
        match mode {
            MODE_PASSPHRASE => { cost.check()?; }
            MODE_DEVICE => {
                if cost != (Cost { t: 0, m_kib: 0, p: 0 }) {
                    return Err("device record names a cost");
                }
            }
            _ => return Err("unknown app-lock mode"),
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&record[21..HEADER_LEN]);
        Ok(Self { mode, cost, salt })
    }
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> SecretBytes<KEY_LEN> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA-512 length");
    SecretBytes::new(*out)
}

/// The KEK for [header]: from the passphrase and H (passphrase mode) or H
/// alone (device mode).
pub fn derive_kek(header: &Header, passphrase: Option<&[u8]>, hw: &[u8; KEY_LEN])
    -> Result<SecretBytes<KEY_LEN>, &'static str>
{
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    match (header.mode, passphrase) {
        (MODE_PASSPHRASE, Some(pass)) => {
            if pass.is_empty() {
                return Err("empty passphrase");
            }
            let params = Params::new(header.cost.m_kib, header.cost.t, header.cost.p, Some(KEY_LEN))
                .map_err(|_| "Argon2id parameters rejected")?;
            let mut p = Zeroizing::new([0u8; KEY_LEN]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(pass, &header.salt, &mut p[..])
                .map_err(|_| "Argon2id failed")?;
            ikm.extend_from_slice(&p[..]);
        }
        (MODE_DEVICE, None) => {}
        (MODE_PASSPHRASE, None) => return Err("this record needs the passphrase"),
        _ => return Err("this record takes no passphrase"),
    }
    ikm.extend_from_slice(hw);
    Ok(hkdf(&ikm, &header.salt, LABEL_KEK))
}

pub fn seal_record(header: &Header, kek: &SecretBytes<KEY_LEN>, dek: &SecretBytes<KEY_LEN>)
    -> Result<Vec<u8>, &'static str>
{
    let head = header.encode();
    let cipher = Aes256Gcm::new_from_slice(kek.expose_slice()).map_err(|_| "bad KEK")?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: dek.expose_slice(), aad: &head })
        .map_err(|_| "wrap failed")?;
    let mut out = Vec::with_capacity(RECORD_LEN);
    out.extend_from_slice(&head);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), RECORD_LEN);
    Ok(out)
}

/// The DEK in [record], or an error that does not say why: a wrong
/// passphrase and a damaged record are the same failure.
pub fn open_record(record: &[u8], passphrase: Option<&[u8]>, hw: &[u8; KEY_LEN])
    -> Result<SecretBytes<KEY_LEN>, &'static str>
{
    let header = Header::parse(record)?;
    let kek = derive_kek(&header, passphrase, hw)?;
    let cipher = Aes256Gcm::new_from_slice(kek.expose_slice()).map_err(|_| "bad KEK")?;
    let nonce: [u8; NONCE_LEN] = record[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        .try_into().expect("length checked");
    let dek = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(nonce),
                     Payload { msg: &record[HEADER_LEN + NONCE_LEN..], aad: &record[..HEADER_LEN] })
            .map_err(|_| "wrong passphrase or damaged record")?,
    );
    SecretBytes::from_slice(&dek).ok_or("wrong passphrase or damaged record")
}

fn vault_cipher(dek: &SecretBytes<KEY_LEN>) -> Aes256Gcm {
    let key = hkdf(dek.expose_slice(), MAGIC, LABEL_VAULT);
    Aes256Gcm::new_from_slice(key.expose_slice()).expect("32-byte key")
}

fn vault_aad(name: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + name.len());
    aad.extend_from_slice(VAULT_MAGIC);
    aad.extend_from_slice(name);
    aad
}

pub fn vault_seal(dek: &SecretBytes<KEY_LEN>, name: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = vault_cipher(dek)
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &vault_aad(name) })
        .map_err(|_| "seal failed")?;
    let mut out = Vec::with_capacity(8 + NONCE_LEN + ct.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// `Ok(None)`: not a sealed record (legacy, written before enrolment).
/// `Err`: a sealed record that does not open under this key and name.
pub fn vault_open(dek: &SecretBytes<KEY_LEN>, name: &[u8], record: &[u8])
    -> Result<Option<Zeroizing<Vec<u8>>>, &'static str>
{
    if record.len() < 8 || &record[..8] != VAULT_MAGIC {
        return Ok(None);
    }
    if record.len() < 8 + NONCE_LEN + TAG_LEN {
        return Err("sealed record too short");
    }
    let nonce: [u8; NONCE_LEN] = record[8..8 + NONCE_LEN].try_into().expect("length checked");
    vault_cipher(dek)
        .decrypt(&Nonce::from(nonce), Payload { msg: &record[8 + NONCE_LEN..], aad: &vault_aad(name) })
        .map(|v| Some(Zeroizing::new(v)))
        .map_err(|_| "sealed record does not open")
}

fn install(dek: SecretBytes<KEY_LEN>) -> Result<(), &'static str> {
    let wrap = hkdf(dek.expose_slice(), MAGIC, LABEL_WRAP);
    at_rest::install_kek_from_rust(&wrap).map_err(|_| "key-wrapping key not installed")?;
    *INSTALLED_WRAP.lock().map_err(|_| "lock poisoned")? = true;
    *DEK.lock().map_err(|_| "lock poisoned")? = Some(dek);
    Ok(())
}

pub fn lock_now() {
    if let Ok(mut p) = PENDING.lock() {
        *p = None;
    }
    if let Ok(mut d) = DEK.lock() {
        *d = None; // SecretBytes zeroizes on drop
    }
    if let Ok(mut installed) = INSTALLED_WRAP.lock() {
        if *installed {
            at_rest::clear_kek_from_rust();
            *installed = false;
        }
    }
}

fn with_dek<T>(f: impl FnOnce(&SecretBytes<KEY_LEN>) -> Result<T, &'static str>) -> Result<T, &'static str> {
    let guard = DEK.lock().map_err(|_| "lock poisoned")?;
    match guard.as_ref() {
        Some(dek) => f(dek),
        None => Err("locked"),
    }
}

// ── Python surface ───────────────────────────────────────────────────────────

/// Copy a secret out of a `bytearray` and zero the source. `bytes` and `str`
/// are refused: they cannot be wiped, so the caller must not have made one.
fn take_secret(obj: &Bound<'_, PyAny>) -> PyResult<Zeroizing<Vec<u8>>> {
    let ba = obj
        .cast::<PyByteArray>()
        .map_err(|_| PyTypeError::new_err("secrets must be passed as a bytearray"))?;
    let copy = Zeroizing::new(ba.to_vec());
    for i in 0..ba.len() {
        ba.set_item(i, 0u8)?;
    }
    Ok(copy)
}

fn take_hw(obj: &Bound<'_, PyAny>) -> PyResult<Zeroizing<[u8; KEY_LEN]>> {
    let raw = take_secret(obj)?;
    if raw.len() != KEY_LEN {
        return Err(PyValueError::new_err("hardware value must be 32 bytes"));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&raw);
    Ok(out)
}

fn take_pass(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Zeroizing<Vec<u8>>>> {
    obj.map(take_secret).transpose()
}

fn rt(e: &'static str) -> PyErr {
    PyRuntimeError::new_err(e)
}

/// A fresh random salt for a new record (public; the key store HMACs it).
#[pyfunction]
pub fn app_lock_new_salt(py: Python<'_>) -> Py<PyBytes> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    PyBytes::new(py, &salt).unbind()
}

/// The public header of [record]: {"mode": "passphrase"|"device", "salt",
/// "t", "m_kib", "p"}. Raises ValueError for anything else.
#[pyfunction]
pub fn app_lock_record_info<'py>(py: Python<'py>, record: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let h = Header::parse(record).map_err(PyValueError::new_err)?;
    let d = PyDict::new(py);
    d.set_item("mode", if h.mode == MODE_PASSPHRASE { "passphrase" } else { "device" })?;
    d.set_item("salt", PyBytes::new(py, &h.salt))?;
    d.set_item("t", h.cost.t)?;
    d.set_item("m_kib", h.cost.m_kib)?;
    d.set_item("p", h.cost.p)?;
    Ok(d)
}

/// Make a new data key and wrap it. Returns the record to store; then
/// [app_lock_commit] starts using the key. `passphrase` None makes a
/// device-mode record (cost ignored). Refused while unlocked: enrolling
/// twice would orphan the first key.
#[pyfunction]
#[pyo3(signature = (passphrase, hw, salt, t, m_kib, p))]
pub fn app_lock_enrol(
    py: Python<'_>, passphrase: Option<&Bound<'_, PyAny>>, hw: &Bound<'_, PyAny>,
    salt: &[u8], t: u32, m_kib: u32, p: u32,
) -> PyResult<Py<PyBytes>> {
    let pass = take_pass(passphrase)?;
    let hw = take_hw(hw)?;
    if app_lock_unlocked() {
        return Err(rt("already unlocked: change the wrapping with app_lock_rewrap"));
    }
    let header = make_header(pass.is_some(), salt, t, m_kib, p)?;
    let mut fresh = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut fresh[..]);
    let dek = SecretBytes::new(*fresh);
    let record = py.detach(|| -> Result<Vec<u8>, &'static str> {
        let kek = derive_kek(&header, pass.as_deref().map(|v| &v[..]), &hw)?;
        seal_record(&header, &kek, &dek)
    }).map_err(rt)?;
    *PENDING.lock().map_err(|_| rt("lock poisoned"))? = Some(dek);
    Ok(PyBytes::new(py, &record).unbind())
}

/// The record from [app_lock_enrol] is stored: unlock with its key. False
/// when there is no enrolment waiting.
#[pyfunction]
pub fn app_lock_commit() -> PyResult<bool> {
    let pending = PENDING.lock().map_err(|_| rt("lock poisoned"))?.take();
    match pending {
        Some(dek) => {
            install(dek).map_err(rt)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

fn make_header(passphrase: bool, salt: &[u8], t: u32, m_kib: u32, p: u32) -> PyResult<Header> {
    let salt: [u8; SALT_LEN] = salt.try_into()
        .map_err(|_| PyValueError::new_err("salt must be 32 bytes"))?;
    if passphrase {
        let cost = Cost { t, m_kib, p }.check().map_err(PyValueError::new_err)?;
        Ok(Header { mode: MODE_PASSPHRASE, cost, salt })
    } else {
        Ok(Header { mode: MODE_DEVICE, cost: Cost { t: 0, m_kib: 0, p: 0 }, salt })
    }
}

/// Unlock with [record]. False for a wrong passphrase or a damaged record
/// (indistinguishable on purpose). The GIL is released for Argon2id.
#[pyfunction]
#[pyo3(signature = (passphrase, hw, record))]
pub fn app_lock_unlock(
    py: Python<'_>, passphrase: Option<&Bound<'_, PyAny>>, hw: &Bound<'_, PyAny>, record: &[u8],
) -> PyResult<bool> {
    let pass = take_pass(passphrase)?;
    let hw = take_hw(hw)?;
    let opened = py.detach(|| open_record(record, pass.as_deref().map(|v| &v[..]), &hw));
    match opened {
        Ok(dek) => {
            install(dek).map_err(rt)?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Whether [passphrase] opens [record] to the data key now in use, without
/// changing anything (asked before a change or before turning the lock off).
#[pyfunction]
#[pyo3(signature = (passphrase, hw, record))]
pub fn app_lock_check(
    py: Python<'_>, passphrase: Option<&Bound<'_, PyAny>>, hw: &Bound<'_, PyAny>, record: &[u8],
) -> PyResult<bool> {
    let pass = take_pass(passphrase)?;
    let hw = take_hw(hw)?;
    let opened = py.detach(|| open_record(record, pass.as_deref().map(|v| &v[..]), &hw));
    let Ok(candidate) = opened else { return Ok(false) };
    with_dek(|dek| Ok(ct_eq(dek.expose_slice(), candidate.expose_slice()))).map_err(rt)
}

/// Wrap the data key in use under a new passphrase (or device mode when
/// None). Returns the new record; nothing is re-encrypted. Unlocked only.
#[pyfunction]
#[pyo3(signature = (passphrase, hw, salt, t, m_kib, p))]
pub fn app_lock_rewrap(
    py: Python<'_>, passphrase: Option<&Bound<'_, PyAny>>, hw: &Bound<'_, PyAny>,
    salt: &[u8], t: u32, m_kib: u32, p: u32,
) -> PyResult<Py<PyBytes>> {
    let pass = take_pass(passphrase)?;
    let hw = take_hw(hw)?;
    let header = make_header(pass.is_some(), salt, t, m_kib, p)?;
    let dek = with_dek(|d| Ok(SecretBytes::<KEY_LEN>::new(*d.expose()))).map_err(rt)?;
    let record = py.detach(|| -> Result<Vec<u8>, &'static str> {
        let kek = derive_kek(&header, pass.as_deref().map(|v| &v[..]), &hw)?;
        seal_record(&header, &kek, &dek)
    }).map_err(rt)?;
    Ok(PyBytes::new(py, &record).unbind())
}

/// Lock: zeroize the data key and remove the key-wrapping key it installed.
#[pyfunction]
pub fn app_lock_lock() {
    lock_now();
}

#[pyfunction]
pub fn app_lock_unlocked() -> bool {
    DEK.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// The vault's inner layer: seal [plaintext] under [name]. Unlocked only.
#[pyfunction]
pub fn app_lock_seal(py: Python<'_>, name: &[u8], plaintext: &[u8]) -> PyResult<Py<PyBytes>> {
    let out = with_dek(|dek| vault_seal(dek, name, plaintext)).map_err(rt)?;
    Ok(PyBytes::new(py, &out).unbind())
}

/// Open a sealed vault record. Returns None for a record that does not open
/// (or was never sealed: the caller checks [app_lock_is_sealed] first).
/// Raises RuntimeError("locked") while locked, so nothing mistakes "locked"
/// for "empty".
#[pyfunction]
pub fn app_lock_open(py: Python<'_>, name: &[u8], record: &[u8]) -> PyResult<Option<Py<PyBytes>>> {
    let opened = with_dek(|dek| Ok(vault_open(dek, name, record))).map_err(rt)?;
    Ok(match opened {
        Ok(Some(plain)) => Some(PyBytes::new(py, &plain).unbind()),
        _ => None,
    })
}

/// Whether [record] carries the vault's inner layer.
#[pyfunction]
pub fn app_lock_is_sealed(record: &[u8]) -> bool {
    record.len() >= 8 && &record[..8] == VAULT_MAGIC
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(app_lock_new_salt, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_record_info, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_enrol, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_commit, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_unlock, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_check, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_rewrap, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_lock, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_unlocked, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_seal, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_open, m)?)?;
    m.add_function(wrap_pyfunction!(app_lock_is_sealed, m)?)?;
    m.add("APP_LOCK_RECORD_LEN", RECORD_LEN)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW: [u8; 32] = [7u8; 32];
    // The minimum cost keeps the tests fast; the bounds are tested separately.
    const CHEAP: Cost = Cost { t: 1, m_kib: M_MIN_KIB, p: 1 };

    fn header(mode: u8) -> Header {
        let cost = if mode == MODE_PASSPHRASE { CHEAP } else { Cost { t: 0, m_kib: 0, p: 0 } };
        Header { mode, cost, salt: [3u8; 32] }
    }

    fn dek() -> SecretBytes<32> { SecretBytes::new([9u8; 32]) }

    fn record(pass: &[u8]) -> Vec<u8> {
        let h = header(MODE_PASSPHRASE);
        let kek = derive_kek(&h, Some(pass), &HW).unwrap();
        seal_record(&h, &kek, &dek()).unwrap()
    }

    #[test]
    fn the_right_passphrase_opens_the_data_key() {
        let r = record(b"correct horse");
        assert_eq!(r.len(), RECORD_LEN);
        assert_eq!(open_record(&r, Some(b"correct horse"), &HW).unwrap().expose(), dek().expose());
    }

    #[test]
    fn a_wrong_passphrase_or_hardware_value_fails() {
        let r = record(b"correct horse");
        assert!(open_record(&r, Some(b"correct horsf"), &HW).is_err());
        assert!(open_record(&r, Some(b"correct horse"), &[8u8; 32]).is_err());
        assert!(open_record(&r, None, &HW).is_err());
    }

    #[test]
    fn every_byte_of_the_record_is_authenticated() {
        let r = record(b"pw");
        for i in 0..r.len() {
            let mut bad = r.clone();
            bad[i] ^= 0x01;
            assert!(open_record(&bad, Some(b"pw"), &HW).is_err(), "byte {i} not covered");
        }
    }

    #[test]
    fn wrong_passphrase_and_damage_give_the_same_error() {
        let r = record(b"pw");
        let wrong = open_record(&r, Some(b"pX"), &HW).err().unwrap();
        let mut bad = r.clone();
        bad[RECORD_LEN - 1] ^= 1;
        assert_eq!(wrong, open_record(&bad, Some(b"pw"), &HW).err().unwrap());
    }

    #[test]
    fn device_mode_needs_only_the_hardware_value() {
        let h = header(MODE_DEVICE);
        let kek = derive_kek(&h, None, &HW).unwrap();
        let r = seal_record(&h, &kek, &dek()).unwrap();
        assert_eq!(open_record(&r, None, &HW).unwrap().expose(), dek().expose());
        assert!(open_record(&r, Some(b"pw"), &HW).is_err());
        assert!(open_record(&r, None, &[0u8; 32]).is_err());
    }

    #[test]
    fn a_record_naming_an_absurd_cost_is_refused_before_argon2() {
        let mut r = record(b"pw");
        r[13..17].copy_from_slice(&(64u32 * 1024 * 1024).to_be_bytes()); // 64 GiB
        assert_eq!(Header::parse(&r).err(), Some("Argon2id cost out of bounds"));
        let mut r = record(b"pw");
        r[9..13].copy_from_slice(&0u32.to_be_bytes());
        assert!(Header::parse(&r).is_err());
    }

    #[test]
    fn the_passphrase_is_stretched_not_used_directly() {
        // Two records with different salts give different KEKs for one
        // passphrase; and the KEK is never the passphrase or H.
        let mut a = header(MODE_PASSPHRASE);
        let mut b = header(MODE_PASSPHRASE);
        a.salt = [1u8; 32];
        b.salt = [2u8; 32];
        let ka = derive_kek(&a, Some(b"pw"), &HW).unwrap();
        let kb = derive_kek(&b, Some(b"pw"), &HW).unwrap();
        assert_ne!(ka.expose(), kb.expose());
        assert_ne!(ka.expose(), &HW);
    }

    #[test]
    fn vault_records_bind_their_name_and_need_the_key() {
        let k = dek();
        let sealed = vault_seal(&k, b"vault/creds", b"secret").unwrap();
        assert_eq!(&vault_open(&k, b"vault/creds", &sealed).unwrap().unwrap()[..], b"secret");
        assert!(vault_open(&k, b"vault/history", &sealed).is_err());
        assert!(vault_open(&SecretBytes::new([1u8; 32]), b"vault/creds", &sealed).is_err());
        // A record from before enrolment is reported as such, not as damage.
        assert!(vault_open(&k, b"x", b"legacy plaintext").unwrap().is_none());
    }

    #[test]
    fn locking_forgets_the_key_and_the_wrapping_key_it_installed() {
        // The KEK slot is process-wide; at_rest's tests take this lock too.
        let _g = crate::at_rest::tests::KEK_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        lock_now();
        install(dek()).unwrap();
        assert!(app_lock_unlocked());
        assert!(crate::at_rest::key_wrapping_active());
        assert!(with_dek(|d| vault_seal(d, b"n", b"p")).is_ok());
        lock_now();
        assert!(!app_lock_unlocked());
        assert!(!crate::at_rest::key_wrapping_active());
        assert_eq!(with_dek(|d| vault_seal(d, b"n", b"p")).err(), Some("locked"));
    }
}
