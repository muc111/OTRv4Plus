// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Secrets the terminal clients keep on disk, read and written by Rust.
//!
//! WHAT THIS REPLACES
//! ==================
//! Two stores used to do their key handling in Python:
//!
//!   * `SMPAutoRespondStorage` (otrv4+.py) read a 32-byte `.smp_seed` into
//!     Python, derived an AES key from it with argon2-cffi (or `hashlib.scrypt`)
//!     in Python, decrypted a JSON file of `{peer: passphrase}` in Python, and
//!     kept that dict for the life of the process -- every stored SMP
//!     passphrase a Python `str`, and `get_secret()` handed them out.
//!   * `TermuxFileDekProvider` (otrv4plus_identity.py) read the identity
//!     data-encryption key into a Python `bytes` and passed it down for every
//!     seal and unseal.
//!
//! Here, the seed, the DEK, the derived keys and the passphrases are Rust
//! memory (`SecretBytes` / `SecretVec`, zeroized on drop) from the moment they
//! leave the file to the moment they are dropped. Python gets booleans, peer
//! names and ciphertext. There is deliberately no getter for a stored
//! passphrase: `SmpSecretStore::bind_into` copies one Rust-to-Rust into a
//! session's `RustSMPVault`, which is the only thing that needs it.
//!
//! WHAT THIS DOES NOT CHANGE
//! =========================
//! The protection at rest is still a key file beside the data, mode 0600, with
//! no passphrase. Anyone who can read the user's home directory can read these
//! secrets; this module makes that no worse and no better. What it removes is
//! the in-process exposure: Python heap copies that nothing could wipe.
//!
//! A passphrase the user types still arrives as a Python `str` (it comes from
//! `getpass` or a prompt), and that object cannot be wiped. `set` copies it
//! into Rust at once and accepts a `bytearray`, which it zeroes, from callers
//! able to supply one.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyString};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{kdf_secret, usage};
use crate::secure_mem::{SecretBytes, SecretVec};
use crate::smp_vault::PySMPVault;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// ── key files ────────────────────────────────────────────────────────────────

/// Read a 32-byte key file. `Ok(None)` when it does not exist.
///
/// A file of any other length is an error, never padded or replaced: a key
/// file that has been truncated may still be the only way to open what it
/// protects, and regenerating it would destroy that silently.
fn read_key_file(path: &Path) -> Result<Option<SecretBytes<KEY_LEN>>, String> {
    let raw = match fs::read(path) {
        Ok(v) => Zeroizing::new(v),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("key file unreadable: {:?}", e.kind())),
    };
    if raw.len() != KEY_LEN {
        return Err(format!(
            "key file is {} bytes, expected {} -- refusing to replace it, \
             because that would discard what it protects",
            raw.len(),
            KEY_LEN
        ));
    }
    Ok(SecretBytes::from_slice(&raw))
}

/// Create a 32-byte key file, O_EXCL and 0600 from the first byte.
fn create_key_file(path: &Path) -> std::io::Result<SecretBytes<KEY_LEN>> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir)?;
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut key[..]);
    let mut f = opts.open(path)?;
    f.write_all(&key[..])?;
    f.sync_all()?;
    Ok(SecretBytes::new(*key))
}

fn load_or_create_key(path: &Path) -> PyResult<SecretBytes<KEY_LEN>> {
    if let Some(k) = read_key_file(path).map_err(PyOSError::new_err)? {
        return Ok(k);
    }
    match create_key_file(path) {
        Ok(k) => Ok(k),
        // Another process created it between the check and the create: that
        // key may already protect something, so read it rather than replace it.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_key_file(path)
            .map_err(PyOSError::new_err)?
            .ok_or_else(|| PyOSError::new_err("key file vanished while being created")),
        Err(e) => Err(PyOSError::new_err(format!("cannot create key file: {:?}", e.kind()))),
    }
}

/// Write `data` to `path` atomically: a 0600 temporary in the same directory,
/// fsync, rename.
fn write_atomically(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("store"),
        suffix.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn nonce_from(bytes: &[u8]) -> PyResult<Nonce<aes_gcm::aead::consts::U12>> {
    let arr: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("nonce must be 12 bytes"))?;
    Ok(Nonce::from(arr))
}

// ── FileDek ──────────────────────────────────────────────────────────────────

/// A data-encryption key read from (or created in) a 0600 file by Rust.
///
/// Replaces `_FileDekHandle`, which held the Termux identity DEK as a Python
/// `bytes` and passed it down on every call. The key never leaves this object:
/// it seals and opens records itself, and the identity functions
/// `create_sealed_identity_under` / `unseal_identity_under` take the object.
#[pyclass(name = "FileDek", module = "otrv4_core")]
pub struct FileDek {
    key: Option<SecretBytes<KEY_LEN>>,
}

impl FileDek {
    pub(crate) fn expose(&self) -> PyResult<&[u8]> {
        self.key
            .as_ref()
            .map(|k| k.expose_slice())
            .ok_or_else(|| PyRuntimeError::new_err("key destroyed"))
    }

    fn cipher(&self) -> PyResult<Aes256Gcm> {
        Aes256Gcm::new_from_slice(self.expose()?)
            .map_err(|_| PyValueError::new_err("invalid data-encryption key"))
    }
}

#[pymethods]
impl FileDek {
    /// Read the key at `path`, creating it (0600, O_EXCL) if it is absent.
    #[staticmethod]
    fn load_or_create(path: &str) -> PyResult<Self> {
        Ok(Self { key: Some(load_or_create_key(Path::new(path))?) })
    }

    /// AES-256-GCM seal under this key. Returns ciphertext || tag.
    fn seal<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self
            .cipher()?
            .encrypt(&nonce_from(nonce)?, Payload { msg: plaintext, aad })
            .map_err(|_| PyValueError::new_err("seal failed"))?;
        Ok(PyBytes::new(py, &ct))
    }

    /// AES-256-GCM open under this key. Raises on any failure, undifferentiated.
    fn open<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let pt = Zeroizing::new(
            self.cipher()?
                .decrypt(&nonce_from(nonce)?, Payload { msg: ciphertext, aad })
                .map_err(|_| PyValueError::new_err("open failed"))?,
        );
        Ok(PyBytes::new(py, &pt))
    }

    /// Drop the key now rather than when Python collects this object.
    fn zeroize(&mut self) {
        self.key = None;
    }

    #[getter]
    fn destroyed(&self) -> bool {
        self.key.is_none()
    }

    fn __repr__(&self) -> &'static str {
        "<FileDek [REDACTED]>"
    }
}

/// `create_sealed_identity`, under a Rust-held DEK.
#[pyfunction]
pub fn create_sealed_identity_under<'py>(
    py: Python<'py>,
    dek: PyRef<'py, FileDek>,
    key_id: u32,
) -> PyResult<(
    crate::key_handles::Ed448KeyHandle,
    crate::key_handles::X448KeyHandle,
    Bound<'py, PyBytes>,
)> {
    crate::identity::create_sealed_identity(py, dek.expose()?, key_id)
}

/// `unseal_identity`, under a Rust-held DEK.
#[pyfunction]
pub fn unseal_identity_under(
    blob: &[u8],
    dek: PyRef<'_, FileDek>,
    key_id: u32,
) -> PyResult<(crate::key_handles::Ed448KeyHandle, crate::key_handles::X448KeyHandle)> {
    crate::identity::unseal_identity(blob, dek.expose()?, key_id)
}

// ── SmpSecretStore ───────────────────────────────────────────────────────────

/// Current on-disk format: MAGIC || nonce(12) || AES-256-GCM(ct || tag).
const STORE_MAGIC: &[u8] = b"OTRV4SMP\x02";
const STORE_AAD: &[u8] = b"otrv4plus.smp-autorespond.v2";
/// The format `SMPAutoRespondStorage` wrote: salt(16) || nonce(12) || ct||tag,
/// key = Argon2id(seed, salt; t=3, m=64 MiB, p=4), AAD below, plaintext JSON.
const LEGACY_AAD: &[u8] = b"smp_secrets_v1";
const LEGACY_SALT_LEN: usize = 16;
const MAX_PEER_LEN: usize = 3071; // RFC 7622 bound on a JID
const MAX_SECRET_LEN: usize = 4096;

/// Parse the flat `{"peer":"secret",...}` object `json.dumps` produced.
///
/// Hand-written so each value is decoded straight into a zeroizing buffer; a
/// general JSON library would leave unescaped copies in memory it frees without
/// wiping. Anything outside that shape is refused.
fn parse_legacy_json(src: &[u8]) -> Option<Vec<(String, SecretVec)>> {
    fn skip_ws(s: &[u8], mut i: usize) -> usize {
        while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        i
    }
    fn hex4(s: &[u8], i: usize) -> Option<u32> {
        let h = s.get(i..i + 4)?;
        let text = std::str::from_utf8(h).ok()?;
        u32::from_str_radix(text, 16).ok()
    }
    fn push_char(out: &mut Zeroizing<Vec<u8>>, c: char) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        buf.zeroize();
    }
    /// Returns (decoded bytes, index after the closing quote).
    fn string(s: &[u8], mut i: usize) -> Option<(Zeroizing<Vec<u8>>, usize)> {
        if s.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        let mut out = Zeroizing::new(Vec::new());
        loop {
            let b = *s.get(i)?;
            match b {
                b'"' => return Some((out, i + 1)),
                b'\\' => {
                    let e = *s.get(i + 1)?;
                    i += 2;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = hex4(s, i)?;
                            i += 4;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if s.get(i) != Some(&b'\\') || s.get(i + 1) != Some(&b'u') {
                                    return None;
                                }
                                let lo = hex4(s, i + 2)?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                i += 6;
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            push_char(&mut out, char::from_u32(cp)?);
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None,
                _ => {
                    out.push(b);
                    i += 1;
                }
            }
        }
    }

    let mut entries = Vec::new();
    let mut i = skip_ws(src, 0);
    if src.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(src, i + 1);
    if src.get(i) == Some(&b'}') {
        return (skip_ws(src, i + 1) == src.len()).then_some(entries);
    }
    loop {
        let (k, next) = string(src, i)?;
        i = skip_ws(src, next);
        if src.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(src, i + 1);
        let (v, next) = string(src, i)?;
        let peer = String::from_utf8(k.to_vec()).ok()?;
        entries.push((peer, SecretVec::from_slice(&v)));
        i = skip_ws(src, next);
        match src.get(i) {
            Some(b',') => i = skip_ws(src, i + 1),
            Some(b'}') => {
                return (skip_ws(src, i + 1) == src.len()).then_some(entries);
            }
            _ => return None,
        }
    }
}

fn legacy_key(seed: &[u8], salt: &[u8]) -> Option<SecretBytes<KEY_LEN>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // The exact parameters argon2-cffi's hash_secret_raw was called with.
    let params = Params::new(65536, 3, 4, Some(KEY_LEN)).ok()?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(seed, salt, &mut out[..])
        .ok()?;
    Some(SecretBytes::new(*out))
}

/// Per-peer SMP auto-respond passphrases, held and persisted by Rust.
///
/// `path=None` is memory-only. With a path, the store is sealed at `path`
/// under a key derived from `.smp_seed` in the same directory (both 0600,
/// both created by Rust on first use).
#[pyclass(name = "SmpSecretStore", module = "otrv4_core")]
pub struct SmpSecretStore {
    path: Option<PathBuf>,
    seed_path: Option<PathBuf>,
    entries: BTreeMap<String, SecretVec>,
    legacy_unreadable: Option<String>,
    migrated: bool,
}

impl SmpSecretStore {
    fn store_key(&self) -> PyResult<SecretBytes<KEY_LEN>> {
        let seed_path = self
            .seed_path
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("memory-only store has no key"))?;
        let seed = load_or_create_key(seed_path)?;
        Ok(kdf_secret::<KEY_LEN>(usage::AT_REST_SMP_STORE, seed.expose_slice()))
    }

    fn load(&mut self) -> PyResult<()> {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };
        let blob = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(PyOSError::new_err(format!("store unreadable: {:?}", e.kind()))),
        };
        let parsed = if blob.starts_with(STORE_MAGIC) {
            self.open_current(&blob)
        } else {
            let r = self.open_legacy(&blob);
            if r.is_some() {
                self.migrated = true;
            }
            r
        };
        match parsed {
            Some(entries) => {
                self.entries = entries.into_iter().collect();
                if self.migrated {
                    // Rewrite in the current format now, so the legacy file --
                    // and its Python-era key derivation -- stops existing.
                    self.save()?;
                }
                Ok(())
            }
            None => {
                // Never overwrite what could not be read: move it aside and
                // say so. It may be a file the scrypt fallback wrote, which
                // this build cannot derive a key for.
                let aside = path.with_extension("unreadable");
                let _ = fs::rename(&path, &aside);
                self.legacy_unreadable = Some(aside.to_string_lossy().into_owned());
                Ok(())
            }
        }
    }

    fn open_current(&self, blob: &[u8]) -> Option<Vec<(String, SecretVec)>> {
        let body = &blob[STORE_MAGIC.len()..];
        if body.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let key = self.store_key().ok()?;
        let cipher = Aes256Gcm::new_from_slice(key.expose_slice()).ok()?;
        let nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().ok()?;
        let mut aad = STORE_MAGIC.to_vec();
        aad.extend_from_slice(STORE_AAD);
        let pt = Zeroizing::new(
            cipher
                .decrypt(&Nonce::from(nonce), Payload { msg: &body[NONCE_LEN..], aad: &aad })
                .ok()?,
        );
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < pt.len() {
            let pl = u16::from_be_bytes(pt.get(i..i + 2)?.try_into().ok()?) as usize;
            i += 2;
            let peer = String::from_utf8(pt.get(i..i + pl)?.to_vec()).ok()?;
            i += pl;
            let sl = u16::from_be_bytes(pt.get(i..i + 2)?.try_into().ok()?) as usize;
            i += 2;
            let secret = SecretVec::from_slice(pt.get(i..i + sl)?);
            i += sl;
            out.push((peer, secret));
        }
        Some(out)
    }

    fn open_legacy(&self, blob: &[u8]) -> Option<Vec<(String, SecretVec)>> {
        if blob.len() < LEGACY_SALT_LEN + NONCE_LEN + TAG_LEN {
            return None;
        }
        let seed = read_key_file(self.seed_path.as_ref()?).ok()??;
        let salt = &blob[..LEGACY_SALT_LEN];
        let nonce: [u8; NONCE_LEN] = blob[LEGACY_SALT_LEN..LEGACY_SALT_LEN + NONCE_LEN].try_into().ok()?;
        let key = legacy_key(seed.expose_slice(), salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.expose_slice()).ok()?;
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload { msg: &blob[LEGACY_SALT_LEN + NONCE_LEN..], aad: LEGACY_AAD },
                )
                .ok()?,
        );
        parse_legacy_json(&pt)
    }

    fn save(&self) -> PyResult<()> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };
        let mut pt = Zeroizing::new(Vec::new());
        for (peer, secret) in &self.entries {
            pt.extend_from_slice(&(peer.len() as u16).to_be_bytes());
            pt.extend_from_slice(peer.as_bytes());
            pt.extend_from_slice(&(secret.len() as u16).to_be_bytes());
            pt.extend_from_slice(secret.expose());
        }
        let key = self.store_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.expose_slice())
            .map_err(|_| PyValueError::new_err("invalid store key"))?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = STORE_MAGIC.to_vec();
        aad.extend_from_slice(STORE_AAD);
        let ct = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: pt.as_slice(), aad: &aad })
            .map_err(|_| PyValueError::new_err("store sealing failed"))?;
        let mut blob = Vec::with_capacity(STORE_MAGIC.len() + NONCE_LEN + ct.len());
        blob.extend_from_slice(STORE_MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        write_atomically(path, &blob)
            .map_err(|e| PyOSError::new_err(format!("store write failed: {:?}", e.kind())))
    }
}

#[pymethods]
impl SmpSecretStore {
    /// Open the store at `path`, or a memory-only store for `None`.
    ///
    /// A legacy (argon2-cffi era) file is migrated to the current format on
    /// open. One that cannot be read is moved aside, never overwritten;
    /// `legacy_unreadable` then names where it went.
    #[new]
    #[pyo3(signature = (path=None))]
    fn new(path: Option<String>) -> PyResult<Self> {
        let path = path.map(PathBuf::from);
        let seed_path = path.as_ref().map(|p| {
            p.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .join(".smp_seed")
        });
        let mut store = Self {
            path,
            seed_path,
            entries: BTreeMap::new(),
            legacy_unreadable: None,
            migrated: false,
        };
        store.load()?;
        Ok(store)
    }

    /// Store `secret` for `peer`. A `bytearray` is zeroed after the copy; a
    /// `str` cannot be, which is the caller's to know.
    fn set(&mut self, peer: &str, secret: &Bound<'_, PyAny>) -> PyResult<()> {
        if peer.is_empty() || peer.len() > MAX_PEER_LEN {
            return Err(PyValueError::new_err("invalid peer"));
        }
        let value = if let Ok(ba) = secret.cast::<PyByteArray>() {
            let copy = SecretVec::from_slice(&ba.to_vec());
            for i in 0..ba.len() {
                ba.set_item(i, 0u8)?;
            }
            copy
        } else if let Ok(s) = secret.cast::<PyString>() {
            // abi3 has no borrowed view of a str, so this extracts an owned
            // copy -- zeroized on drop, not left for the allocator.
            let owned: Zeroizing<String> = Zeroizing::new(s.extract::<String>()?);
            SecretVec::from_slice(owned.as_bytes())
        } else {
            return Err(PyValueError::new_err("secret must be str or bytearray"));
        };
        if value.is_empty() || value.len() > MAX_SECRET_LEN {
            return Err(PyValueError::new_err("secret length out of range"));
        }
        self.entries.insert(peer.to_string(), value);
        self.save()
    }

    fn has(&self, peer: &str) -> bool {
        self.entries.contains_key(peer)
    }

    fn remove(&mut self, peer: &str) -> PyResult<bool> {
        let had = self.entries.remove(peer).is_some();
        if had {
            self.save()?;
        }
        Ok(had)
    }

    fn peers(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    fn __len__(&self) -> usize {
        self.entries.len()
    }

    /// Copy `peer`'s passphrase into `vault` under `name`, Rust to Rust.
    /// Returns False when nothing is stored for `peer`.
    fn bind_into(&self, peer: &str, vault: &mut PySMPVault, name: &str) -> PyResult<bool> {
        match self.entries.get(peer) {
            Some(secret) => {
                vault
                    .store_internal(name, secret.expose())
                    .map_err(PyValueError::new_err)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Forget everything in memory. The file is left alone: deleting it is
    /// the caller's decision (Wipe & Exit destroys the directory).
    fn clear_memory(&mut self) {
        self.entries.clear();
    }

    /// Forget everything, in memory and on disk.
    fn clear(&mut self) -> PyResult<()> {
        self.entries.clear();
        self.save()
    }

    #[getter]
    fn legacy_unreadable(&self) -> Option<String> {
        self.legacy_unreadable.clone()
    }

    #[getter]
    fn migrated(&self) -> bool {
        self.migrated
    }

    #[getter]
    fn persistent(&self) -> bool {
        self.path.is_some()
    }

    fn __repr__(&self) -> String {
        format!("<SmpSecretStore peers={} [REDACTED]>", self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_json_round_trips_escapes_and_unicode() {
        let src = br#"{"alice@x":"p\u00e4ss \"q\" \\ \ud83d\ude00","b@y":"plain"}"#;
        let got = parse_legacy_json(src).expect("parses");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "alice@x");
        assert_eq!(got[0].1.expose(), "päss \"q\" \\ 😀".as_bytes());
        assert_eq!(got[1].1.expose(), b"plain");
    }

    #[test]
    fn legacy_json_empty_object() {
        assert_eq!(parse_legacy_json(b"{}").map(|v| v.len()), Some(0));
    }

    #[test]
    fn legacy_json_refuses_other_shapes() {
        for bad in [&b"[]"[..], b"{\"a\":1}", b"{\"a\":\"b\"} x", b"{\"a\" \"b\"}",
                    b"{\"a\":\"\\ud800\"}", b"{\"a\":\"b\",}", b"{\"a\":\"\x01\"}"] {
            assert!(parse_legacy_json(bad).is_none(), "{:?}", bad);
        }
    }
}
