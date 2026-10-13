// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The `.otrv` container: a file encrypted at rest, and for export.
//!
//! A received file used to rest as plaintext (0600) in app-private storage.
//! It now rests as a `.otrv` container sealed under a device key; opening it
//! decrypts in memory, and only an explicit Save or export writes plaintext.
//! A passphrase variant makes a portable, encrypted export that any build
//! of OTRv4Plus opens, on Android or Termux.
//!
//! FORMAT, version 1 (all integers big-endian)
//! ===========================================
//! ```text
//!   0  4  magic "OTRV"
//!   4  1  version = 1
//!   5  1  key source: 1 = device key (FileDek), 2 = passphrase (Argon2id)
//!   6  4  chunk size, bytes (1 KiB ..= 1 MiB)
//!  10  8  plaintext length, bytes
//!  18 16  salt (random per file)
//!  34  8  nonce prefix (random per file)
//!  42  4  Argon2id memory, KiB   (0 for a device key)
//!  46  4  Argon2id iterations    (0 for a device key)
//!  50  4  Argon2id parallelism   (0 for a device key)
//!  54  2  reserved, zero
//!  56  .. chunks
//! ```
//! Chunk `i` of `n = max(1, ceil(length / chunk size))` is AES-256-GCM of
//! that slice of the plaintext (the last may be short; a zero-length file is
//! one empty chunk), with
//!   nonce = prefix(8) || i (4)
//!   AAD   = header(56) || i (4) || final (1)
//! and its 16-byte tag appended.
//!
//! KEYS. Device: HKDF-SHA256(salt, DEK, "OTRv4Plus .otrv v1 device").
//! Passphrase: Argon2id(passphrase, salt, m, t, p) -> 32 bytes, then
//! HKDF-SHA256(salt, that, "OTRv4Plus .otrv v1 passphrase"). A fresh salt
//! per file means a fresh key per file, so nonces never repeat under a key.
//!
//! WHAT IS CHECKED ON OPEN, before any plaintext is released:
//!   * the header (magic, version, key source, bounds) -- and it is inside
//!     every chunk's AAD, so no field can be changed;
//!   * the file's exact length, from the header: truncation or extension
//!     refuses;
//!   * each chunk's index and final flag are authenticated, so chunks cannot
//!     be reordered, duplicated or dropped, and the last cannot be cut.
//!
//! `open_file` writes to a temporary file and renames only after the last
//! chunk authenticates; on any failure the partial output is removed.
//! Every failure is one undifferentiated error.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::at_rest::FileDek;

pub const MAGIC: &[u8; 4] = b"OTRV";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 56;
pub const TAG_LEN: usize = 16;
pub const SOURCE_DEVICE: u8 = 1;
pub const SOURCE_PASSPHRASE: u8 = 2;
pub const MIN_CHUNK: u32 = 1024;
pub const MAX_CHUNK: u32 = 1 << 20;
pub const DEFAULT_CHUNK: u32 = 64 * 1024;
/// Argon2id for exports: the parameters the core already uses for at-rest
/// keys (64 MiB, 3 passes, 4 lanes).
pub const ARGON_M: u32 = 65536;
pub const ARGON_T: u32 = 3;
pub const ARGON_P: u32 = 4;
/// What a container may ask of us when opened: a hostile file must not be
/// able to demand gigabytes of memory or an hour of CPU.
const ARGON_M_MAX: u32 = 1 << 20; // 1 GiB
const ARGON_T_MAX: u32 = 10;
const ARGON_P_MAX: u32 = 16;

const INFO_DEVICE: &[u8] = b"OTRv4Plus .otrv v1 device";
const INFO_PASSPHRASE: &[u8] = b"OTRv4Plus .otrv v1 passphrase";

#[derive(Debug, PartialEq, Eq)]
pub enum ContainerError {
    /// Anything wrong with the container or the key: one answer, on purpose.
    Refused,
    Io(String),
    TooLarge,
    BadArgument(&'static str),
}

type Result<T> = std::result::Result<T, ContainerError>;

fn io(e: std::io::Error) -> ContainerError {
    ContainerError::Io(format!("{:?}", e.kind()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub source: u8,
    pub chunk: u32,
    pub length: u64,
    salt: [u8; 16],
    prefix: [u8; 8],
    argon: (u32, u32, u32),
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(MAGIC);
        h[4] = VERSION;
        h[5] = self.source;
        h[6..10].copy_from_slice(&self.chunk.to_be_bytes());
        h[10..18].copy_from_slice(&self.length.to_be_bytes());
        h[18..34].copy_from_slice(&self.salt);
        h[34..42].copy_from_slice(&self.prefix);
        h[42..46].copy_from_slice(&self.argon.0.to_be_bytes());
        h[46..50].copy_from_slice(&self.argon.1.to_be_bytes());
        h[50..54].copy_from_slice(&self.argon.2.to_be_bytes());
        h
    }

    fn decode(h: &[u8]) -> Result<Self> {
        if h.len() != HEADER_LEN || &h[0..4] != MAGIC || h[4] != VERSION || h[54..56] != [0, 0] {
            return Err(ContainerError::Refused);
        }
        // Fixed offsets into a buffer whose length was checked above; the
        // conversions cannot fail, and refuse rather than panic if they did.
        fn at<const N: usize>(h: &[u8], i: usize) -> Result<[u8; N]> {
            h.get(i..i + N).and_then(|s| s.try_into().ok()).ok_or(ContainerError::Refused)
        }
        let u32_at = |i: usize| at::<4>(h, i).map(u32::from_be_bytes);
        let header = Header {
            source: h[5],
            chunk: u32_at(6)?,
            length: u64::from_be_bytes(at::<8>(h, 10)?),
            salt: at::<16>(h, 18)?,
            prefix: at::<8>(h, 34)?,
            argon: (u32_at(42)?, u32_at(46)?, u32_at(50)?),
        };
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&header.chunk) {
            return Err(ContainerError::Refused);
        }
        match header.source {
            SOURCE_DEVICE if header.argon == (0, 0, 0) => {}
            SOURCE_PASSPHRASE => {
                let (m, t, p) = header.argon;
                // p is bounded BEFORE it is used in arithmetic: the header is
                // unauthenticated, and with overflow-checks + panic=abort in
                // release, `8 * p` on p = 0xffff_ffff killed the process
                // (found by fuzz/container_header).
                if p == 0 || p > ARGON_P_MAX || t == 0 || t > ARGON_T_MAX
                    || m > ARGON_M_MAX || m < 8 * p
                {
                    return Err(ContainerError::Refused);
                }
            }
            _ => return Err(ContainerError::Refused),
        }
        Ok(header)
    }

    fn chunks(&self) -> u64 {
        if self.length == 0 { 1 } else { self.length.div_ceil(self.chunk as u64) }
    }

    /// The exact container size this header implies.
    fn container_len(&self) -> Option<u64> {
        self.length
            .checked_add(self.chunks().checked_mul(TAG_LEN as u64)?)?
            .checked_add(HEADER_LEN as u64)
    }
}

/// How a container's key is obtained.
pub enum KeySource<'a> {
    Device(&'a [u8]),
    Passphrase(&'a [u8]),
}

fn derive(header: &Header, key: &KeySource) -> Result<Zeroizing<[u8; 32]>> {
    let (ikm, info): (Zeroizing<Vec<u8>>, &[u8]) = match (key, header.source) {
        (KeySource::Device(dek), SOURCE_DEVICE) => {
            if dek.len() != 32 {
                return Err(ContainerError::BadArgument("device key must be 32 bytes"));
            }
            (Zeroizing::new(dek.to_vec()), INFO_DEVICE)
        }
        (KeySource::Passphrase(pw), SOURCE_PASSPHRASE) => {
            use argon2::{Algorithm, Argon2, Params, Version};
            let (m, t, p) = header.argon;
            let params = Params::new(m, t, p, Some(32)).map_err(|_| ContainerError::Refused)?;
            let mut out = Zeroizing::new(vec![0u8; 32]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(pw, &header.salt, &mut out)
                .map_err(|_| ContainerError::Refused)?;
            (out, INFO_PASSPHRASE)
        }
        // A device container offered a passphrase, or the reverse.
        _ => return Err(ContainerError::Refused),
    };
    let hk = Hkdf::<Sha256>::new(Some(&header.salt), &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut key[..]).map_err(|_| ContainerError::Refused)?;
    Ok(key)
}

fn nonce(prefix: &[u8; 8], i: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&i.to_be_bytes());
    n
}

fn aad(header: &[u8; HEADER_LEN], i: u32, last: bool) -> [u8; HEADER_LEN + 5] {
    let mut a = [0u8; HEADER_LEN + 5];
    a[..HEADER_LEN].copy_from_slice(header);
    a[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&i.to_be_bytes());
    a[HEADER_LEN + 4] = last as u8;
    a
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]).map_err(io)? {
            0 => break,
            n => off += n,
        }
    }
    Ok(off)
}

fn tmp_beside(dst: &Path) -> PathBuf {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    let name = format!(
        ".{}.{}.part",
        dst.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    dst.with_file_name(name)
}

fn create_private(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(io)
}

/// Seal `src` into a new container at `dst`, replacing `dst` if it exists.
pub fn seal_file(src: &Path, dst: &Path, key: &KeySource, chunk: u32) -> Result<()> {
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk) {
        return Err(ContainerError::BadArgument("chunk size out of range"));
    }
    let mut input = File::open(src).map_err(io)?;
    let length = input.metadata().map_err(io)?.len();
    let mut salt = [0u8; 16];
    let mut prefix = [0u8; 8];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut prefix);
    let header = Header {
        source: match key { KeySource::Device(_) => SOURCE_DEVICE, KeySource::Passphrase(_) => SOURCE_PASSPHRASE },
        chunk,
        length,
        salt,
        prefix,
        argon: match key { KeySource::Device(_) => (0, 0, 0), KeySource::Passphrase(_) => (ARGON_M, ARGON_T, ARGON_P) },
    };
    let n = header.chunks();
    if n > u32::MAX as u64 {
        return Err(ContainerError::TooLarge);
    }
    let hbytes = header.encode();
    let k = derive(&header, key)?;
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|_| ContainerError::Refused)?;

    let tmp = tmp_beside(dst);
    let result = (|| -> Result<()> {
        let mut out = create_private(&tmp)?;
        out.write_all(&hbytes).map_err(io)?;
        let mut buf = Zeroizing::new(vec![0u8; chunk as usize]);
        let mut remaining = length;
        for i in 0..n as u32 {
            let want = remaining.min(chunk as u64) as usize;
            let got = read_full(&mut input, &mut buf[..want])?;
            if got != want {
                // The source changed size while being sealed.
                return Err(ContainerError::Io("source changed while sealing".into()));
            }
            remaining -= want as u64;
            let last = i as u64 + 1 == n;
            let ct = cipher
                .encrypt(<&Nonce<_>>::from(&nonce(&prefix, i)[..]),
                         Payload { msg: &buf[..want], aad: &aad(&hbytes, i, last) })
                .map_err(|_| ContainerError::Refused)?;
            out.write_all(&ct).map_err(io)?;
        }
        out.sync_all().map_err(io)?;
        fs::rename(&tmp, dst).map_err(io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Decrypt a container, handing each authenticated chunk to `sink`. Nothing
/// is handed over until its chunk's tag verifies; the caller must still
/// discard what it received if this returns an error.
fn open_with(src: &Path, key: &KeySource, mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<Header> {
    let mut input = File::open(src).map_err(io)?;
    let actual = input.metadata().map_err(io)?.len();
    let mut hbytes = [0u8; HEADER_LEN];
    if read_full(&mut input, &mut hbytes)? != HEADER_LEN {
        return Err(ContainerError::Refused);
    }
    let header = Header::decode(&hbytes)?;
    if header.container_len() != Some(actual) {
        return Err(ContainerError::Refused);
    }
    let k = derive(&header, key)?;
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|_| ContainerError::Refused)?;
    let n = header.chunks();
    let mut remaining = header.length;
    let mut buf = vec![0u8; header.chunk as usize + TAG_LEN];
    for i in 0..n as u32 {
        let want = remaining.min(header.chunk as u64) as usize;
        if read_full(&mut input, &mut buf[..want + TAG_LEN])? != want + TAG_LEN {
            return Err(ContainerError::Refused);
        }
        let last = i as u64 + 1 == n;
        let pt = Zeroizing::new(
            cipher
                .decrypt(<&Nonce<_>>::from(&nonce(&header.prefix, i)[..]),
                         Payload { msg: &buf[..want + TAG_LEN], aad: &aad(&hbytes, i, last) })
                .map_err(|_| ContainerError::Refused)?,
        );
        remaining -= want as u64;
        sink(&pt)?;
    }
    Ok(header)
}

/// Decrypt to a plaintext file at `dst` (Save, import). Replaces `dst`.
pub fn open_file(src: &Path, dst: &Path, key: &KeySource) -> Result<u64> {
    let tmp = tmp_beside(dst);
    let result = (|| -> Result<u64> {
        let mut out = create_private(&tmp)?;
        let header = open_with(src, key, |pt| out.write_all(pt).map_err(io))?;
        out.sync_all().map_err(io)?;
        drop(out);
        fs::rename(&tmp, dst).map_err(io)?;
        Ok(header.length)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Decrypt into memory (Open). Refuses a container larger than `max_len`
/// before deriving any key.
pub fn open_bytes(src: &Path, key: &KeySource, max_len: u64) -> Result<Zeroizing<Vec<u8>>> {
    let header = info(src)?;
    // The header is not authenticated until a chunk verifies, so its length
    // is checked against the file's real size BEFORE it sizes anything. A
    // single flipped bit in the length once made this allocate 72 PB and
    // abort the process (found by `every_byte_flip_is_refused`).
    let actual = fs::metadata(src).map_err(io)?.len();
    if header.container_len() != Some(actual) {
        return Err(ContainerError::Refused);
    }
    if header.length > max_len {
        return Err(ContainerError::TooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(header.length as usize));
    open_with(src, key, |pt| {
        out.extend_from_slice(pt);
        Ok(())
    })?;
    Ok(out)
}

/// The header of a container, checked, without any key.
pub fn info(src: &Path) -> Result<Header> {
    let mut input = File::open(src).map_err(io)?;
    let mut hbytes = [0u8; HEADER_LEN];
    if read_full(&mut input, &mut hbytes)? != HEADER_LEN {
        return Err(ContainerError::Refused);
    }
    Header::decode(&hbytes)
}

// ── Python ──────────────────────────────────────────────────────────────────

fn py_err(e: ContainerError) -> PyErr {
    match e {
        ContainerError::Refused => PyValueError::new_err("otrv: container refused"),
        ContainerError::TooLarge => PyValueError::new_err("otrv: too large"),
        ContainerError::BadArgument(w) => PyValueError::new_err(format!("otrv: {w}")),
        ContainerError::Io(k) => PyOSError::new_err(format!("otrv: io {k}")),
    }
}

/// Seal a file under this device's key (at rest). Replaces `dst`.
#[pyfunction]
#[pyo3(signature = (dek, src, dst, chunk_size=DEFAULT_CHUNK))]
pub fn otrv_seal_file(py: Python<'_>, dek: PyRef<'_, FileDek>, src: &str, dst: &str,
                      chunk_size: u32) -> PyResult<()> {
    let key = Zeroizing::new(dek.expose()?.to_vec());
    py.detach(|| seal_file(Path::new(src), Path::new(dst), &KeySource::Device(&key), chunk_size))
        .map_err(py_err)
}

/// Decrypt a device-key container to a plaintext file (explicit Save).
#[pyfunction]
pub fn otrv_open_file(py: Python<'_>, dek: PyRef<'_, FileDek>, src: &str, dst: &str) -> PyResult<u64> {
    let key = Zeroizing::new(dek.expose()?.to_vec());
    py.detach(|| open_file(Path::new(src), Path::new(dst), &KeySource::Device(&key)))
        .map_err(py_err)
}

/// Decrypt a device-key container into memory (Open). No plaintext file.
#[pyfunction]
pub fn otrv_open_bytes<'py>(py: Python<'py>, dek: PyRef<'_, FileDek>, src: &str,
                            max_len: u64) -> PyResult<Bound<'py, PyBytes>> {
    let key = Zeroizing::new(dek.expose()?.to_vec());
    let pt = py
        .detach(|| open_bytes(Path::new(src), &KeySource::Device(&key), max_len))
        .map_err(py_err)?;
    Ok(PyBytes::new(py, &pt))
}

/// Seal a file under a passphrase: a portable encrypted export.
#[pyfunction]
#[pyo3(signature = (passphrase, src, dst, chunk_size=DEFAULT_CHUNK))]
pub fn otrv_export_file(py: Python<'_>, passphrase: &[u8], src: &str, dst: &str,
                        chunk_size: u32) -> PyResult<()> {
    if passphrase.len() < 8 {
        return Err(PyValueError::new_err("otrv: passphrase must be at least 8 bytes"));
    }
    let pw = Zeroizing::new(passphrase.to_vec());
    py.detach(|| seal_file(Path::new(src), Path::new(dst), &KeySource::Passphrase(&pw), chunk_size))
        .map_err(py_err)
}

/// Open a passphrase container to a plaintext file (import).
#[pyfunction]
pub fn otrv_import_file(py: Python<'_>, passphrase: &[u8], src: &str, dst: &str) -> PyResult<u64> {
    let pw = Zeroizing::new(passphrase.to_vec());
    py.detach(|| open_file(Path::new(src), Path::new(dst), &KeySource::Passphrase(&pw)))
        .map_err(py_err)
}

/// A container's public header: version, key source, plaintext length.
#[pyfunction]
pub fn otrv_info<'py>(py: Python<'py>, src: &str) -> PyResult<Bound<'py, PyDict>> {
    let h = info(Path::new(src)).map_err(py_err)?;
    let d = PyDict::new(py);
    d.set_item("version", VERSION)?;
    d.set_item("key_source", match h.source { SOURCE_DEVICE => "device", _ => "passphrase" })?;
    d.set_item("length", h.length)?;
    d.set_item("chunk_size", h.chunk)?;
    Ok(d)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(otrv_seal_file, m)?)?;
    m.add_function(wrap_pyfunction!(otrv_open_file, m)?)?;
    m.add_function(wrap_pyfunction!(otrv_open_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(otrv_export_file, m)?)?;
    m.add_function(wrap_pyfunction!(otrv_import_file, m)?)?;
    m.add_function(wrap_pyfunction!(otrv_info, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Regression (fuzz/container_header crash-c06dcdab): a passphrase
    /// header with lanes p = 0xffffffff overflowed `8 * p` before p was
    /// bounded. With panic = "abort" that was a process kill on `info`.
    #[test]
    fn a_huge_lane_count_is_refused_not_an_overflow() {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(MAGIC);
        h[4] = VERSION;
        h[5] = SOURCE_PASSPHRASE;
        h[6..10].copy_from_slice(&DEFAULT_CHUNK.to_be_bytes());
        h[42..46].copy_from_slice(&ARGON_M.to_be_bytes());
        h[46..50].copy_from_slice(&ARGON_T.to_be_bytes());
        for p in [u32::MAX, u32::MAX / 8 + 1, ARGON_P_MAX + 1, 0] {
            h[50..54].copy_from_slice(&p.to_be_bytes());
            assert_eq!(Header::decode(&h), Err(ContainerError::Refused), "p={p}");
        }
        h[50..54].copy_from_slice(&ARGON_P.to_be_bytes());
        assert!(Header::decode(&h).is_ok());
    }

    use super::*;

    fn tmpdir() -> PathBuf {
        let mut r = [0u8; 8];
        OsRng.fill_bytes(&mut r);
        let d = std::env::temp_dir().join(format!("otrv-test-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    const K: [u8; 32] = [9u8; 32];

    fn roundtrip(len: usize, chunk: u32) {
        let d = tmpdir();
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        fs::write(d.join("in"), &data).unwrap();
        seal_file(&d.join("in"), &d.join("c.otrv"), &KeySource::Device(&K), chunk).unwrap();
        let c = fs::read(d.join("c.otrv")).unwrap();
        assert!(len < 16 || !c.windows(16).any(|w| w == &data[..16]), "plaintext in container");
        assert_eq!(open_bytes(&d.join("c.otrv"), &KeySource::Device(&K), u64::MAX).unwrap().as_slice(), &data[..]);
        open_file(&d.join("c.otrv"), &d.join("out"), &KeySource::Device(&K)).unwrap();
        assert_eq!(fs::read(d.join("out")).unwrap(), data);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn round_trips_every_shape() {
        for (len, chunk) in [(0, 1024), (1, 1024), (1023, 1024), (1024, 1024), (1025, 1024),
                             (5000, 1024), (200_000, 65536), (1 << 20, 1 << 20)] {
            roundtrip(len, chunk);
        }
    }

    fn sealed(len: usize) -> (PathBuf, Vec<u8>) {
        let d = tmpdir();
        fs::write(d.join("in"), vec![7u8; len]).unwrap();
        seal_file(&d.join("in"), &d.join("c.otrv"), &KeySource::Device(&K), 1024).unwrap();
        let bytes = fs::read(d.join("c.otrv")).unwrap();
        (d, bytes)
    }

    fn refused(d: &Path, bytes: &[u8]) -> bool {
        fs::write(d.join("bad.otrv"), bytes).unwrap();
        let r = open_bytes(&d.join("bad.otrv"), &KeySource::Device(&K), u64::MAX).is_err();
        let f = open_file(&d.join("bad.otrv"), &d.join("bad.out"), &KeySource::Device(&K)).is_err();
        assert!(!d.join("bad.out").exists(), "a partial plaintext file was left behind");
        r && f
    }

    #[test]
    fn every_byte_flip_is_refused() {
        let (d, c) = sealed(3000);
        for i in (0..c.len()).filter(|i| i % 37 == 0).chain([0, 4, 5, 6, 10, 18, 34, 54, c.len() - 1]) {
            let mut b = c.clone();
            b[i] ^= 0x01;
            assert!(refused(&d, &b), "flip at {i} accepted");
        }
    }

    #[test]
    fn truncation_extension_reorder_duplication_are_refused() {
        let (d, c) = sealed(3000); // 3 chunks of 1024+16 after the header
        let cs = 1024 + TAG_LEN;
        let (h, body) = c.split_at(HEADER_LEN);
        assert!(refused(&d, &c[..c.len() - 1]));
        assert!(refused(&d, &c[..HEADER_LEN + cs]));
        let mut longer = c.clone();
        longer.push(0);
        assert!(refused(&d, &longer));
        // swap chunk 0 and 1
        let mut swapped = h.to_vec();
        swapped.extend_from_slice(&body[cs..2 * cs]);
        swapped.extend_from_slice(&body[..cs]);
        swapped.extend_from_slice(&body[2 * cs..]);
        assert!(refused(&d, &swapped));
        // duplicate chunk 0 in place of chunk 1
        let mut dup = h.to_vec();
        dup.extend_from_slice(&body[..cs]);
        dup.extend_from_slice(&body[..cs]);
        dup.extend_from_slice(&body[2 * cs..]);
        assert!(refused(&d, &dup));
    }

    #[test]
    fn a_wrong_key_or_the_other_key_source_is_refused() {
        let (d, c) = sealed(100);
        fs::write(d.join("c2.otrv"), &c).unwrap();
        assert!(open_bytes(&d.join("c2.otrv"), &KeySource::Device(&[8u8; 32]), u64::MAX).is_err());
        assert!(open_bytes(&d.join("c2.otrv"), &KeySource::Passphrase(b"a passphrase"), u64::MAX).is_err());
    }

    #[test]
    fn passphrase_export_round_trips_and_refuses_the_wrong_one() {
        let d = tmpdir();
        fs::write(d.join("in"), b"portable secret").unwrap();
        seal_file(&d.join("in"), &d.join("e.otrv"), &KeySource::Passphrase(b"correct horse"), 1024).unwrap();
        assert_eq!(info(&d.join("e.otrv")).unwrap().source, SOURCE_PASSPHRASE);
        assert!(open_file(&d.join("e.otrv"), &d.join("o"), &KeySource::Passphrase(b"wrong horse")).is_err());
        open_file(&d.join("e.otrv"), &d.join("o"), &KeySource::Passphrase(b"correct horse")).unwrap();
        assert_eq!(fs::read(d.join("o")).unwrap(), b"portable secret");
        assert!(open_file(&d.join("e.otrv"), &d.join("o2"), &KeySource::Device(&K)).is_err());
    }

    #[test]
    fn a_hostile_header_cannot_demand_resources() {
        let (d, mut c) = sealed(10);
        c[5] = SOURCE_PASSPHRASE;
        c[42..46].copy_from_slice(&u32::MAX.to_be_bytes());
        c[46..50].copy_from_slice(&1u32.to_be_bytes());
        c[50..54].copy_from_slice(&1u32.to_be_bytes());
        fs::write(d.join("h.otrv"), &c).unwrap();
        assert_eq!(info(&d.join("h.otrv")), Err(ContainerError::Refused));
        let (d2, mut c2) = sealed(10);
        c2[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(d2.join("h.otrv"), &c2).unwrap();
        assert_eq!(info(&d2.join("h.otrv")), Err(ContainerError::Refused));
    }

    #[test]
    fn open_bytes_refuses_before_decrypting_when_too_large() {
        let (d, _) = sealed(5000);
        assert_eq!(open_bytes(&d.join("c.otrv"), &KeySource::Device(&K), 4999),
                   Err(ContainerError::TooLarge));
    }

    #[test]
    fn sealing_replaces_an_existing_destination() {
        let d = tmpdir();
        fs::write(d.join("a"), b"first").unwrap();
        fs::write(d.join("b"), b"second").unwrap();
        seal_file(&d.join("a"), &d.join("x.otrv"), &KeySource::Device(&K), 1024).unwrap();
        seal_file(&d.join("b"), &d.join("x.otrv"), &KeySource::Device(&K), 1024).unwrap();
        assert_eq!(open_bytes(&d.join("x.otrv"), &KeySource::Device(&K), 100).unwrap().as_slice(), b"second");
        let leftovers: Vec<_> = fs::read_dir(&d).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part")).collect();
        assert!(leftovers.is_empty());
    }
}
