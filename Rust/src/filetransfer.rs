//! Rust-owned file-transfer cryptography for `/sendfile` (XMPP only).
//!
//! WHAT THIS IS FOR
//! ================
//! Python drives the transfer -- reads the file, pumps bytes over the OTR
//! channel, draws the progress bar -- and never holds a key.  Everything on
//! the secret side of that line lives here:
//!
//!   * the per-transfer FileKey, generated here, `SecretBytes<32>`, no getter;
//!   * the wrapping key, derived from the session's DAKE extra symmetric key,
//!     never materialised outside this module;
//!   * the chunk AEAD, so a chunk crosses the boundary already sealed.
//!
//! Python receives handles, opaque envelope bytes and ciphertext.  There is no
//! accessor for any of it, and adding one would defeat the module.
//!
//! WHY NOT `aead.rs`
//! =================
//! `aes256gcm_encrypt` takes the key as a parameter, because it was written to
//! replace `cryptography.AESGCM` in the storage classes, where Python already
//! held the key.  Using it here would mean the FileKey crossing the FFI on
//! every chunk, which is the one thing this module exists to prevent.  Both
//! call the same `aes-gcm` crate; the difference is who owns the key.
//!
//! The shape follows `voice.rs`, which solved the same problem for media keys
//! at v10.13.2.
//!
//! WHY NO SECOND ML-KEM EXCHANGE
//! =============================
//! The double ratchet's brace key already folds ML-KEM-1024 shared secrets, so
//! the session this transfer belongs to is already post-quantum protected and
//! already authenticated by the DAKE.  The extra symmetric key is derived from
//! that same DAKE.  Running a second KEM to reach a security level the session
//! already has would add a handshake, a transcript and a failure mode for no
//! gain -- and would be the second cryptographic system this project has
//! repeatedly refused to build.
//!
//! WHY THE EXTRA SYMMETRIC KEY AND NOT A CHAIN KEY
//! ===============================================
//! A transfer must survive the session ratcheting forward while it is in
//! flight.  Root and chain keys advance; the extra symmetric key does not.  It
//! is also what OTRv4 reserves for out-of-band uses exactly like this one.
//!
//! NONCE DISCIPLINE
//! ================
//! The FileKey is fresh per transfer and never reused, and the chunk nonce is
//! a pure function of the chunk index.  A (key, nonce) pair therefore cannot
//! repeat within a transfer, and cannot repeat across transfers because the
//! key differs.  The sender refuses to seal the same index twice, so a caller
//! bug cannot produce a repeat either.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::{PyValueError, PyRuntimeError};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::secure_mem::SecretBytes;

/// Wire version for the encrypted-file format.  Bump on any change to the
/// chunk framing, the AAD construction or the envelope layout.
pub const FILE_FORMAT_VERSION: u8 = 1;

/// Domain separator.  Fixed by the specification this was built to; it is a
/// constant of the wire format, so it does not track the client version.
const FT_DOMAIN: &[u8] = b"OTRv4Plus_FileTransfer_v2\x00";

/// Transfer ids are fixed-width so length never needs encoding alongside them.
pub const TRANSFER_ID_LEN: usize = 16;

const KEY_LEN:   usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN:   usize = 16;

/// Sealed key envelope: nonce ‖ wrapped FileKey ‖ tag.
pub const ENVELOPE_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// The largest plaintext chunk a sender will accept.  64 KiB keeps peak
/// memory bounded regardless of file size -- a 1 GB file is 16384 chunks, not
/// 1 GB of RAM -- while staying large enough that per-chunk overhead is noise.
pub const MAX_CHUNK_PLAIN_LEN: usize = 64 * 1024;

/// Refuse absurd indices long before they can overflow anything.
const MAX_CHUNK_INDEX: u64 = 1 << 40;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Length-prefixed append, 4-byte big-endian.
///
/// FOUR bytes, not eight.  The voice module's first Rust draft used a u64 here
/// and every cross-implementation frame failed its tag with no error and no
/// clue -- just silence.  Any transcript this project builds uses the same
/// 4-byte rule; keep it.
fn lp(value: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
    if value.len() > u32::MAX as usize {
        return Err("transcript field too long");
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Per-chunk nonce: 4 zero bytes ‖ chunk index (u64 big-endian).
///
/// Deterministic rather than random, which is the safer choice here: with a
/// fresh key per transfer, a counter cannot collide, whereas 96-bit random
/// nonces have a birthday bound that a large file could approach.
fn chunk_nonce(index: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

/// Authenticated associated data for one chunk.
///
/// Binds the format version, the transfer, the chunk's position in it, and
/// whether it is the last one.  A chunk therefore cannot be moved to another
/// index, replayed into another transfer, or presented as the final chunk to
/// truncate a file -- each of those changes the AAD and fails the tag.
fn chunk_aad(transfer_id: &[u8; TRANSFER_ID_LEN], index: u64, is_final: bool)
    -> Result<Vec<u8>, &'static str>
{
    let mut aad = Vec::with_capacity(FT_DOMAIN.len() + 64);
    aad.extend_from_slice(FT_DOMAIN);
    aad.push(FILE_FORMAT_VERSION);
    lp(transfer_id, &mut aad)?;
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    Ok(aad)
}

/// AAD for the key envelope.  Separate from the chunk AAD by construction --
/// it carries a different tag byte -- so an envelope can never be accepted as
/// a chunk or the reverse.
fn envelope_aad(transfer_id: &[u8; TRANSFER_ID_LEN]) -> Result<Vec<u8>, &'static str> {
    let mut aad = Vec::with_capacity(FT_DOMAIN.len() + 32);
    aad.extend_from_slice(FT_DOMAIN);
    aad.push(FILE_FORMAT_VERSION);
    aad.extend_from_slice(b"envelope");
    lp(transfer_id, &mut aad)?;
    Ok(aad)
}

pub(crate) fn transfer_id_from(raw: &[u8]) -> PyResult<[u8; TRANSFER_ID_LEN]> {
    if raw.len() != TRANSFER_ID_LEN {
        return Err(PyValueError::new_err(format!(
            "transfer id must be {TRANSFER_ID_LEN} bytes, got {}", raw.len()
        )));
    }
    let mut id = [0u8; TRANSFER_ID_LEN];
    id.copy_from_slice(raw);
    Ok(id)
}

fn cipher_for(key: &SecretBytes<32>) -> PyResult<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key.expose_slice())
        .map_err(|_| PyRuntimeError::new_err("file transfer: invalid key length"))
}

/// Derive the transfer wrapping key from the session's extra symmetric key.
///
/// Domain-separated by usage id AND by the transcript, and bound to the
/// transfer id, so two transfers in one session never share a wrapping key.
pub(crate) fn derive_wrap_key(
    extra_sym_key: &SecretBytes<32>,
    transfer_id: &[u8; TRANSFER_ID_LEN],
) -> PyResult<SecretBytes<32>> {
    let mut transcript = Vec::with_capacity(FT_DOMAIN.len() + 64);
    transcript.extend_from_slice(FT_DOMAIN);
    transcript.push(FILE_FORMAT_VERSION);
    lp(extra_sym_key.expose_slice(), &mut transcript)
        .map_err(PyValueError::new_err)?;
    lp(transfer_id, &mut transcript).map_err(PyValueError::new_err)?;
    let key = crate::kdf::kdf_secret::<32>(
        crate::kdf::usage::FILE_TRANSFER_WRAP, &transcript);
    transcript.zeroize();
    Ok(key)
}

// ---------------------------------------------------------------------------
// sender
// ---------------------------------------------------------------------------

/// Seals one file for one transfer.  Owns the FileKey; Python cannot read it.
#[pyclass(name = "RustFileSender")]
pub struct PyFileSender {
    file_key:    SecretBytes<32>,
    transfer_id: [u8; TRANSFER_ID_LEN],
    envelope:    Vec<u8>,
    /// Next index the caller is allowed to seal.  Strictly increasing, so the
    /// same (key, nonce) pair cannot be produced twice even by a caller bug.
    next_index:  u64,
    finished:    bool,
    zeroized:    bool,
    plain_hash:  Sha256,
    cipher_hash: Sha256,
    plain_len:   u64,
    cipher_len:  u64,
}

impl PyFileSender {
    pub(crate) fn create(
        extra_sym_key: &SecretBytes<32>,
        transfer_id: [u8; TRANSFER_ID_LEN],
    ) -> PyResult<Self> {
        // Fresh FileKey per transfer, straight from the OS RNG.  Never
        // derived from the session, so a compromised session key does not
        // retrospectively yield the file key of a completed transfer beyond
        // what the envelope already gives.
        let mut raw = [0u8; KEY_LEN];
        getrandom::getrandom(&mut raw)
            .map_err(|_| PyRuntimeError::new_err(
                "file transfer: system RNG unavailable"))?;
        let file_key = SecretBytes::<32>::new(raw);
        raw.zeroize();

        let wrap = derive_wrap_key(extra_sym_key, &transfer_id)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| PyRuntimeError::new_err(
                "file transfer: system RNG unavailable"))?;
        let aad = envelope_aad(&transfer_id).map_err(PyValueError::new_err)?;
        let sealed = cipher_for(&wrap)?
            .encrypt(Nonce::from_slice(&nonce),
                     Payload { msg: file_key.expose_slice(), aad: &aad })
            .map_err(|_| PyRuntimeError::new_err(
                "file transfer: could not seal the key envelope"))?;

        let mut envelope = Vec::with_capacity(ENVELOPE_LEN);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&sealed);

        Ok(Self {
            file_key,
            transfer_id,
            envelope,
            next_index: 0,
            finished: false,
            zeroized: false,
            plain_hash: Sha256::new(),
            cipher_hash: Sha256::new(),
            plain_len: 0,
            cipher_len: 0,
        })
    }
}

#[pymethods]
impl PyFileSender {
    /// The sealed key envelope, to travel in the authenticated offer.
    ///
    /// This is wrapped key material, not the FileKey.  Opening it needs the
    /// wrapping key, which needs the peer's own copy of the session's extra
    /// symmetric key -- so only the peer this session was established with
    /// can use it, even if the offer leaked.
    #[getter]
    fn envelope<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.envelope)
    }

    #[getter] fn transfer_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.transfer_id)
    }
    #[getter] fn next_index(&self) -> u64 { self.next_index }
    #[getter] fn plaintext_len(&self) -> u64 { self.plain_len }
    #[getter] fn ciphertext_len(&self) -> u64 { self.cipher_len }
    #[getter] fn finished(&self) -> bool { self.finished }
    #[getter] fn zeroized(&self) -> bool { self.zeroized }
    #[getter] fn format_version(&self) -> u8 { FILE_FORMAT_VERSION }

    /// Seal one chunk.  Chunks must be sealed in order, starting at 0.
    ///
    /// `is_final` is authenticated, so a truncation attack -- delivering the
    /// first N chunks and stopping -- cannot pass verification: the receiver
    /// never sees a chunk claiming to be last.
    fn seal_chunk<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
        is_final: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if self.zeroized {
            return Err(PyRuntimeError::new_err("file sender already zeroized"));
        }
        if self.finished {
            return Err(PyRuntimeError::new_err(
                "the final chunk has already been sealed"));
        }
        if plaintext.len() > MAX_CHUNK_PLAIN_LEN {
            return Err(PyValueError::new_err(format!(
                "chunk is {} bytes; the maximum is {MAX_CHUNK_PLAIN_LEN}",
                plaintext.len()
            )));
        }
        if self.next_index >= MAX_CHUNK_INDEX {
            return Err(PyValueError::new_err("too many chunks"));
        }

        let index = self.next_index;
        let aad = chunk_aad(&self.transfer_id, index, is_final)
            .map_err(PyValueError::new_err)?;
        let sealed = cipher_for(&self.file_key)?
            .encrypt(Nonce::from_slice(&chunk_nonce(index)),
                     Payload { msg: plaintext, aad: &aad })
            .map_err(|_| PyRuntimeError::new_err(
                "file transfer: chunk encryption failed"))?;

        self.plain_hash.update(plaintext);
        self.cipher_hash.update(&sealed);
        // Checked: a caller cannot drive these to wrap.
        self.plain_len = self.plain_len
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| PyValueError::new_err("plaintext length overflow"))?;
        self.cipher_len = self.cipher_len
            .checked_add(sealed.len() as u64)
            .ok_or_else(|| PyValueError::new_err("ciphertext length overflow"))?;
        self.next_index = index + 1;
        if is_final {
            self.finished = true;
        }
        Ok(PyBytes::new(py, &sealed))
    }

    /// SHA-256 over every plaintext chunk sealed so far.
    fn plaintext_sha256<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.plain_hash.clone().finalize())
    }

    /// SHA-256 over every sealed chunk, in order.  Goes in the offer so the
    /// receiver can reject a corrupted or substituted body before decrypting.
    fn ciphertext_sha256<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.cipher_hash.clone().finalize())
    }

    /// Destroy the FileKey.  Called when the transfer completes, is cancelled
    /// or fails; also runs on drop, so a forgotten call is not a leak.
    fn zeroize(&mut self) {
        self.file_key = SecretBytes::<32>::zeroed();
        self.envelope.zeroize();
        self.zeroized = true;
    }
}

// ---------------------------------------------------------------------------
// receiver
// ---------------------------------------------------------------------------

/// Opens one incoming file.  Owns the unwrapped FileKey.
#[pyclass(name = "RustFileReceiver")]
pub struct PyFileReceiver {
    file_key:    SecretBytes<32>,
    transfer_id: [u8; TRANSFER_ID_LEN],
    next_index:  u64,
    finished:    bool,
    zeroized:    bool,
    plain_hash:  Sha256,
    cipher_hash: Sha256,
    plain_len:   u64,
    cipher_len:  u64,
}

impl PyFileReceiver {
    pub(crate) fn create(
        extra_sym_key: &SecretBytes<32>,
        transfer_id: [u8; TRANSFER_ID_LEN],
        envelope: &[u8],
    ) -> PyResult<Self> {
        if envelope.len() != ENVELOPE_LEN {
            return Err(PyValueError::new_err(format!(
                "key envelope must be {ENVELOPE_LEN} bytes, got {}",
                envelope.len()
            )));
        }
        let wrap = derive_wrap_key(extra_sym_key, &transfer_id)?;
        let aad = envelope_aad(&transfer_id).map_err(PyValueError::new_err)?;
        // Fails if the envelope was made for another transfer id, another
        // session, or tampered with -- all three change the tag.
        let mut opened = cipher_for(&wrap)?
            .decrypt(Nonce::from_slice(&envelope[..NONCE_LEN]),
                     Payload { msg: &envelope[NONCE_LEN..], aad: &aad })
            .map_err(|_| PyValueError::new_err(
                "key envelope failed authentication (wrong session, wrong \
                 transfer id, or tampered offer)"))?;
        if opened.len() != KEY_LEN {
            opened.zeroize();
            return Err(PyValueError::new_err("key envelope had the wrong size"));
        }
        let file_key = SecretBytes::<32>::from_slice(&opened)
            .ok_or_else(|| PyValueError::new_err("key envelope had the wrong size"))?;
        opened.zeroize();

        Ok(Self {
            file_key,
            transfer_id,
            next_index: 0,
            finished: false,
            zeroized: false,
            plain_hash: Sha256::new(),
            cipher_hash: Sha256::new(),
            plain_len: 0,
            cipher_len: 0,
        })
    }
}

#[pymethods]
impl PyFileReceiver {
    #[getter] fn transfer_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.transfer_id)
    }
    #[getter] fn next_index(&self) -> u64 { self.next_index }
    #[getter] fn plaintext_len(&self) -> u64 { self.plain_len }
    #[getter] fn ciphertext_len(&self) -> u64 { self.cipher_len }
    #[getter] fn finished(&self) -> bool { self.finished }
    #[getter] fn zeroized(&self) -> bool { self.zeroized }

    /// Authenticate and open one chunk.  Chunks must arrive in order.
    ///
    /// Nothing commits until the tag verifies: a forged chunk cannot advance
    /// the index or contribute to either hash.
    fn open_chunk<'py>(
        &mut self,
        py: Python<'py>,
        sealed: &[u8],
        is_final: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if self.zeroized {
            return Err(PyRuntimeError::new_err("file receiver already zeroized"));
        }
        if self.finished {
            return Err(PyRuntimeError::new_err(
                "the final chunk has already been opened"));
        }
        if sealed.len() < TAG_LEN {
            return Err(PyValueError::new_err("chunk is shorter than its tag"));
        }
        if sealed.len() > MAX_CHUNK_PLAIN_LEN + TAG_LEN {
            return Err(PyValueError::new_err("chunk is larger than the maximum"));
        }
        if self.next_index >= MAX_CHUNK_INDEX {
            return Err(PyValueError::new_err("too many chunks"));
        }

        let index = self.next_index;
        let aad = chunk_aad(&self.transfer_id, index, is_final)
            .map_err(PyValueError::new_err)?;
        let plaintext = cipher_for(&self.file_key)?
            .decrypt(Nonce::from_slice(&chunk_nonce(index)),
                     Payload { msg: sealed, aad: &aad })
            .map_err(|_| PyValueError::new_err(
                "chunk failed authentication"))?;

        self.plain_hash.update(&plaintext);
        self.cipher_hash.update(sealed);
        self.plain_len = self.plain_len
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| PyValueError::new_err("plaintext length overflow"))?;
        self.cipher_len = self.cipher_len
            .checked_add(sealed.len() as u64)
            .ok_or_else(|| PyValueError::new_err("ciphertext length overflow"))?;
        self.next_index = index + 1;
        if is_final {
            self.finished = true;
        }
        Ok(PyBytes::new(py, &plaintext))
    }

    fn plaintext_sha256<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.plain_hash.clone().finalize())
    }
    fn ciphertext_sha256<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.cipher_hash.clone().finalize())
    }

    fn zeroize(&mut self) {
        self.file_key = SecretBytes::<32>::zeroed();
        self.zeroized = true;
    }
}

// ---------------------------------------------------------------------------
// standalone helpers Python needs and must not reimplement
// ---------------------------------------------------------------------------

/// A fresh transfer id.  Here rather than in Python so there is exactly one
/// source of randomness for this feature.
#[pyfunction]
pub fn file_transfer_new_id<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    let mut id = [0u8; TRANSFER_ID_LEN];
    getrandom::getrandom(&mut id)
        .map_err(|_| PyRuntimeError::new_err("file transfer: system RNG unavailable"))?;
    Ok(PyBytes::new(py, &id))
}

/// The sealed size a plaintext of `plain_len` will occupy, and its chunk
/// count.  The offer states both before a byte is sent, and the receiver
/// checks what arrives against them.
#[pyfunction]
pub fn file_transfer_sizes(plain_len: u64) -> PyResult<(u64, u64)> {
    let chunk = MAX_CHUNK_PLAIN_LEN as u64;
    // An empty file is still one chunk: it carries the final flag, and a
    // transfer with no chunks at all could not be authenticated as complete.
    let chunks = if plain_len == 0 { 1 } else { plain_len.div_ceil(chunk) };
    let sealed = plain_len
        .checked_add(chunks.checked_mul(TAG_LEN as u64).ok_or_else(
            || PyValueError::new_err("file too large"))?)
        .ok_or_else(|| PyValueError::new_err("file too large"))?;
    Ok((sealed, chunks))
}

#[pyfunction]
pub fn file_transfer_chunk_len() -> usize { MAX_CHUNK_PLAIN_LEN }

#[pyfunction]
pub fn file_transfer_format_version() -> u8 { FILE_FORMAT_VERSION }

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn esk(b: u8) -> SecretBytes<32> { SecretBytes::<32>::new([b; 32]) }
    fn tid(b: u8) -> [u8; TRANSFER_ID_LEN] { [b; TRANSFER_ID_LEN] }

    #[test]
    fn the_wrap_key_depends_on_the_session() {
        let a = derive_wrap_key(&esk(1), &tid(9)).expect("derive");
        let b = derive_wrap_key(&esk(2), &tid(9)).expect("derive");
        assert_ne!(a.expose_slice(), b.expose_slice());
    }

    #[test]
    fn the_wrap_key_depends_on_the_transfer() {
        let a = derive_wrap_key(&esk(1), &tid(9)).expect("derive");
        let b = derive_wrap_key(&esk(1), &tid(8)).expect("derive");
        assert_ne!(a.expose_slice(), b.expose_slice(),
            "two transfers in one session share a wrapping key");
    }

    #[test]
    fn chunk_nonces_are_unique_per_index() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..10_000u64 {
            assert!(seen.insert(chunk_nonce(i)), "nonce repeated at index {i}");
        }
    }

    #[test]
    fn the_final_flag_changes_the_aad() {
        let open  = chunk_aad(&tid(3), 7, false).expect("aad");
        let close = chunk_aad(&tid(3), 7, true).expect("aad");
        assert_ne!(open, close,
            "a truncation attack would pass: the last chunk is not \
             distinguishable from a middle one");
    }

    #[test]
    fn the_index_changes_the_aad() {
        assert_ne!(chunk_aad(&tid(3), 7, false).expect("aad"),
                   chunk_aad(&tid(3), 8, false).expect("aad"));
    }

    #[test]
    fn the_envelope_aad_cannot_collide_with_a_chunk_aad() {
        let env = envelope_aad(&tid(4)).expect("aad");
        for i in 0..64u64 {
            for f in [true, false] {
                assert_ne!(env, chunk_aad(&tid(4), i, f).expect("aad"));
            }
        }
    }

    #[test]
    fn sizes_account_for_every_tag() {
        let (sealed, chunks) = file_transfer_sizes(0).expect("sizes");
        assert_eq!(chunks, 1, "an empty file is still one authenticated chunk");
        assert_eq!(sealed, TAG_LEN as u64);

        let (sealed, chunks) = file_transfer_sizes(MAX_CHUNK_PLAIN_LEN as u64)
            .expect("sizes");
        assert_eq!(chunks, 1);
        assert_eq!(sealed, MAX_CHUNK_PLAIN_LEN as u64 + TAG_LEN as u64);

        let (sealed, chunks) = file_transfer_sizes(MAX_CHUNK_PLAIN_LEN as u64 + 1)
            .expect("sizes");
        assert_eq!(chunks, 2);
        assert_eq!(sealed, MAX_CHUNK_PLAIN_LEN as u64 + 1 + 2 * TAG_LEN as u64);
    }

    #[test]
    fn a_round_trip_recovers_the_plaintext() {
        let key = esk(7);
        let id = tid(1);
        let mut tx = PyFileSender::create(&key, id).expect("sender");
        let env = tx.envelope.clone();
        let sealed = {
            let aad = chunk_aad(&id, 0, true).expect("aad");
            cipher_for(&tx.file_key).expect("cipher")
                .encrypt(Nonce::from_slice(&chunk_nonce(0)),
                         Payload { msg: b"hello file", aad: &aad })
                .expect("seal")
        };
        let rx = PyFileReceiver::create(&key, id, &env).expect("receiver");
        let aad = chunk_aad(&id, 0, true).expect("aad");
        let out = cipher_for(&rx.file_key).expect("cipher")
            .decrypt(Nonce::from_slice(&chunk_nonce(0)),
                     Payload { msg: &sealed, aad: &aad })
            .expect("open");
        assert_eq!(out, b"hello file");
        tx.zeroize();
    }

    #[test]
    fn every_transfer_gets_a_different_file_key() {
        let key = esk(7);
        let a = PyFileSender::create(&key, tid(1)).expect("sender");
        let b = PyFileSender::create(&key, tid(1)).expect("sender");
        assert_ne!(a.file_key.expose_slice(), b.file_key.expose_slice(),
            "the FileKey is being reused across transfers");
    }

    #[test]
    fn a_wrong_session_cannot_open_the_envelope() {
        let tx = PyFileSender::create(&esk(7), tid(1)).expect("sender");
        assert!(PyFileReceiver::create(&esk(8), tid(1), &tx.envelope).is_err(),
            "a different session opened the key envelope");
    }

    #[test]
    fn a_wrong_transfer_id_cannot_open_the_envelope() {
        let tx = PyFileSender::create(&esk(7), tid(1)).expect("sender");
        assert!(PyFileReceiver::create(&esk(7), tid(2), &tx.envelope).is_err());
    }

    #[test]
    fn a_tampered_envelope_is_rejected() {
        let tx = PyFileSender::create(&esk(7), tid(1)).expect("sender");
        for i in 0..tx.envelope.len() {
            let mut bad = tx.envelope.clone();
            bad[i] ^= 0x01;
            assert!(PyFileReceiver::create(&esk(7), tid(1), &bad).is_err(),
                "flipping byte {i} of the envelope was accepted");
        }
    }

    #[test]
    fn a_truncated_envelope_is_rejected() {
        let tx = PyFileSender::create(&esk(7), tid(1)).expect("sender");
        let short = &tx.envelope[..tx.envelope.len() - 1];
        assert!(PyFileReceiver::create(&esk(7), tid(1), short).is_err());
    }

    #[test]
    fn zeroize_clears_the_key() {
        let mut tx = PyFileSender::create(&esk(7), tid(1)).expect("sender");
        tx.zeroize();
        assert!(tx.zeroized);
        assert_eq!(tx.file_key.expose_slice(), &[0u8; 32]);
    }
}
