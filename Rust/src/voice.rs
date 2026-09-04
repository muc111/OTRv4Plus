// src/voice.rs — Rust-owned media keys and voice key exchange
//
// Version: OTRv4+ v10.13.2
//
// Why this module exists
// ======================
// The voice path was the last place in OTRv4+ where long-lived key material
// lived in Python.  `VoiceFrameCrypto` kept its keys in a `bytearray` so they
// could be wiped -- and then handed each one to OpenSSL as an immutable
// `bytes`:
//
//     self._send_key = derive_media_key(root, ...)        # wipeable
//     self._send_gcm = AESGCM(bytes(self._send_key))      # not wipeable
//
// The bytearray was wiped.  The `bytes` was not, and neither was the copy
// inside the AESGCM object.  With RATCHET_INTERVAL = 500 frames at 60 ms
// that is one unwipeable copy per direction every 30 seconds: a 69-minute
// call left roughly 276 of them on the Python heap for the garbage collector
// to deal with whenever it felt like it.
//
// Calling the existing `aes256gcm_encrypt(key, nonce, pt, aad)` helper per
// frame would have been worse, not better -- it takes the key as an argument,
// so the key would enter Python on EVERY frame instead of every 500.  What
// was needed was a Rust-owned cipher OBJECT that holds the key across calls.
// That is `VoiceCipher` below, and it is the same shape `RustSMP` has used
// since the SMP engine moved into Rust.
//
// What did NOT move
// =================
// The frame header, the AAD construction, the replay window, the jitter
// buffer and the call state machine stay in Python.  None of them touch key
// material, all of them are proven on real calls, and rewriting working
// protocol code to no security benefit is how stable systems get broken.
//
// Byte-for-byte compatibility
// ===========================
// Everything here reproduces the Python construction exactly, because both
// ends of a live call must agree:
//
//   media key    HKDF-SHA512(ikm = root, salt = call_id,
//                            info = "OTRv4+Voice/Media/v1" || LP(call_id)
//                                   || u64(epoch) || u8(direction))
//   ratchet      HKDF-SHA512(ikm = key, salt = "",
//                            info = "OTRv4+Voice/Ratchet/v1")
//   nonce        u32(epoch & 0xFFFFFFFF) || u64(counter)
//   AEAD         AES-256-GCM, AAD supplied by the caller
//
// `tests/test_voice_rust_parity.py` runs the Python and Rust derivations side
// by side and fails on any difference.  It is the test that would catch a
// well-meaning "simplification" here silently breaking every call.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::{PyBytes, PyByteArray};

use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secure_mem::SecretBytes;

// ─── constants (must match otrv4plus_voice.py) ───────────────────────────────

const LABEL_MEDIA:    &[u8] = b"OTRv4+Voice/Media/v1";
const LABEL_RATCHET:  &[u8] = b"OTRv4+Voice/Ratchet/v1";
const LABEL_SALT:     &[u8] = b"OTRv4+Voice/Salt/v3";
const LABEL_INITIAL:  &[u8] = b"OTRv4+Voice/Initial/v1";
const LABEL_REKEY:    &[u8] = b"OTRv4+Voice/Rekey/v1";
const LABEL_CONFIRM:  &[u8] = b"OTRv4+Voice/Confirm/v1";
const LABEL_ENDPOINT: &[u8] = b"OTRv4+Voice/Endpoint/v1";

const CONFIRM_LEN:  usize = 32;
const MLKEM_SS_LEN: usize = 32;
const X448_SS_LEN:  usize = 56;

const ROOT_LEN:      usize = 64;
const MEDIA_KEY_LEN: usize = 32;
const NONCE_LEN:     usize = 12;

/// Frames between one-way ratchet steps.  Mirrors
/// `VoiceFrameCrypto.RATCHET_INTERVAL`; the two must agree or the peers
/// advance their chains at different rates and stop decrypting.
const RATCHET_INTERVAL: u64 = 500;

/// Sub-epochs retained for reordered frames.
const EPOCH_GRACE: u64 = 1;

/// Bound on forced hashing from a single frame claiming a far-future
/// sub-epoch.  Without it one crafted header costs unbounded CPU.
const MAX_SUBEPOCH_JUMP: u64 = 16;

const MAX_COUNTER: u64 = 1 << 62;

/// Direction bytes, mixed into the media-key info string.  These are wire
/// values: 0x01 caller->callee, 0x02 callee->caller, matching
/// `DIR_INITIATOR` / `DIR_RESPONDER` in otrv4plus_voice.py.  Getting them
/// wrong derives a different key and every frame fails its tag.
const DIR_INITIATOR: u8 = 0x01;
const DIR_RESPONDER: u8 = 0x02;

// ─── length-prefixed field encoding ──────────────────────────────────────────

/// Length-prefix one field, as `_lp` does Python-side.
///
/// Unprefixed concatenation is re-partitionable: a short call_id followed by
/// a long field hashes identically to a long call_id followed by a short one.
///
/// The prefix is a 4-byte big-endian length -- `struct.pack(">I", ...)`, NOT
/// 8.  This was written as a u64 first and every cross-implementation frame
/// failed its tag, which is what `test_voice_rust_parity.py` exists to catch:
/// the two sides derive silently different keys and the only symptom is that
/// nothing decrypts.
fn lp(value: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
    if value.len() > u32::MAX as usize {
        return Err("transcript field too long");
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

// ─── key derivation ──────────────────────────────────────────────────────────

fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8])
    -> Result<(), &'static str>
{
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| "HKDF output length invalid")
}

fn derive_media_key(root: &[u8], call_id: &[u8], epoch: u64, direction: u8)
    -> Result<SecretBytes<MEDIA_KEY_LEN>, &'static str>
{
    if root.len() != ROOT_LEN {
        return Err("epoch root must be 64 bytes");
    }
    let mut info = Vec::with_capacity(LABEL_MEDIA.len() + 4 + call_id.len() + 9);
    info.extend_from_slice(LABEL_MEDIA);
    lp(call_id, &mut info)?;
    info.extend_from_slice(&epoch.to_be_bytes());
    info.push(direction);

    let mut key = [0u8; MEDIA_KEY_LEN];
    hkdf_sha512(root, call_id, &info, &mut key)?;
    let out = SecretBytes::new(key);
    key.zeroize();
    Ok(out)
}

fn ratchet_once(key: &SecretBytes<MEDIA_KEY_LEN>)
    -> Result<SecretBytes<MEDIA_KEY_LEN>, &'static str>
{
    let mut next = [0u8; MEDIA_KEY_LEN];
    hkdf_sha512(key.expose_slice(), b"", LABEL_RATCHET, &mut next)?;
    let out = SecretBytes::new(next);
    next.zeroize();
    Ok(out)
}

fn media_nonce(epoch: u64, counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&((epoch & 0xFFFF_FFFF) as u32).to_be_bytes());
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

// ─── one direction of one epoch ──────────────────────────────────────────────

/// A chain key plus the sub-epoch it has been advanced to.
///
/// The `Aes256Gcm` instance is rebuilt on each ratchet step rather than kept
/// beside the key, so there is exactly one copy of the key material and it is
/// the one that zeroizes.
#[derive(ZeroizeOnDrop)]
struct Chain {
    key: SecretBytes<MEDIA_KEY_LEN>,
    #[zeroize(skip)]
    sub: u64,
}

impl Chain {
    fn new(key: SecretBytes<MEDIA_KEY_LEN>) -> Self { Self { key, sub: 0 } }

    fn cipher(&self) -> Result<Aes256Gcm, &'static str> {
        Aes256Gcm::new_from_slice(self.key.expose_slice())
            .map_err(|_| "AES-256-GCM rejected a 32-byte key")
    }

    /// Advance to `target`, returning how many steps were taken.
    fn advance_to(&mut self, target: u64) -> Result<u64, &'static str> {
        if target <= self.sub {
            return Ok(0);
        }
        let steps = target - self.sub;
        if steps > MAX_SUBEPOCH_JUMP {
            return Err("sub-epoch too far ahead");
        }
        for _ in 0..steps {
            let next = ratchet_once(&self.key)?;
            self.key = next;          // old key drops -> zeroized
            self.sub += 1;
        }
        Ok(steps)
    }
}

// ─── the PyO3 surface ────────────────────────────────────────────────────────

/// AES-256-GCM media protection for one epoch of one call, both directions.
///
/// Python holds this object and calls `seal` / `open`.  It never sees a key:
/// there is no getter, and adding one would defeat the entire module.
#[pyclass(name = "RustVoiceCipher")]
pub struct PyVoiceCipher {
    call_id:   Vec<u8>,
    epoch:     u64,
    send_dir:  u8,
    recv_dir:  u8,

    send: Option<Chain>,
    recv: Option<Chain>,
    /// The previous receive sub-epoch, retained for reordered frames.
    recv_prev: Option<Chain>,

    send_counter: u64,
    ratchet_steps: u64,
    zeroized: bool,
}

#[pymethods]
impl PyVoiceCipher {
    /// Build both directional chains from the epoch root.
    ///
    /// `root` is still a Python object at this point -- the epoch root itself
    /// moves into Rust in the key-schedule migration.  What this constructor
    /// guarantees is that the derived MEDIA keys never become Python objects
    /// at all, which is where the per-ratchet copies were accumulating.
    #[new]
    fn new(root: &[u8], call_id: &[u8], epoch: u64, is_initiator: bool)
        -> PyResult<Self>
    {
        if root.len() != ROOT_LEN {
            return Err(PyValueError::new_err(
                "epoch root must be 64 bytes"));
        }
        if call_id.len() < 16 {
            return Err(PyValueError::new_err(
                "call_id must be at least 16 bytes"));
        }
        let (send_dir, recv_dir) = if is_initiator {
            (DIR_INITIATOR, DIR_RESPONDER)
        } else {
            (DIR_RESPONDER, DIR_INITIATOR)
        };

        let send = derive_media_key(root, call_id, epoch, send_dir)
            .map_err(PyValueError::new_err)?;
        let recv = derive_media_key(root, call_id, epoch, recv_dir)
            .map_err(PyValueError::new_err)?;

        Ok(Self {
            call_id: call_id.to_vec(),
            epoch,
            send_dir,
            recv_dir,
            send: Some(Chain::new(send)),
            recv: Some(Chain::new(recv)),
            recv_prev: None,
            send_counter: 0,
            ratchet_steps: 0,
            zeroized: false,
        })
    }

    #[getter] fn epoch(&self) -> u64 { self.epoch }
    #[getter] fn send_counter(&self) -> u64 { self.send_counter }
    #[getter] fn ratchet_steps(&self) -> u64 { self.ratchet_steps }
    #[getter] fn zeroized(&self) -> bool { self.zeroized }
    #[getter] fn send_dir(&self) -> u8 { self.send_dir }

    /// How far each chain has ratcheted.  Counters, not key material, and
    /// exposed deliberately: "a forged frame must not advance the receive
    /// chain" is a security property, and a property nothing can observe is
    /// a property nothing can test.
    #[getter]
    fn send_sub(&self) -> u64 {
        self.send.as_ref().map(|c| c.sub).unwrap_or(0)
    }

    #[getter]
    fn recv_sub(&self) -> u64 {
        self.recv.as_ref().map(|c| c.sub).unwrap_or(0)
    }
    #[getter] fn recv_dir(&self) -> u8 { self.recv_dir }

    /// Encrypt one frame.  Returns (counter, ciphertext||tag).
    ///
    /// The caller supplies the AAD it built from the header, because the
    /// header layout is Python's business and duplicating it here would give
    /// two definitions of the wire format to keep in step.
    fn seal<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<(u64, Bound<'py, PyBytes>)> {
        if self.zeroized {
            return Err(PyRuntimeError::new_err("media cipher already zeroized"));
        }
        if self.send_counter >= MAX_COUNTER {
            return Err(PyRuntimeError::new_err("frame counter exhausted"));
        }
        let counter = self.send_counter;
        let target = counter / RATCHET_INTERVAL;

        let chain = self.send.as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("send chain gone"))?;
        let stepped = chain.advance_to(target).map_err(PyValueError::new_err)?;
        self.ratchet_steps += stepped;

        let cipher = chain.cipher().map_err(PyValueError::new_err)?;
        let nonce_bytes = media_nonce(self.epoch, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let sealed = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|_| PyRuntimeError::new_err("AES-256-GCM encryption failed"))?;

        self.send_counter += 1;
        Ok((counter, PyBytes::new(py, &sealed)))
    }

    /// Decrypt one frame.  Raises ValueError if the tag does not verify.
    ///
    /// Replay rejection stays Python-side: the replay window is protocol
    /// state, not key material, and it is already tested there.
    fn open<'py>(
        &mut self,
        py: Python<'py>,
        sealed: &[u8],
        aad: &[u8],
        counter: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if self.zeroized {
            return Err(PyRuntimeError::new_err("media cipher already zeroized"));
        }
        let target = counter / RATCHET_INTERVAL;
        let nonce_bytes = media_nonce(self.epoch, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let current_sub = self.recv.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("receive chain gone"))?
            .sub;

        // A frame from the sub-epoch we have just left.  Kept because the
        // network reorders and a ratchet step is not a synchronisation point.
        if target + EPOCH_GRACE == current_sub {
            if let Some(prev) = self.recv_prev.as_ref() {
                let cipher = prev.cipher().map_err(PyValueError::new_err)?;
                return cipher
                    .decrypt(nonce, Payload { msg: sealed, aad })
                    .map(|pt| PyBytes::new(py, &pt))
                    .map_err(|_| PyValueError::new_err("frame failed authentication"));
            }
            return Err(PyValueError::new_err("frame from an expired sub-epoch"));
        }
        if target < current_sub {
            return Err(PyValueError::new_err("frame from an expired sub-epoch"));
        }

        if target > current_sub {
            // Advancing on RECEIPT is what makes a forged header expensive,
            // so the jump is bounded.  The chain only moves forward once the
            // frame that asked for it has authenticated, which is why the
            // advance happens on a clone first.
            let chain = self.recv.as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("receive chain gone"))?;
            let steps = target - chain.sub;
            if steps > MAX_SUBEPOCH_JUMP {
                return Err(PyValueError::new_err("sub-epoch too far ahead"));
            }
            let mut probe_key = SecretBytes::from_slice(chain.key.expose_slice())
                .ok_or_else(|| PyRuntimeError::new_err("key length changed"))?;
            for _ in 0..steps {
                probe_key = ratchet_once(&probe_key).map_err(PyValueError::new_err)?;
            }
            let probe = Aes256Gcm::new_from_slice(probe_key.expose_slice())
                .map_err(|_| PyValueError::new_err("AES-256-GCM rejected a key"))?;
            let plaintext = probe
                .decrypt(nonce, Payload { msg: sealed, aad })
                .map_err(|_| PyValueError::new_err("frame failed authentication"))?;

            // Authenticated: commit the advance, retaining the sub-epoch we
            // are leaving so reordered frames still open.
            let old = std::mem::replace(
                &mut self.recv,
                Some(Chain { key: probe_key, sub: target }),
            );
            self.recv_prev = old;
            self.ratchet_steps += steps;
            return Ok(PyBytes::new(py, &plaintext));
        }

        let chain = self.recv.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("receive chain gone"))?;
        let cipher = chain.cipher().map_err(PyValueError::new_err)?;
        cipher
            .decrypt(nonce, Payload { msg: sealed, aad })
            .map(|pt| PyBytes::new(py, &pt))
            .map_err(|_| PyValueError::new_err("frame failed authentication"))
    }

    /// Destroy every key this epoch holds.  Idempotent, never raises.
    fn zeroize(&mut self) {
        // Dropping each Chain fires ZeroizeOnDrop on its SecretBytes.
        self.send = None;
        self.recv = None;
        self.recv_prev = None;
        self.zeroized = true;
    }

    fn __repr__(&self) -> String {
        format!("<RustVoiceCipher epoch={} sent={} steps={} zeroized={}>",
                self.epoch, self.send_counter, self.ratchet_steps,
                self.zeroized)
    }
}

impl Drop for PyVoiceCipher {
    fn drop(&mut self) {
        self.call_id.zeroize();
    }
}

/// Take a shared secret from Python and wipe the caller's buffer.
///
/// Accepts `bytes` or `bytearray`.  A `bytearray` is what `RustVoiceKex.agree`
/// hands back and what the voice module carries shared secrets in precisely so
/// they can be wiped, so this zeroes it here rather than relying on the
/// caller's `finally` -- one fewer place the wipe can be forgotten or, as had
/// already happened twice elsewhere, defeated by an intervening copy.
fn take_shared(value: &Bound<'_, PyAny>, expect_len: usize, what: &str)
    -> PyResult<Vec<u8>>
{
    let bytes: Vec<u8> = value.extract().map_err(|_| {
        PyValueError::new_err(format!("{} must be bytes or bytearray", what))
    })?;
    if bytes.len() != expect_len {
        return Err(PyValueError::new_err(
            format!("{} must be {} bytes", what, expect_len)));
    }
    if let Ok(buf) = value.downcast::<PyByteArray>() {
        let n = buf.len();
        for i in 0..n {
            buf.set_item(i, 0u8)?;
        }
    }
    Ok(bytes)
}

// ─── the epoch root ──────────────────────────────────────────────────────────

/// One committed voice epoch root, owned by Rust.
///
/// The root was the last secret in the voice path Python still held.  It is
/// the input every media key derives from, so a copy of it is a copy of every
/// key for that epoch -- and it lived in a `bytearray` for the whole call.
///
/// Python now holds this handle instead.  It can ask the root to produce a
/// cipher, a confirmation pair or an endpoint tag; it cannot ask for the root.
/// The rekey STATE MACHINE stays in Python deliberately: it is protocol
/// logic, it owns the convergence properties fixed at v10.13.1, and moving it
/// would put freshly-audited behaviour through an unnecessary rewrite.
#[pyclass(name = "RustVoiceRoot")]
pub struct PyVoiceRoot {
    root: Option<SecretBytes<ROOT_LEN>>,
}

impl PyVoiceRoot {
    fn expose(&self) -> PyResult<&[u8]> {
        self.root.as_ref().map(|r| r.expose_slice()).ok_or_else(|| {
            PyRuntimeError::new_err("this epoch root has been zeroized")
        })
    }

    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        SecretBytes::<ROOT_LEN>::from_slice(bytes)
            .map(|r| Self { root: Some(r) })
            .ok_or_else(|| PyValueError::new_err("epoch root must be 64 bytes"))
    }
}

/// `SHA-512(LABEL_SALT || transcript)`, matching `_salt_for`.
fn salt_for(transcript: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    let mut h = Sha512::new();
    h.update(LABEL_SALT);
    h.update(transcript);
    let out = h.finalize();
    let mut salt = [0u8; 64];
    salt.copy_from_slice(&out);
    salt
}

#[pymethods]
impl PyVoiceRoot {
    /// Derive the initial root from the hybrid agreement.
    ///
    /// Both secrets are mandatory: an X448-only root would be classically
    /// secure and post-quantum worthless, which is the whole reason the
    /// exchange is hybrid.
    #[staticmethod]
    fn from_initial_agreement(
        x448_shared:  &Bound<'_, PyAny>,
        mlkem_shared: &Bound<'_, PyAny>,
        transcript:   &[u8],
    ) -> PyResult<Self> {
        let mut x = take_shared(x448_shared, X448_SS_LEN,
                                "X448 shared secret")?;
        let mut k = take_shared(mlkem_shared, MLKEM_SS_LEN,
                                "ML-KEM shared secret")?;

        let mut ikm = Vec::with_capacity(8 + X448_SS_LEN + MLKEM_SS_LEN);
        let built = lp(&x, &mut ikm).and_then(|_| lp(&k, &mut ikm));
        x.zeroize();
        k.zeroize();
        built.map_err(PyValueError::new_err)?;

        let mut info = Vec::with_capacity(LABEL_INITIAL.len() + transcript.len());
        info.extend_from_slice(LABEL_INITIAL);
        info.extend_from_slice(transcript);

        let mut root = [0u8; ROOT_LEN];
        let derived = hkdf_sha512(&ikm, &salt_for(transcript), &info, &mut root);
        ikm.zeroize();
        derived.map_err(PyValueError::new_err)?;

        let held = SecretBytes::new(root);
        root.zeroize();
        Ok(Self { root: Some(held) })
    }

    /// Derive the next epoch's root, chained onto this one.
    ///
    /// Chaining is what makes a rekey an upgrade rather than a replacement:
    /// an attacker who compromised neither the old root nor the new
    /// ephemerals gains nothing, and one holding only the old root is locked
    /// out by the fresh X448 and ML-KEM secrets.
    ///
    /// The old root is NOT consumed -- a rekey that fails to confirm must
    /// leave the call running on the epoch it already had.
    fn derive_rekey(
        &self,
        x448_shared:  &Bound<'_, PyAny>,
        mlkem_shared: &Bound<'_, PyAny>,
        transcript:   &[u8],
    ) -> PyResult<Self> {
        let mut x = take_shared(x448_shared, X448_SS_LEN,
                                "X448 shared secret")?;
        let mut k = take_shared(mlkem_shared, MLKEM_SS_LEN,
                                "ML-KEM shared secret")?;
        let old = self.expose()?;

        let mut ikm = Vec::with_capacity(12 + ROOT_LEN + X448_SS_LEN + MLKEM_SS_LEN);
        let built = lp(old, &mut ikm)
            .and_then(|_| lp(&x, &mut ikm))
            .and_then(|_| lp(&k, &mut ikm));
        x.zeroize();
        k.zeroize();
        built.map_err(PyValueError::new_err)?;

        let mut info = Vec::with_capacity(LABEL_REKEY.len() + transcript.len());
        info.extend_from_slice(LABEL_REKEY);
        info.extend_from_slice(transcript);

        let mut root = [0u8; ROOT_LEN];
        let derived = hkdf_sha512(&ikm, &salt_for(transcript), &info, &mut root);
        ikm.zeroize();
        derived.map_err(PyValueError::new_err)?;

        let held = SecretBytes::new(root);
        root.zeroize();
        Ok(Self { root: Some(held) })
    }

    /// Build the media cipher for one epoch.  The root never leaves Rust.
    fn make_cipher(&self, call_id: &[u8], epoch: u64, is_initiator: bool)
        -> PyResult<PyVoiceCipher>
    {
        PyVoiceCipher::new(self.expose()?, call_id, epoch, is_initiator)
    }

    /// `(confirm_initiator, confirm_responder)` for this root and epoch.
    ///
    /// Two distinct tags rather than one shared value, so a tag observed
    /// from one side cannot be reflected back to satisfy the other.
    fn confirmations<'py>(&self, py: Python<'py>, call_id: &[u8], epoch: u64)
        -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)>
    {
        let mut info = Vec::with_capacity(LABEL_CONFIRM.len() + 4 + call_id.len() + 8);
        info.extend_from_slice(LABEL_CONFIRM);
        lp(call_id, &mut info).map_err(PyValueError::new_err)?;
        info.extend_from_slice(&epoch.to_be_bytes());

        let mut raw = [0u8; CONFIRM_LEN * 2];
        hkdf_sha512(self.expose()?, call_id, &info, &mut raw)
            .map_err(PyValueError::new_err)?;
        let out = (PyBytes::new(py, &raw[..CONFIRM_LEN]),
                   PyBytes::new(py, &raw[CONFIRM_LEN..]));
        raw.zeroize();
        Ok(out)
    }

    /// Authenticate one media-endpoint announcement.
    ///
    /// The announcement travels the XMPP control channel, so arriving over it
    /// proves nothing on its own.  The tag comes from the committed epoch
    /// root, which exists only because the hybrid agreement succeeded, and
    /// binds the call, the epoch, a strictly increasing sequence, the
    /// destination and the direction -- so it cannot cross calls, outlive a
    /// rekey, roll back, be substituted or be reflected.
    fn endpoint_tag<'py>(
        &self,
        py: Python<'py>,
        call_id: &[u8],
        epoch: u64,
        seq: u64,
        destination: &str,
        from_initiator: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut info = Vec::new();
        info.extend_from_slice(LABEL_ENDPOINT);
        lp(call_id, &mut info).map_err(PyValueError::new_err)?;
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(&seq.to_be_bytes());
        if !destination.is_ascii() {
            return Err(PyValueError::new_err(
                "destination must be ASCII"));
        }
        lp(destination.as_bytes(), &mut info).map_err(PyValueError::new_err)?;
        info.push(if from_initiator { 1 } else { 0 });

        let mut tag = [0u8; CONFIRM_LEN];
        hkdf_sha512(self.expose()?, call_id, &info, &mut tag)
            .map_err(PyValueError::new_err)?;
        let out = PyBytes::new(py, &tag);
        tag.zeroize();
        Ok(out)
    }

    /// Wrap raw bytes as a root handle.
    ///
    /// Takes material IN, which is the safe direction -- there is no matching
    /// accessor and there will not be one.  Production does not use this: the
    /// root is derived by `from_initial_agreement` or `derive_rekey` and never
    /// exists as a Python object.  This exists so tests can build a schedule
    /// from a fixed root without a full hybrid agreement, and so a caller
    /// holding a root from an older build can hand it over rather than keep it.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn py_from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Self::from_bytes(bytes)
    }

    /// Destroy the root.  Idempotent.
    fn zeroize(&mut self) { self.root = None; }

    #[getter]
    fn spent(&self) -> bool { self.root.is_none() }

    fn __repr__(&self) -> String {
        format!("<RustVoiceRoot spent={}>", self.root.is_none())
    }
}

// ─── voice key exchange: the X448 private scalar ─────────────────────────────

/// One side's ephemeral X448 material for one voice epoch.
///
/// This replaces `cryptography.hazmat.primitives.asymmetric.x448`, whose
/// private key is an OpenSSL object Python cannot wipe and cannot even reach.
/// It was the last private scalar in the voice path outside Rust.
///
/// The shared secret never crosses the PyO3 boundary: `agree_into_root`
/// performs the X448 agreement, mixes in the ML-KEM shared secret and returns
/// the ROOT, so the raw DH output is not a Python object at any point.
#[pyclass(name = "RustVoiceKex")]
pub struct PyVoiceKex {
    secret: Option<SecretBytes<56>>,
    public: [u8; 56],
}

// Not #[pymethods]: raw_agree is an internal helper.  Exposing it would put
// the raw X448 shared secret one call away from Python, which is the thing
// this module exists to prevent.
impl PyVoiceKex {
    /// Every check the Python `_agree_x448` performed, in one place.
    ///
    /// Consumes the scalar whatever the outcome: an ephemeral key that has
    /// been offered to a peer is spent, and retrying with a different peer
    /// key is exactly the shape of a small-subgroup probe.
    fn raw_agree(&mut self, peer_public: &[u8])
        -> PyResult<SecretBytes<56>>
    {
        if peer_public.len() != 56 {
            return Err(PyValueError::new_err(
                "peer X448 public key must be 56 bytes"));
        }
        if peer_public == self.public {
            // Reflection: a peer echoing our own key back would make both
            // sides derive a value the reflector can also compute.
            self.secret = None;
            return Err(PyValueError::new_err(
                "peer echoed our own X448 public key"));
        }
        if peer_public.iter().all(|b| *b == 0) {
            self.secret = None;
            return Err(PyValueError::new_err(
                "peer sent an all-zero X448 public key"));
        }
        let secret = self.secret.take().ok_or_else(|| {
            PyRuntimeError::new_err(
                "this key exchange has already been used; an ephemeral \
                 scalar is single-use by design")
        })?;

        // from_bytes, not from_bytes_unchecked: it rejects points that are
        // not on the curve before any scalar multiplication happens.
        let peer_pk = x448::PublicKey::from_bytes(peer_public).ok_or_else(|| {
            PyValueError::new_err("peer X448 public key is not a valid point")
        })?;
        let own = x448::Secret::from(*secret.expose());

        // None for a low-order / degenerate peer key.  RFC 7748 requires the
        // exchange be aborted rather than the all-zero result used: anyone
        // who forced it could derive the same root we did.
        let shared = own.as_diffie_hellman(&peer_pk).ok_or_else(|| {
            PyValueError::new_err(
                "degenerate X448 shared secret - aborting")
        })?;
        let bytes = shared.as_bytes();
        if bytes.iter().all(|b| *b == 0) {
            return Err(PyValueError::new_err(
                "degenerate X448 shared secret - aborting"));
        }
        SecretBytes::<56>::from_slice(bytes).ok_or_else(|| {
            PyRuntimeError::new_err("X448 shared secret has the wrong length")
        })
    }
}

#[pymethods]
impl PyVoiceKex {
    #[new]
    fn new() -> PyResult<Self> {
        use rand::RngCore;
        let mut sk = [0u8; 56];
        rand::rngs::OsRng.fill_bytes(&mut sk);

        let secret = x448::Secret::from(sk);
        let public = x448::PublicKey::from(&secret);
        let pub_bytes: [u8; 56] = *public.as_bytes();

        let held = SecretBytes::new(sk);
        sk.zeroize();
        Ok(Self { secret: Some(held), public: pub_bytes })
    }

    /// Our X448 public key.  Public by definition -- safe to hand out.
    #[getter]
    fn public<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public)
    }

    /// Agree with the peer and derive the epoch root, all inside Rust.
    ///
    /// `info` is the transcript the caller has already built; it is public
    /// material (call id, fingerprints, epoch) and is not secret.
    ///
    /// Returns the 64-byte root.  That IS secret and does become a Python
    /// object -- for now.  Moving the root behind a handle is the key-schedule
    /// migration; this step removes the X448 private scalar and the raw DH
    /// output, which are the two values Python could never wipe at all.
    fn agree_into_root<'py>(
        &mut self,
        py: Python<'py>,
        peer_public: &[u8],
        mlkem_shared: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        if peer_public.len() != 56 {
            return Err(PyValueError::new_err(
                "peer X448 public key must be 56 bytes"));
        }
        let shared = self.raw_agree(peer_public)?;

        let mut ikm = Vec::with_capacity(56 + mlkem_shared.len());
        ikm.extend_from_slice(shared.expose_slice());
        ikm.extend_from_slice(mlkem_shared);

        let mut root = [0u8; ROOT_LEN];
        let derived = hkdf_sha512(&ikm, salt, info, &mut root);

        ikm.zeroize();
        // `secret` and `shared` drop here; SecretBytes zeroizes, and the x448
        // crate's own types zeroize on drop.

        derived.map_err(PyValueError::new_err)?;
        let out = PyBytes::new(py, &root);
        root.zeroize();
        Ok(out)
    }

    /// Agree with the peer, returning the raw X448 shared secret.
    ///
    /// Matches the shape of the Python `_agree_x448` it replaces, so the
    /// call sites do not change: the caller still receives the shared secret
    /// and still combines it with the ML-KEM secret itself.  What changes is
    /// the PRIVATE SCALAR -- previously an OpenSSL object Python could
    /// neither wipe nor reach, now `SecretBytes<56>` that zeroizes on drop.
    ///
    /// Returned as a `bytearray` rather than `bytes` so the caller's existing
    /// `_wipe` still works on it.  Handing back `bytes` would have made the
    /// shared secret unwipeable and undone half the point.
    ///
    /// `agree_into_root` is the stronger form and keeps the shared secret
    /// inside Rust entirely; it is used once the key schedule moves too.
    fn agree<'py>(
        &mut self,
        py: Python<'py>,
        peer_public: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let shared = self.raw_agree(peer_public)?;
        let out = PyByteArray::new(py, shared.expose_slice());
        Ok(out)
    }

    /// Drop the private scalar without performing an agreement.
    fn zeroize(&mut self) { self.secret = None; }

    #[getter]
    fn spent(&self) -> bool { self.secret.is_none() }

    fn __repr__(&self) -> String {
        format!("<RustVoiceKex spent={}>", self.secret.is_none())
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CALL: &[u8] = b"0123456789abcdef";
    const ROOT: [u8; ROOT_LEN] = [7u8; ROOT_LEN];

    #[test]
    fn media_keys_differ_by_direction() {
        let a = derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap();
        let b = derive_media_key(&ROOT, CALL, 0, DIR_RESPONDER).unwrap();
        assert_ne!(a.expose_slice(), b.expose_slice(),
                   "both directions share a key, so both counters starting \
                    at zero would repeat a nonce");
    }

    #[test]
    fn media_keys_differ_by_epoch() {
        let a = derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap();
        let b = derive_media_key(&ROOT, CALL, 1, DIR_INITIATOR).unwrap();
        assert_ne!(a.expose_slice(), b.expose_slice());
    }

    #[test]
    fn media_keys_differ_by_call() {
        let a = derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap();
        let b = derive_media_key(&ROOT, b"fedcba9876543210", 0, DIR_INITIATOR).unwrap();
        assert_ne!(a.expose_slice(), b.expose_slice());
    }

    #[test]
    fn a_short_root_is_refused() {
        assert!(derive_media_key(&[0u8; 32], CALL, 0, DIR_INITIATOR).is_err());
    }

    #[test]
    fn the_ratchet_is_not_the_identity() {
        let k = derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap();
        let n = ratchet_once(&k).unwrap();
        assert_ne!(k.expose_slice(), n.expose_slice());
    }

    #[test]
    fn the_ratchet_is_deterministic() {
        let k = derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap();
        let a = ratchet_once(&k).unwrap();
        let b = ratchet_once(&k).unwrap();
        assert_eq!(a.expose_slice(), b.expose_slice());
    }

    #[test]
    fn nonce_folds_in_the_epoch() {
        assert_ne!(media_nonce(0, 5), media_nonce(1, 5));
        assert_ne!(media_nonce(0, 5), media_nonce(0, 6));
    }

    #[test]
    fn a_bounded_jump_is_allowed_and_an_unbounded_one_is_not() {
        let mut c = Chain::new(derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap());
        assert_eq!(c.advance_to(MAX_SUBEPOCH_JUMP).unwrap(), MAX_SUBEPOCH_JUMP);
        assert!(c.advance_to(c.sub + MAX_SUBEPOCH_JUMP + 1).is_err());
    }

    #[test]
    fn advancing_backwards_is_a_no_op() {
        let mut c = Chain::new(derive_media_key(&ROOT, CALL, 0, DIR_INITIATOR).unwrap());
        c.advance_to(3).unwrap();
        assert_eq!(c.advance_to(1).unwrap(), 0);
        assert_eq!(c.sub, 3);
    }

    #[test]
    fn length_prefix_removes_the_ambiguity() {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        lp(b"ab", &mut a).unwrap(); lp(b"c", &mut a).unwrap();
        lp(b"a", &mut b).unwrap();  lp(b"bc", &mut b).unwrap();
        assert_ne!(a, b);
    }
}
