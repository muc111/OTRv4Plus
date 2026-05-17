#![cfg(feature = "pq-rust")]
#![allow(deprecated)]  // upstream generic-array 0.x deprecation in ed448-goldilocks-plus 0.16; see ring_sig.rs for full rationale
// src/dake.rs — OTRv4 Deniable Authenticated Key Exchange
//
// All secret material stays inside Rust.  Wire parsing of DAKE1/2 is handled
// natively so that optional ML‑DSA‑87 fields are processed correctly.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};
use zeroize::ZeroizeOnDrop;

use pqcrypto_traits::kem::{
    PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    Ciphertext as KemCiphertext, SharedSecret as KemSharedSecret,
};
use pqcrypto_traits::sign::{
    PublicKey as SignPublicKey, DetachedSignature as SignDetachedSignature,
};

use crate::error::{OtrError, Result};
use crate::kdf::{self, usage};
use crate::secure_mem::{SecretBytes, SecretVec, DakeSessionKeys};



const MSG_DAKE1: u8 = 0x35;
const MSG_DAKE2: u8 = 0x36;
const MSG_DAKE3: u8 = 0x37;

const ED448_PUB_SIZE: usize = 57;
const X448_PUB_SIZE:  usize = 56;
const MLKEM_EK_SIZE:  usize = 1568;
const MLKEM_CT_SIZE:  usize = 1568;
const MLDSA_PUB_SIZE: usize = 2592;
const MLDSA_SIG_SIZE: usize = 4627;
const MAC_SIZE:       usize = 64;

const RING_SIGMA_SIZE: usize = 228;

// ─────────────────────────────────────────────────────────────────────────────
//  Generic DAKE result (returned to Python)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[pyclass]
pub struct Dakeresult {
    #[pyo3(get, set)] pub success: bool,
    #[pyo3(get, set)] pub error: Option<String>,
    #[pyo3(get, set)] pub dake2_bytes: Option<Vec<u8>>,

    // Secret fields (read‑once, zeroised after consumption)
    pub root_key:    Option<Vec<u8>>,
    pub chain_key_a: Option<Vec<u8>>,
    pub chain_key_b: Option<Vec<u8>>,
    pub brace_key:   Option<Vec<u8>>,
    pub mac_key:     Option<Vec<u8>>,

    #[pyo3(get, set)] pub ssid: Option<Vec<u8>>,
    #[pyo3(get, set)] pub remote_identity_pub: Option<Vec<u8>>,
    #[pyo3(get, set)] pub remote_mldsa_pub: Option<Vec<u8>>,
    #[pyo3(get, set)] pub remote_profile_bytes: Option<Vec<u8>>,

    pub consumed: bool,
}

#[pymethods]
impl Dakeresult {
    #[new] fn new() -> Self { Self { success: false, error: None, dake2_bytes: None, root_key: None, chain_key_a: None, chain_key_b: None, brace_key: None, mac_key: None, ssid: None, remote_identity_pub: None, remote_mldsa_pub: None, remote_profile_bytes: None, consumed: false } }

    // ── Getters / setters with consumption guard ───────────────
    #[getter] fn consumed(&self) -> bool { self.consumed }

    #[getter] fn root_key<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.check_not_consumed()?; Ok(self.root_key.as_ref().map(|v| PyBytes::new_bound(py, v)))
    }
    #[setter(root_key)] fn set_root_key(&mut self, v: Option<Vec<u8>>) -> PyResult<()> {
        self.check_not_consumed()?; self.root_key = v; Ok(())
    }

    #[getter] fn chain_key_a<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.check_not_consumed()?; Ok(self.chain_key_a.as_ref().map(|v| PyBytes::new_bound(py, v)))
    }
    #[setter(chain_key_a)] fn set_chain_key_a(&mut self, v: Option<Vec<u8>>) -> PyResult<()> {
        self.check_not_consumed()?; self.chain_key_a = v; Ok(())
    }

    #[getter] fn chain_key_b<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.check_not_consumed()?; Ok(self.chain_key_b.as_ref().map(|v| PyBytes::new_bound(py, v)))
    }
    #[setter(chain_key_b)] fn set_chain_key_b(&mut self, v: Option<Vec<u8>>) -> PyResult<()> {
        self.check_not_consumed()?; self.chain_key_b = v; Ok(())
    }

    #[getter] fn brace_key<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.check_not_consumed()?; Ok(self.brace_key.as_ref().map(|v| PyBytes::new_bound(py, v)))
    }
    #[setter(brace_key)] fn set_brace_key(&mut self, v: Option<Vec<u8>>) -> PyResult<()> {
        self.check_not_consumed()?; self.brace_key = v; Ok(())
    }

    #[getter] fn mac_key<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.check_not_consumed()?; Ok(self.mac_key.as_ref().map(|v| PyBytes::new_bound(py, v)))
    }
    #[setter(mac_key)] fn set_mac_key(&mut self, v: Option<Vec<u8>>) -> PyResult<()> {
        self.check_not_consumed()?; self.mac_key = v; Ok(())
    }
}

impl Dakeresult {
    fn check_not_consumed(&self) -> PyResult<()> {
        if self.consumed {
            Err(pyo3::exceptions::PyRuntimeError::new_err("Dakeresult has been consumed"))
        } else { Ok(()) }
    }

    fn aggressive_zero(v: &mut Option<Vec<u8>>) {
        if let Some(ref mut inner) = v {
            for b in inner.iter_mut() { *b = 0; } inner.clear(); inner.shrink_to_fit();
        }
        *v = None;
    }

    pub(crate) fn mark_consumed_and_zero(&mut self) {
        Self::aggressive_zero(&mut self.root_key);
        Self::aggressive_zero(&mut self.chain_key_a);
        Self::aggressive_zero(&mut self.chain_key_b);
        Self::aggressive_zero(&mut self.brace_key);
        Self::aggressive_zero(&mut self.mac_key);
        self.consumed = true;
    }

    fn success() -> Self { Self { success: true, error: None, ..Self::new() } }
}

// ─────────────────────────────────────────────────────────────────────────────
//  DAKE state machine
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DakePhase {
    Idle, SentDake1, ReceivedDake1, SentDake2,
    ReceivedDake2, Established, Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
//  DakeOutput — Phase 4 opaque session-key handle
//
//  Replaces Dakeresult's `Vec<u8>` PyO3 getter-set fields with a private
//  RefCell<Option<DakeSessionKeys>>.  Python NEVER sees the secret key bytes
//  as PyBytes — they are moved directly into a RustDoubleRatchet via
//  consume_into_ratchet(), without crossing the FFI boundary.
//
//  This closes audit findings C2 and C3 (Critical Exposure Window) when the
//  caller uses generate_dake2_output / process_dake2_output instead of the
//  legacy generate_dake2 / process_dake2 PyO3 methods.
//
//  The legacy Dakeresult path remains available for backward compatibility
//  during the Python adapter migration; once the migration is complete in
//  v10.6.3+, Dakeresult and its associated PyO3 methods will be removed.
// ─────────────────────────────────────────────────────────────────────────────

use std::cell::RefCell;

#[pyclass]
pub struct DakeOutput {
    // Secret material — private, no PyO3 getter.  Consumed by
    // consume_into_ratchet().  Wrapped in Option so we can .take() it out
    // when consuming; wrapped in RefCell so consume_into_ratchet can take
    // &self (PyO3 method receiver) rather than &mut self.
    inner: RefCell<Option<DakeSessionKeys>>,

    // Public material — exposed via #[pyo3(get)].  These are NOT secrets:
    //   ssid is a session identifier (8 bytes) public to both parties
    //   remote_identity_pub is the peer's Ed448 long-term identity key
    //   remote_mldsa_pub is the peer's optional ML-DSA-87 long-term key
    //   remote_profile_bytes is the peer's signed client profile blob
    //   dake2_bytes is the wire message to send (only populated on generate)
    #[pyo3(get)] pub ssid:                 [u8; 8],
    #[pyo3(get)] pub remote_identity_pub:  Vec<u8>,
    #[pyo3(get)] pub remote_mldsa_pub:     Option<Vec<u8>>,
    #[pyo3(get)] pub remote_profile_bytes: Vec<u8>,
    #[pyo3(get)] pub dake2_bytes:          Option<Vec<u8>>,
}

#[pymethods]
impl DakeOutput {
    /// True after consume_into_ratchet has moved the secret keys into a
    /// ratchet.  Subsequent calls to consume_into_ratchet will raise.
    #[getter]
    fn consumed(&self) -> bool { self.inner.borrow().is_none() }

    /// Move the secret session keys into a new RustDoubleRatchet.
    /// The keys NEVER become PyBytes — they transit from the private
    /// RefCell<Option<DakeSessionKeys>> directly into the ratchet's owned
    /// SecretBytes fields via DoubleRatchet::new().
    ///
    /// Calling consume_into_ratchet a second time raises PyValueError.
    /// After a successful call, self.consumed becomes True and all secret
    /// material has either been moved into the returned ratchet or
    /// zeroized.
    ///
    /// Parameters:
    ///   - `ad`: associated-data bytes for AES-256-GCM in the ratchet
    ///     (e.g. b"OTRv4-DATA")
    ///   - `dh_pub_local`: 56-byte X448 public key for the ratchet's
    ///     local DH side.  The Python adapter generates the X448
    ///     keypair (via cryptography library) and supplies the public
    ///     bytes here.  Phase 5 moves X448 keypair generation into Rust
    ///     and removes this parameter.
    ///   - `is_initiator`: matches the caller's role from DAKE; the
    ///     ratchet swaps chain_key_send/recv internally based on this
    ///     flag.
    #[pyo3(signature = (ad, dh_pub_local, is_initiator))]
    fn consume_into_ratchet(
        &self,
        ad:           &[u8],
        dh_pub_local: &[u8],
        is_initiator: bool,
    ) -> PyResult<crate::ratchet::RustDoubleRatchet> {
        use pyo3::exceptions::PyValueError;

        if dh_pub_local.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "dh_pub_local must be 56 bytes (X448 public key), got {}",
                dh_pub_local.len(),
            )));
        }
        let mut dh_pub_local_arr = [0u8; 56];
        dh_pub_local_arr.copy_from_slice(dh_pub_local);

        // Take the session keys out of the RefCell, consuming them.
        let keys = self.inner.borrow_mut().take().ok_or_else(|| {
            PyValueError::new_err(
                "DakeOutput has already been consumed — cannot consume twice",
            )
        })?;

        // Move keys directly into a RustDoubleRatchet via the from_dake_keys
        // constructor (added in ratchet.rs).  This path NEVER allocates
        // PyBytes for the secret material.
        crate::ratchet::RustDoubleRatchet::from_dake_keys(
            keys, ad, &dh_pub_local_arr, is_initiator,
        ).map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

impl DakeOutput {
    /// Internal constructor — only the Rust DakeState may build a DakeOutput.
    /// Python cannot construct one directly (no `#[new]` method).
    pub(crate) fn from_keys_and_public(
        keys:                  DakeSessionKeys,
        remote_identity_pub:   Vec<u8>,
        remote_mldsa_pub:      Option<Vec<u8>>,
        remote_profile_bytes:  Vec<u8>,
        dake2_bytes:           Option<Vec<u8>>,
    ) -> Self {
        let ssid = *keys.ssid.expose();
        Self {
            inner: RefCell::new(Some(keys)),
            ssid,
            remote_identity_pub,
            remote_mldsa_pub,
            remote_profile_bytes,
            dake2_bytes,
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct DakeState {
    our_identity_priv: SecretBytes<57>,
    our_identity_pub:  [u8; ED448_PUB_SIZE],
    our_prekey_priv:   SecretBytes<56>,
    our_prekey_pub:    [u8; X448_PUB_SIZE],
    our_mldsa_priv:    Option<SecretVec>,
    our_mldsa_pub:     Option<Vec<u8>>,
    our_eph_x448_priv: SecretBytes<56>,
    our_eph_x448_pub:  [u8; X448_PUB_SIZE],

    our_mlkem_sk:      SecretVec,
    our_mlkem_ek:      [u8; MLKEM_EK_SIZE],

    peer_identity_pub: [u8; ED448_PUB_SIZE],
    peer_eph_x448_pub: [u8; X448_PUB_SIZE],
    peer_mlkem_ek:     [u8; MLKEM_EK_SIZE],
    peer_mldsa_pub:    Option<Vec<u8>>,
    peer_profile_bytes: Option<Vec<u8>>,

    #[zeroize(skip)] pub our_profile_bytes: Vec<u8>,
    session_keys:      Option<DakeSessionKeys>,
    transcript:        Vec<u8>,

    #[zeroize(skip)] pub phase:        DakePhase,
    #[zeroize(skip)] pub is_initiator: bool,
    #[zeroize(skip)] pub sender_tag:   u32,
    #[zeroize(skip)] pub receiver_tag: u32,
}

impl DakeState {
    pub fn new(
        identity_priv: &[u8; 57], identity_pub: &[u8; ED448_PUB_SIZE],
        prekey_priv:   &[u8; 56], prekey_pub:   &[u8; X448_PUB_SIZE],
        mldsa_priv:    Option<&[u8]>, mldsa_pub: Option<&[u8]>,
        sender_tag:    u32,
    ) -> Result<Self> {
        let (eph_priv, eph_pub) = Self::generate_x448_ephemeral()?;
        let (ek, sk) = Self::generate_mlkem_keypair()?;

        let mut ip   = [0u8; 57]; ip.copy_from_slice(identity_priv);
        let mut pp   = [0u8; 56]; pp.copy_from_slice(prekey_priv);
        let mut ipub = [0u8; ED448_PUB_SIZE]; ipub.copy_from_slice(identity_pub);
        let mut ppub = [0u8; X448_PUB_SIZE];  ppub.copy_from_slice(prekey_pub);
        let mut mlek = [0u8; MLKEM_EK_SIZE];  mlek.copy_from_slice(&ek);

        Ok(Self {
            our_identity_priv: SecretBytes::new(ip), our_identity_pub: ipub,
            our_prekey_priv: SecretBytes::new(pp), our_prekey_pub: ppub,
            our_mldsa_priv: mldsa_priv.map(SecretVec::from_slice), our_mldsa_pub: mldsa_pub.map(|b| b.to_vec()),
            our_eph_x448_priv: eph_priv, our_eph_x448_pub: eph_pub,
            our_mlkem_sk: SecretVec::from_slice(&sk), our_mlkem_ek: mlek,
            peer_identity_pub: [0u8; ED448_PUB_SIZE], peer_eph_x448_pub: [0u8; X448_PUB_SIZE],
            peer_mlkem_ek: [0u8; MLKEM_EK_SIZE], peer_mldsa_pub: None, peer_profile_bytes: None,
            our_profile_bytes: Vec::new(), session_keys: None, transcript: Vec::new(),
            phase: DakePhase::Idle, is_initiator: false, sender_tag, receiver_tag: 0,
        })
    }

    // ── DAKE1 ────────────────────────────────────────────────
    pub fn generate_dake1(&mut self, client_profile: &[u8], mldsa_pub: Option<&[u8]>) -> Result<Vec<u8>> {
        if self.phase != DakePhase::Idle { return Err(OtrError::Dake("wrong phase")); }
        self.is_initiator = true;
        let mut msg = vec![MSG_DAKE1];
        msg.extend_from_slice(&self.our_eph_x448_pub);
        msg.extend_from_slice(&self.our_mlkem_ek);
        msg.extend_from_slice(client_profile);
        if let Some(p) = mldsa_pub.or(self.our_mldsa_pub.as_deref()) { msg.extend_from_slice(p); }
        self.transcript.extend_from_slice(&msg);
        self.phase = DakePhase::SentDake1;
        Ok(msg)
    }

    pub fn process_dake1(&mut self, data: &[u8]) -> Result<()> {
        // Wire: type | X448_pub(56) | MLKEM_ek(1568) | profile(var) | [MLDSA_pub(2592)]
        if data.len() < 1 + X448_PUB_SIZE + MLKEM_EK_SIZE + 3 { return Err(OtrError::TooShort { need: 1+X448_PUB_SIZE+MLKEM_EK_SIZE+3, got: data.len() }); }
        if data[0] != MSG_DAKE1 { return Err(OtrError::WireFormat); }
        let mut off = 1;
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off + X448_PUB_SIZE]);
        off += X448_PUB_SIZE;
        self.peer_mlkem_ek.copy_from_slice(&data[off..off + MLKEM_EK_SIZE]);
        off += MLKEM_EK_SIZE;

        // parse profile
        let num_versions = data[off + 1] as usize;
        if num_versions == 0 || num_versions > 8 { return Err(OtrError::WireFormat); }
        let prof_size = 1 + 1 + num_versions + ED448_PUB_SIZE + X448_PUB_SIZE + 8 + 114;
        if off + prof_size > data.len() { return Err(OtrError::WireFormat); }
        let profile_slice = &data[off..off + prof_size];
        off += prof_size;

        // optional ML‑DSA pub
        if data.len() - off >= MLDSA_PUB_SIZE { self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec()); }

        self.peer_identity_pub = Self::extract_identity_from_profile(profile_slice)?;
        self.peer_profile_bytes = Some(profile_slice.to_vec());
        self.transcript.extend_from_slice(data);
        self.phase = DakePhase::ReceivedDake1;
        Ok(())
    }

    // ── DAKE2 ────────────────────────────────────────────────
    pub fn generate_dake2(
        &mut self, client_profile: &[u8], our_prekey_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>,
    ) -> Result<(Vec<u8>, DakeSessionKeys)> {
        if self.phase != DakePhase::ReceivedDake1 { return Err(OtrError::Dake("wrong phase")); }
        let prekey_priv_bytes = our_prekey_priv.unwrap_or(self.our_prekey_priv.expose());


        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_prekey_pub())?;
        let dh3 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        let (ct, mlkem_ss) = Self::mlkem_encapsulate(&self.peer_mlkem_ek)?;
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1); combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3); combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        let ssid = { let mut a = [0u8; 8]; a.copy_from_slice(&kdf::kdf_1(usage::SSID, &mixed_secret, 8)); a };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);

        // Build the wire BEFORE computing MAC, so the MAC covers exactly what
        // will be sent.  The parser (process_dake2) MACs over data[..off]
        // where off is everything before the MAC — i.e. the full wire body
        // including any ML-DSA pub.  We must match that on the writer side.
        let mldsa_to_send: Option<&[u8]> = mldsa_pub.or(self.our_mldsa_pub.as_deref());

        let mut wire_body = Vec::new();
        wire_body.push(MSG_DAKE2);
        wire_body.extend_from_slice(&self.our_eph_x448_pub);
        wire_body.extend_from_slice(&ct);
        wire_body.extend_from_slice(client_profile);
        if let Some(p) = mldsa_to_send {
            wire_body.extend_from_slice(p);
        }

        // ── CRITICAL FIX (Patch-3.5): MAC over the actual wire body bytes ──
        // The previous version MACed over (transcript || eph_pub || ct ||
        // client_profile), excluding both MSG_DAKE2 and the ML-DSA pub.  The
        // parser MACs over data[..off] which IS the full wire body.  These
        // disagreed and caused MAC verification to fail.
        let mac = kdf::hmac_sha3_512(&mac_key, &wire_body);

        // Assemble final message = wire_body || MAC
        let mut msg = wire_body;
        msg.extend_from_slice(&mac);

        let session_keys = Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?;
        self.transcript.extend_from_slice(&msg);
        self.phase = DakePhase::SentDake2;
        Ok((msg, session_keys))
    }

    /// Process DAKE2 – all parsing done here.
    pub fn process_dake2(
        &mut self, data: &[u8], our_prekey_priv: Option<&[u8]>,
    ) -> Result<DakeSessionKeys> {
        if self.phase != DakePhase::SentDake1 {
            return Err(OtrError::Dake("wrong phase"));
        }
        if data.is_empty() {
            return Err(OtrError::WireFormat);
        }
        if data[0] != MSG_DAKE2 { return Err(OtrError::WireFormat); }

        let mut off = 1;
        if off + X448_PUB_SIZE > data.len() {
            return Err(OtrError::WireFormat);
        }
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off + X448_PUB_SIZE]);
        off += X448_PUB_SIZE;

        if off + MLKEM_CT_SIZE > data.len() {
            return Err(OtrError::TooShort { need: off + MLKEM_CT_SIZE, got: data.len() });
        }
        let mlkem_ct = data[off..off + MLKEM_CT_SIZE].to_vec();
        off += MLKEM_CT_SIZE;

        // ── Parse profile (deterministic length) ───────────────
        if off + 3 > data.len() {
            return Err(OtrError::TooShort { need: off + 3, got: data.len() });
        }
        let num_versions = data[off + 1] as usize;
        if num_versions == 0 || num_versions > 8 {
            return Err(OtrError::WireFormat);
        }
        let prof_size = 1 + 1 + num_versions + ED448_PUB_SIZE + X448_PUB_SIZE + 8 + 114;
        if off + prof_size > data.len() {
            return Err(OtrError::WireFormat);
        }
        let profile_slice = &data[off..off + prof_size];
        off += prof_size;

        // ── Optional ML‑DSA‑87 public key (no flag byte) ──────
        let mac_start = data.len() - MAC_SIZE;
        if mac_start > off && mac_start - off >= MLDSA_PUB_SIZE {
            self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec());
            off += MLDSA_PUB_SIZE;
        }

        if off + MAC_SIZE != data.len() {
            return Err(OtrError::WireFormat);
        }
        let mac_received = &data[off..];
        let message_body = &data[..off];

        // ── Critical: store peer profile BEFORE deriving DH so that
        // peer_prekey_pub() can read it.  We will reset on MAC failure.
        self.peer_profile_bytes = Some(profile_slice.to_vec());

        // ── Cryptography (initiator side) ──────────────────────
        let prekey_priv_bytes = our_prekey_priv.unwrap_or(self.our_prekey_priv.expose());


        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        let dh3 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_prekey_pub())?;
        let mlkem_ss = Self::mlkem_decapsulate(self.our_mlkem_sk.expose(), &mlkem_ct)?;
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1); combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3); combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        let ssid = { let mut a = [0u8; 8]; a.copy_from_slice(&kdf::kdf_1(usage::SSID, &mixed_secret, 8)); a };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);

        let expected_mac = kdf::hmac_sha3_512(&mac_key, message_body);

        if !crate::secure_mem::ct_eq(mac_received, &expected_mac) {
            // MAC failed: clear the prematurely-stored profile so a later
            // retry doesn't keep stale state.
            self.peer_profile_bytes = None;
            return Err(OtrError::AeadDecrypt);
        }

        self.peer_identity_pub = Self::extract_identity_from_profile(profile_slice)?;
        // peer_profile_bytes already stored before DH (line above).
        self.transcript.extend_from_slice(data);
        let session_keys = Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?;
        self.phase = DakePhase::ReceivedDake2;
        Ok(session_keys)
    }

    // ── DAKE3 & helpers (unchanged) ───────────────────────────
    pub fn assemble_dake3(&self, sigma: &[u8], mldsa_sig: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut msg = vec![MSG_DAKE3]; msg.extend_from_slice(sigma);
        match mldsa_sig { Some(s) => { msg.push(0x01); msg.extend_from_slice(s); } None => msg.push(0x00), }
        Ok(msg)
    }
    pub fn process_dake3(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != DakePhase::SentDake2 { return Err(OtrError::Dake("wrong phase")); }
        if data.len() < 1 + RING_SIGMA_SIZE + 1 { return Err(OtrError::TooShort{need:1+RING_SIGMA_SIZE+1,got:data.len()}); }
        let sigma = &data[1..1+RING_SIGMA_SIZE];
        let off = 1+RING_SIGMA_SIZE;
        let flag = data[off];
        if flag == 0x01 {
            let start = off+1;
            if data.len()-start < MLDSA_SIG_SIZE { return Err(OtrError::TooShort{need:start+MLDSA_SIG_SIZE,got:data.len()}); }
            let mldsa_sig = &data[start..start+MLDSA_SIG_SIZE];
            let peer_mldsa_pub = self.peer_mldsa_pub.as_ref().ok_or(OtrError::MlDsa)?;
            Self::mldsa_verify(peer_mldsa_pub, &self.transcript, mldsa_sig)?;
        } else if flag != 0x00 { return Err(OtrError::WireFormat); }
        Self::verify_ring_signature(&self.transcript, &self.our_identity_pub, &self.peer_identity_pub, sigma)?;
        self.transcript.extend_from_slice(data);
        self.phase = DakePhase::Established;
        Ok(())
    }

    // ── utility functions ──────────────────────────────────────
    fn peer_prekey_pub(&self) -> [u8; X448_PUB_SIZE] {
        if let Some(ref profile) = self.peer_profile_bytes {
            let vc = if profile.len() > 1 { profile[1] as usize } else { 0 };
            let hl = 2 + vc;
            if profile.len() >= hl + 57 + 56 { let mut a = [0u8; 56]; a.copy_from_slice(&profile[hl+57..hl+57+56]); return a; }
        }
        [0u8; 56]
    }

    fn extract_identity_from_profile(profile: &[u8]) -> Result<[u8; ED448_PUB_SIZE]> {
        let vc = if profile.len() > 1 { profile[1] as usize } else { return Err(OtrError::TooShort{need:2,got:profile.len()}) };
        let hl = 2 + vc;
        if profile.len() < hl + ED448_PUB_SIZE { return Err(OtrError::TooShort{need:hl+ED448_PUB_SIZE,got:profile.len()}); }
        let mut id = [0u8; ED448_PUB_SIZE]; id.copy_from_slice(&profile[hl..hl+ED448_PUB_SIZE]); Ok(id)
    }

    fn verify_ring_signature(t: &[u8], a0: &[u8;57], a1: &[u8;57], s: &[u8]) -> Result<()> {
        use ed448_goldilocks_plus::{EdwardsPoint,CompressedEdwardsY,elliptic_curve::Group};
        use sha3::{Shake256,digest::{Update,ExtendableOutput,XofReader}};
        if s.len() != RING_SIGMA_SIZE { return Err(OtrError::WireFormat); }
        let c0 = &s[0..57]; let r0 = &s[57..114]; let c1 = &s[114..171]; let r1 = &s[171..228];
        let y0 = CompressedEdwardsY::try_from(a0).map_err(|_| OtrError::WireFormat)?.decompress().into_option().ok_or(OtrError::WireFormat)?;
        let y1 = CompressedEdwardsY::try_from(a1).map_err(|_| OtrError::WireFormat)?.decompress().into_option().ok_or(OtrError::WireFormat)?;
        let c0s = Self::scalar_from_wide_bytes(c0); let r0s = Self::scalar_from_wide_bytes(r0);
        let c1s = Self::scalar_from_wide_bytes(c1); let r1s = Self::scalar_from_wide_bytes(r1);
        let g = EdwardsPoint::generator();
        let r0p = g * r0s + y0 * c0s;
        let c2 = Self::scalar_from_wide_bytes(&{ let mut shake = Shake256::default(); Update::update(&mut shake, t); Update::update(&mut shake, r0p.compress().as_bytes()); Update::update(&mut shake, y1.compress().as_bytes()); let mut h=[0u8;114]; shake.finalize_xof().read(&mut h); h });
        let r1p = g * r1s + y1 * c1s;
        let call = Self::scalar_from_wide_bytes(&{ let mut shake = Shake256::default(); Update::update(&mut shake, t); Update::update(&mut shake, r0p.compress().as_bytes()); Update::update(&mut shake, r1p.compress().as_bytes()); let mut h=[0u8;114]; shake.finalize_xof().read(&mut h); h });
        if (c0s + c1s) == call || (c0s + c2) == call { Ok(()) } else { Err(OtrError::SignatureInvalid) }
    }

    fn scalar_from_wide_bytes(b: &[u8]) -> ed448_goldilocks_plus::Scalar {
        use ed448_goldilocks_plus::elliptic_curve::generic_array::GenericArray;
        let mut w=[0u8;114]; let l=b.len().min(114); w[..l].copy_from_slice(&b[..l]);
        ed448_goldilocks_plus::Scalar::from_bytes_mod_order_wide(&GenericArray::clone_from_slice(&w))
    }

    fn generate_x448_ephemeral() -> Result<(SecretBytes<56>, [u8; X448_PUB_SIZE])> {
        let mut bytes=[0u8;56]; getrandom::getrandom(&mut bytes).map_err(|_| OtrError::Internal)?;
        let sk = x448::Secret::from(bytes); Ok((SecretBytes::new(bytes), *x448::PublicKey::from(&sk).as_bytes()))
    }
    fn generate_mlkem_keypair() -> Result<(Vec<u8>,Vec<u8>)> {
        // v10.6.16: pqcrypto-kyber 0.8 (round-3 Kyber) replaced by
        // pqcrypto-mlkem 0.1.1 (FIPS 203 ML-KEM-1024).  API surface
        // (keypair / encapsulate / decapsulate / from_bytes) is identical;
        // wire format differs in the domain-separator constants embedded
        // in the FO transform.  No interop with v10.6.15 or earlier peers.
        let (pk,sk) = pqcrypto_mlkem::mlkem1024::keypair(); Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }
    fn mlkem_encapsulate(ek: &[u8]) -> Result<(Vec<u8>,Vec<u8>)> {
        let pk = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(ek).map_err(|_| OtrError::MlKem)?;
        // CRITICAL: pqcrypto_mlkem::mlkem1024::encapsulate returns
        //   (SharedSecret, Ciphertext)   - NOT (Ciphertext, SharedSecret).
        // Same footgun as the pqcrypto-kyber crate it replaced.  We
        // return (Ciphertext, SharedSecret) to match the caller's
        // destructuring `let (ct, mlkem_ss) = mlkem_encapsulate(...)`.
        let (ss, ct) = pqcrypto_mlkem::mlkem1024::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }
    fn mlkem_decapsulate(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let sk = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(sk).map_err(|_| OtrError::MlKem)?;
        let ct = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ct).map_err(|_| OtrError::MlKem)?;
        Ok(pqcrypto_mlkem::mlkem1024::decapsulate(&ct,&sk).as_bytes().to_vec())
    }
    fn mldsa_verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        let pk = pqcrypto_mldsa::mldsa87::PublicKey::from_bytes(pub_key).map_err(|_| OtrError::MlDsa)?;
        let sig = pqcrypto_mldsa::mldsa87::DetachedSignature::from_bytes(sig).map_err(|_| OtrError::MlDsa)?;
        pqcrypto_mldsa::mldsa87::verify_detached_signature(&sig, msg, &pk).map_err(|_| OtrError::SignatureInvalid)
    }
    fn x448_dh(priv_bytes: &[u8], pub_bytes: &[u8;56]) -> Result<Vec<u8>> {
        let sk = x448::Secret::from(<[u8;56]>::try_from(priv_bytes).map_err(|_| OtrError::Internal)?);
        let pk = x448::PublicKey::from_bytes(pub_bytes).ok_or(OtrError::Internal)?;
        Ok(sk.as_diffie_hellman(&pk).ok_or(OtrError::Internal)?.as_bytes().to_vec())
    }
    fn derive_session_keys(mixed_secret: &[u8], brace_key: &SecretBytes<32>, ssid: &[u8;8]) -> Result<DakeSessionKeys> {
        let root_seed = kdf::kdf_1(usage::ROOT_KEY, mixed_secret, 96);
        let extra_raw = kdf::kdf_1(usage::EXTRA_SYM_KEY, mixed_secret, 32);
        let mut root=[0u8;32]; root.copy_from_slice(&root_seed[..32]);
        let mut ck_a=[0u8;32]; ck_a.copy_from_slice(&root_seed[32..64]);
        let mut ck_b=[0u8;32]; ck_b.copy_from_slice(&root_seed[64..96]);
        let mut extra=[0u8;32]; extra.copy_from_slice(&extra_raw);
        let mut sid=[0u8;8]; sid.copy_from_slice(ssid);
        Ok(DakeSessionKeys{ root_key:SecretBytes::new(root), chain_key_send:SecretBytes::new(ck_a),
            chain_key_recv:SecretBytes::new(ck_b), brace_key:SecretBytes::new(*brace_key.expose()),
            ssid:SecretBytes::new(sid), extra_sym_key:SecretBytes::new(extra) })
    }

    pub fn take_session_keys(&mut self) -> Option<DakeSessionKeys> { self.session_keys.take() }
    pub fn get_transcript(&self) -> &[u8] { &self.transcript }
    pub fn get_peer_identity_pub(&self) -> &[u8; ED448_PUB_SIZE] { &self.peer_identity_pub }
    pub fn get_our_identity_pub(&self)  -> &[u8; ED448_PUB_SIZE] { &self.our_identity_pub }
    pub fn get_peer_mldsa_pub(&self) -> Option<&Vec<u8>> { self.peer_mldsa_pub.as_ref() }
    pub fn get_peer_profile_bytes(&self) -> Option<&Vec<u8>> { self.peer_profile_bytes.as_ref() }
}

// ─────────────────────────────────────────────────────────────────────────────
//  PyO3 binding
// ─────────────────────────────────────────────────────────────────────────────

#[pyclass(name = "RustDAKE")]
pub struct PyDake { inner: DakeState }

#[pymethods]
impl PyDake {
    #[new]
    #[pyo3(signature = (is_initiator, our_profile_bytes, our_ik_bytes, our_prekey_bytes, mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn new(
        is_initiator: bool, our_profile_bytes: &[u8], our_ik_bytes: &[u8], our_prekey_bytes: &[u8],
        mldsa_priv: Option<&[u8]>, mldsa_pub: Option<&[u8]>, sender_tag: u32,
    ) -> PyResult<Self> {
        let vc = if our_profile_bytes.len() > 1 { our_profile_bytes[1] as usize } else { return Err(PyErr::from(OtrError::TooShort{need:2,got:our_profile_bytes.len()})) };
        let hl = 2 + vc;
        if our_profile_bytes.len() < hl + 57 + 56 { return Err(PyErr::from(OtrError::TooShort{need:hl+57+56,got:our_profile_bytes.len()})) }
        let ipub: &[u8;57] = our_profile_bytes[hl..hl+57].try_into().map_err(|_|PyErr::from(OtrError::TooShort{need:57,got:our_profile_bytes.len()-hl}))?;
        let ipriv: &[u8;57] = our_ik_bytes.try_into().map_err(|_|PyErr::from(OtrError::TooShort{need:57,got:our_ik_bytes.len()}))?;
        let ppriv: &[u8;56] = our_prekey_bytes.try_into().map_err(|_|PyErr::from(OtrError::TooShort{need:56,got:our_prekey_bytes.len()}))?;
        let ppub: &[u8;56] = our_profile_bytes[hl+57..hl+57+56].try_into().map_err(|_|PyErr::from(OtrError::TooShort{need:56,got:our_profile_bytes.len().saturating_sub(hl+57)}))?;
        let mut inner = DakeState::new(ipriv, ipub, ppriv, ppub, mldsa_priv, mldsa_pub, sender_tag).map_err(PyErr::from)?;
        inner.is_initiator = is_initiator;
        inner.our_profile_bytes = our_profile_bytes.to_vec();
        Ok(Self { inner })
    }

    /// Phase 5.2 (v10.6.5): construct a RustDAKE from bytearrays and wipe
    /// the source Python-side bytearrays in-place after copying into Rust
    /// SecretBytes.
    ///
    /// Differs from `new` in two ways:
    ///   1. `our_ik_bytes` and `our_prekey_bytes` are `&Bound<PyByteArray>`
    ///      (mutable Python buffers), not `&[u8]` (read-only bytes objects).
    ///      Rust grabs the bytes via PyByteArray::to_vec(), copies into
    ///      SecretBytes inside DakeState::new, then wipes the bytearray
    ///      in-place via the safe PyByteArray::set_item API.
    ///   2. The intermediate Vec<u8> we copy through is wrapped in
    ///      SecretVec so that even if anything goes wrong between the
    ///      to_vec() call and DakeState::new(), the temporary
    ///      heap-allocated copy is zeroized on drop.
    ///
    /// After this call returns successfully, the Python-side bytearrays
    /// referenced by `our_ik_bytes` and `our_prekey_bytes` contain
    /// all-zero bytes.  The caller does not need to wipe them again,
    /// though doing so is harmless.
    ///
    /// On error, the bytearrays MAY be partially wiped or unwiped
    /// depending on which step failed.  Callers should treat them as
    /// untrusted after a failed call and wipe defensively.
    ///
    /// Closes audit-adjacent finding for long-term identity key
    /// exposure: with this constructor, the only Python-side
    /// representation of the private bytes is the bytearray we wipe,
    /// not an immutable bytes object that lingers in the heap until
    /// GC.
    #[staticmethod]
    #[pyo3(signature = (is_initiator, our_profile_bytes, our_ik_bytes, our_prekey_bytes, mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn new_from_bytearrays<'py>(
        is_initiator: bool,
        our_profile_bytes: &[u8],
        our_ik_bytes: &Bound<'py, PyByteArray>,
        our_prekey_bytes: &Bound<'py, PyByteArray>,
        mldsa_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>,
        sender_tag: u32,
    ) -> PyResult<Self> {
        use pyo3::exceptions::PyValueError;

        // ── Length sanity (fail before copying) ──
        if our_ik_bytes.len() != 57 {
            return Err(PyValueError::new_err(format!(
                "our_ik_bytes must be a bytearray of length 57 (Ed448 private), got {}",
                our_ik_bytes.len()
            )));
        }
        if our_prekey_bytes.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "our_prekey_bytes must be a bytearray of length 56 (X448 private), got {}",
                our_prekey_bytes.len()
            )));
        }

        // ── Parse the (public) profile ──
        let vc = if our_profile_bytes.len() > 1 {
            our_profile_bytes[1] as usize
        } else {
            return Err(PyErr::from(OtrError::TooShort{need:2, got:our_profile_bytes.len()}));
        };
        let hl = 2 + vc;
        if our_profile_bytes.len() < hl + 57 + 56 {
            return Err(PyErr::from(OtrError::TooShort{need:hl+57+56, got:our_profile_bytes.len()}));
        }
        let ipub: &[u8;57] = our_profile_bytes[hl..hl+57]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:57, got:our_profile_bytes.len()-hl}))?;
        let ppub: &[u8;56] = our_profile_bytes[hl+57..hl+57+56]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:56, got:our_profile_bytes.len().saturating_sub(hl+57)}))?;

        // ── Copy private bytes from bytearrays into SecretVec wrappers ──
        // SecretVec wraps the temporary heap allocation in ZeroizeOnDrop.
        // If anything between here and DakeState::new() panics or returns
        // early, the temporary copies still get wiped automatically.
        let ipriv_secret = crate::secure_mem::SecretVec::new(our_ik_bytes.to_vec());
        let ppriv_secret = crate::secure_mem::SecretVec::new(our_prekey_bytes.to_vec());

        let ipriv_arr: &[u8;57] = ipriv_secret.expose()
            .try_into()
            .map_err(|_| PyValueError::new_err("internal: identity copy wrong length"))?;
        let ppriv_arr: &[u8;56] = ppriv_secret.expose()
            .try_into()
            .map_err(|_| PyValueError::new_err("internal: prekey copy wrong length"))?;

        // ── Construct DakeState (copies bytes into SecretBytes<N>) ──
        let mut inner = DakeState::new(
            ipriv_arr, ipub, ppriv_arr, ppub,
            mldsa_priv, mldsa_pub, sender_tag,
        ).map_err(PyErr::from)?;
        inner.is_initiator = is_initiator;
        inner.our_profile_bytes = our_profile_bytes.to_vec();

        // ── Wipe the source bytearrays in-place ──
        // PyByteArray::set_item is the safe API; no unsafe needed.
        // After this loop, the Python-side bytearray that the caller
        // passed in contains all zeros — wherever Python is keeping that
        // memory, it is now zeroed.
        for i in 0..57 {
            our_ik_bytes.set_item(i, 0u8)?;
        }
        for i in 0..56 {
            our_prekey_bytes.set_item(i, 0u8)?;
        }

        // ipriv_secret and ppriv_secret drop here; ZeroizeOnDrop wipes them.

        Ok(Self { inner })
    }

    /// Phase 5.3a (v10.6.6, Option A2): construct a RustDAKE and ALSO
    /// produce the Ed448 signature over the unsigned profile body in
    /// one FFI call.
    ///
    /// This eliminates the `client_profile.identity_key.sign(...)` call
    /// in Python: the Ed448 identity private bytes go to Rust once,
    /// where (a) they're used to sign the unsigned profile body, (b)
    /// they're stored in DakeState's SecretBytes<57>, and (c) the
    /// source bytearrays are wiped in-place.
    ///
    /// The 114-byte Ed448 signature (RFC 8032 §5.2 pure Ed448, empty
    /// context) is returned to Python for appending to the unsigned
    /// profile body.  Output is byte-identical to what the Python
    /// `cryptography` library's `Ed448PrivateKey.sign(msg)` would
    /// produce for the same private bytes and the same message —
    /// callers MUST validate this with a startup self-check before
    /// trusting this path in production, because an implementation
    /// difference between `ed448-goldilocks-plus` and OpenSSL's Ed448
    /// would silently break compatibility with peers running v10.6.5
    /// or earlier.
    ///
    /// Returns: (RustDAKE, 114-byte Ed448 signature) as a Python tuple.
    /// The signature is a Py<PyBytes>.
    ///
    /// On any error (length mismatch, signing failure, etc.) returns
    /// PyValueError.  On error, the source bytearrays MAY be partially
    /// wiped; callers should treat them as untrusted and wipe
    /// defensively.
    #[staticmethod]
    #[pyo3(signature = (is_initiator, our_profile_bytes, unsigned_body, our_ik_bytes, our_prekey_bytes, mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn sign_profile_body_and_construct<'py>(
        py: Python<'py>,
        is_initiator: bool,
        our_profile_bytes: &[u8],
        unsigned_body: &[u8],
        our_ik_bytes: &Bound<'py, PyByteArray>,
        our_prekey_bytes: &Bound<'py, PyByteArray>,
        mldsa_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>,
        sender_tag: u32,
    ) -> PyResult<(Self, Py<PyBytes>)> {
        use pyo3::exceptions::PyValueError;
        use ed448_goldilocks_plus::SigningKey;
        use std::convert::TryFrom;

        // ── Length sanity ──
        if our_ik_bytes.len() != 57 {
            return Err(PyValueError::new_err(format!(
                "our_ik_bytes must be a bytearray of length 57 (Ed448 private), got {}",
                our_ik_bytes.len()
            )));
        }
        if our_prekey_bytes.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "our_prekey_bytes must be a bytearray of length 56 (X448 private), got {}",
                our_prekey_bytes.len()
            )));
        }
        if unsigned_body.is_empty() {
            return Err(PyValueError::new_err("unsigned_body must not be empty"));
        }

        // ── Parse the (public) profile for ipub/ppub ──
        let vc = if our_profile_bytes.len() > 1 {
            our_profile_bytes[1] as usize
        } else {
            return Err(PyErr::from(OtrError::TooShort{need:2, got:our_profile_bytes.len()}));
        };
        let hl = 2 + vc;
        if our_profile_bytes.len() < hl + 57 + 56 {
            return Err(PyErr::from(OtrError::TooShort{need:hl+57+56, got:our_profile_bytes.len()}));
        }
        let ipub: &[u8;57] = our_profile_bytes[hl..hl+57]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:57, got:our_profile_bytes.len()-hl}))?;
        let ppub: &[u8;56] = our_profile_bytes[hl+57..hl+57+56]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:56, got:our_profile_bytes.len().saturating_sub(hl+57)}))?;

        // ── Copy private bytes from bytearrays into SecretVec wrappers ──
        let ipriv_secret = crate::secure_mem::SecretVec::new(our_ik_bytes.to_vec());
        let ppriv_secret = crate::secure_mem::SecretVec::new(our_prekey_bytes.to_vec());

        let ipriv_arr: &[u8;57] = ipriv_secret.expose()
            .try_into()
            .map_err(|_| PyValueError::new_err("internal: identity copy wrong length"))?;
        let ppriv_arr: &[u8;56] = ppriv_secret.expose()
            .try_into()
            .map_err(|_| PyValueError::new_err("internal: prekey copy wrong length"))?;

        // ── Ed448 sign the unsigned profile body ──
        // RFC 8032 §5.2 pure Ed448 (empty context).  Matches what
        // Python `cryptography` lib's Ed448PrivateKey.sign(msg) produces
        // — caller must verify with a startup self-check before
        // trusting this path in production.
        let signing_key = SigningKey::try_from(ipriv_secret.expose())
            .map_err(|e| PyValueError::new_err(format!("Ed448 SigningKey construction failed: {:?}", e)))?;
        let signature = signing_key.sign_raw(unsigned_body);
        let sig_bytes_arr: [u8; 114] = signature.to_bytes();
        let sig_py = PyBytes::new_bound(py, &sig_bytes_arr).unbind();

        // ── Construct DakeState (copies bytes into SecretBytes<N>) ──
        let mut inner = DakeState::new(
            ipriv_arr, ipub, ppriv_arr, ppub,
            mldsa_priv, mldsa_pub, sender_tag,
        ).map_err(PyErr::from)?;
        inner.is_initiator = is_initiator;
        inner.our_profile_bytes = our_profile_bytes.to_vec();

        // ── Wipe source bytearrays in-place ──
        for i in 0..57 {
            our_ik_bytes.set_item(i, 0u8)?;
        }
        for i in 0..56 {
            our_prekey_bytes.set_item(i, 0u8)?;
        }

        // ipriv_secret, ppriv_secret, signing_key all drop here.
        // SecretVec wipes via ZeroizeOnDrop.  SigningKey's internal
        // SecretKey field SHOULD wipe on drop (the crate documents
        // zeroize on drop for keys), but we do not rely on this.
        // The key bytes will eventually be reclaimed by the allocator;
        // the most sensitive copies (in our SecretVec) are wiped.

        Ok((Self { inner }, sig_py))
    }

    /// Phase 5.3e (v10.6.12): construct a RustDAKE using `Ed448KeyHandle`
    /// and `X448KeyHandle` (Rust-owned long-term identity keys) instead
    /// of `Bound<PyByteArray>` for the private bytes.
    ///
    /// Eliminates the last code path that briefly extracts long-term
    /// private bytes into a Python-side bytearray.  The Rust handles
    /// already hold the bytes inside their own `SecretBytes` storage;
    /// this method reads from them once to construct `DakeState` and
    /// sign the profile, then returns.  Python never sees the bytes.
    ///
    /// Output: same as sign_profile_body_and_construct — a tuple
    /// `(RustDAKE, signature[114])`.
    ///
    /// Note that the handle objects passed in remain alive after this
    /// call.  Python is expected to keep them on the ClientProfile so
    /// later operations (e.g., ring signing) can use the same key
    /// material without re-extracting.
    #[staticmethod]
    #[pyo3(signature = (is_initiator, our_profile_bytes, unsigned_body, ed448_handle, x448_handle, mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn sign_profile_body_and_construct_with_handles<'py>(
        py: Python<'py>,
        is_initiator: bool,
        our_profile_bytes: &[u8],
        unsigned_body: &[u8],
        ed448_handle: &Bound<'py, crate::key_handles::Ed448KeyHandle>,
        x448_handle:  &Bound<'py, crate::key_handles::X448KeyHandle>,
        mldsa_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>,
        sender_tag: u32,
    ) -> PyResult<(Self, Py<PyBytes>)> {
        use pyo3::exceptions::PyValueError;
        use ed448_goldilocks_plus::SigningKey;
        use std::convert::TryFrom;

        // ── Parse the (public) profile for ipub/ppub ──
        // (Mirrors the validation in sign_profile_body_and_construct.)
        let vc = if our_profile_bytes.len() > 1 {
            our_profile_bytes[1] as usize
        } else {
            return Err(PyErr::from(OtrError::TooShort{need:2, got:our_profile_bytes.len()}));
        };
        let hl = 2 + vc;
        if our_profile_bytes.len() < hl + 57 + 56 {
            return Err(PyErr::from(OtrError::TooShort{need:hl+57+56, got:our_profile_bytes.len()}));
        }
        let ipub: &[u8;57] = our_profile_bytes[hl..hl+57]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:57, got:our_profile_bytes.len()-hl}))?;
        let ppub: &[u8;56] = our_profile_bytes[hl+57..hl+57+56]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort{need:56, got:our_profile_bytes.len().saturating_sub(hl+57)}))?;

        if unsigned_body.is_empty() {
            return Err(PyValueError::new_err("unsigned_body must not be empty"));
        }

        // ── Borrow handles immutably and read the private bytes ──
        // The handles own SecretBytes (ZeroizeOnDrop).  We read from
        // them here without copying out of Rust; the bytes are then
        // passed to DakeState::new which copies them into its own
        // SecretBytes fields.
        let ed448_ref = ed448_handle.borrow();
        let x448_ref  = x448_handle.borrow();

        let ipriv_slice = ed448_ref.expose_seed_slice();
        let ppriv_slice = x448_ref.expose_priv_slice();

        if ipriv_slice.len() != 57 {
            return Err(PyValueError::new_err(format!(
                "Ed448 seed wrong length in handle: {}", ipriv_slice.len()
            )));
        }
        if ppriv_slice.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "X448 private wrong length in handle: {}", ppriv_slice.len()
            )));
        }
        let ipriv_arr: &[u8;57] = ipriv_slice.try_into()
            .map_err(|_| PyValueError::new_err("Ed448 seed wrong length"))?;
        let ppriv_arr: &[u8;56] = ppriv_slice.try_into()
            .map_err(|_| PyValueError::new_err("X448 priv wrong length"))?;

        // ── Sign the unsigned profile body with Ed448 ──
        let signing_key = SigningKey::try_from(ipriv_slice)
            .map_err(|e| PyValueError::new_err(format!(
                "Ed448 SigningKey construction failed: {:?}", e
            )))?;
        let signature = signing_key.sign_raw(unsigned_body);
        let sig_bytes_arr: [u8; 114] = signature.to_bytes();
        let sig_py = PyBytes::new_bound(py, &sig_bytes_arr).unbind();

        // ── Construct DakeState ──
        let mut inner = DakeState::new(
            ipriv_arr, ipub, ppriv_arr, ppub,
            mldsa_priv, mldsa_pub, sender_tag,
        ).map_err(PyErr::from)?;
        inner.is_initiator = is_initiator;
        inner.our_profile_bytes = our_profile_bytes.to_vec();

        // No bytearray to wipe — the source is Rust-owned SecretBytes
        // that remains in the handles for future operations.  The
        // handles are zeroized on drop when Python GC's them.

        Ok((Self { inner }, sig_py))
    }

    /// Phase 5.3a self-check helper: Ed448-sign a test message using
    /// the same code path as sign_profile_body_and_construct, so the
    /// Python adapter can verify byte-identical output with the
    /// `cryptography` library before trusting Rust signing in
    /// production.
    ///
    /// Inputs:
    ///   - test_priv: 57-byte Ed448 private key
    ///   - test_msg: arbitrary message
    /// Returns: 114-byte Ed448 signature
    ///
    /// Intended ONLY for startup compatibility verification.  Do not
    /// use this for production signing.
    #[staticmethod]
    fn ed448_sign_test<'py>(
        py: Python<'py>,
        test_priv: &[u8],
        test_msg: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        use pyo3::exceptions::PyValueError;
        use ed448_goldilocks_plus::SigningKey;
        use std::convert::TryFrom;

        if test_priv.len() != 57 {
            return Err(PyValueError::new_err(format!(
                "test_priv must be 57 bytes (Ed448 private), got {}",
                test_priv.len()
            )));
        }
        let signing_key = SigningKey::try_from(test_priv)
            .map_err(|e| PyValueError::new_err(format!("Ed448 SigningKey construction failed: {:?}", e)))?;
        let signature = signing_key.sign_raw(test_msg);
        let sig_bytes_arr: [u8; 114] = signature.to_bytes();
        Ok(PyBytes::new_bound(py, &sig_bytes_arr).unbind())
    }

    #[pyo3(signature = (our_profile_bytes = None, mldsa_pub_bytes = None))]
    fn generate_dake1<'py>(&mut self, py: Python<'py>, our_profile_bytes: Option<&[u8]>, mldsa_pub_bytes: Option<&[u8]>) -> PyResult<Bound<'py, PyBytes>> {
        let profile = match our_profile_bytes { Some(p) => p.to_vec(), None => self.inner.our_profile_bytes.clone() };
        if profile.is_empty() { return Err(PyErr::from(OtrError::Internal)); }
        Ok(PyBytes::new_bound(py, &self.inner.generate_dake1(&profile, mldsa_pub_bytes).map_err(PyErr::from)?))
    }

    /// Process DAKE1 – no profile extraction needed in Python.
    fn process_dake1<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Py<PyAny>> {
        let robj = Py::new(py, Dakeresult::new())?; let rb = robj.bind(py);
        match self.inner.process_dake1(data) {
            Ok(()) => {
                rb.setattr("success", true)?;
                rb.setattr("remote_identity_pub", self.inner.get_peer_identity_pub().to_vec())?;
                rb.setattr("remote_mldsa_pub", self.inner.get_peer_mldsa_pub().cloned())?;
                rb.setattr("remote_profile_bytes", self.inner.get_peer_profile_bytes().cloned())?;
            }
            Err(e) => { rb.setattr("success", false)?; rb.setattr("error", e.to_string())?; }
        }
        Ok(robj.into_any())
    }

    fn generate_dake2<'py>(&mut self, py: Python<'py>, our_prekey_priv_bytes: Option<&[u8]>, mldsa_pub_bytes: Option<&[u8]>) -> PyResult<Py<PyAny>> {
        if self.inner.our_profile_bytes.is_empty() { return Err(PyErr::from(OtrError::Internal)); }
        let profile = self.inner.our_profile_bytes.clone();
        let (msg, keys) = self.inner.generate_dake2(&profile, our_prekey_priv_bytes, mldsa_pub_bytes).map_err(PyErr::from)?;
        let robj = Py::new(py, Dakeresult::success())?; let rb = robj.bind(py);
        rb.setattr("dake2_bytes", msg)?;
        rb.setattr("root_key", keys.root_key.expose())?;
        rb.setattr("chain_key_a", keys.chain_key_send.expose())?;
        rb.setattr("chain_key_b", keys.chain_key_recv.expose())?;
        rb.setattr("brace_key", keys.brace_key.expose())?;
        rb.setattr("ssid", keys.ssid.expose())?;
        rb.setattr("mac_key", keys.extra_sym_key.expose())?;
        Ok(robj.into_any())
    }

    /// Phase 4: generate DAKE2 and return a DakeOutput opaque handle.
    /// Unlike generate_dake2, the secret session keys NEVER become PyBytes.
    /// Call output.consume_into_ratchet(ad, is_initiator) to move the keys
    /// into a RustDoubleRatchet.  This closes the Critical Exposure Window
    /// for callers that use this path instead of generate_dake2.
    fn generate_dake2_output(
        &mut self,
        our_prekey_priv_bytes: Option<&[u8]>,
        mldsa_pub_bytes:       Option<&[u8]>,
    ) -> PyResult<DakeOutput> {
        if self.inner.our_profile_bytes.is_empty() {
            return Err(PyErr::from(OtrError::Internal));
        }
        let profile = self.inner.our_profile_bytes.clone();
        let (msg, keys) = self.inner.generate_dake2(
            &profile, our_prekey_priv_bytes, mldsa_pub_bytes,
        ).map_err(PyErr::from)?;
        // We do not have the peer's public material in generate_dake2 unless
        // it was set during process_dake1.  Pull what we have.
        let remote_identity_pub  = self.inner.get_peer_identity_pub().to_vec();
        let remote_mldsa_pub     = self.inner.get_peer_mldsa_pub().cloned();
        let remote_profile_bytes = self.inner.get_peer_profile_bytes().cloned()
            .unwrap_or_default();
        Ok(DakeOutput::from_keys_and_public(
            keys, remote_identity_pub, remote_mldsa_pub,
            remote_profile_bytes, Some(msg),
        ))
    }

    /// Process DAKE2 – parsing done in Rust, no profile bytes needed.
    fn process_dake2<'py>(&mut self, py: Python<'py>, dake2_bytes: &[u8], our_prekey_priv_bytes: Option<&[u8]>) -> PyResult<Py<PyAny>> {
        let keys = self.inner.process_dake2(dake2_bytes, our_prekey_priv_bytes).map_err(PyErr::from)?;
        let robj = Py::new(py, Dakeresult::success())?; let rb = robj.bind(py);
        rb.setattr("root_key", keys.root_key.expose())?;
        rb.setattr("chain_key_a", keys.chain_key_send.expose())?;
        rb.setattr("chain_key_b", keys.chain_key_recv.expose())?;
        rb.setattr("brace_key", keys.brace_key.expose())?;
        rb.setattr("ssid", keys.ssid.expose())?;
        rb.setattr("mac_key", keys.extra_sym_key.expose())?;
        rb.setattr("remote_identity_pub", self.inner.get_peer_identity_pub().to_vec())?;
        rb.setattr("remote_mldsa_pub", self.inner.get_peer_mldsa_pub().cloned())?;
        rb.setattr("remote_profile_bytes", self.inner.get_peer_profile_bytes().cloned())?;
        Ok(robj.into_any())
    }

    /// Phase 4: process DAKE2 and return a DakeOutput opaque handle.
    /// Unlike process_dake2, the secret session keys NEVER become PyBytes.
    /// Call output.consume_into_ratchet(ad, is_initiator) to move the keys
    /// into a RustDoubleRatchet.  This closes the Critical Exposure Window
    /// for callers that use this path instead of process_dake2.
    fn process_dake2_output(
        &mut self,
        dake2_bytes:           &[u8],
        our_prekey_priv_bytes: Option<&[u8]>,
    ) -> PyResult<DakeOutput> {
        let keys = self.inner.process_dake2(
            dake2_bytes, our_prekey_priv_bytes,
        ).map_err(PyErr::from)?;
        let remote_identity_pub  = self.inner.get_peer_identity_pub().to_vec();
        let remote_mldsa_pub     = self.inner.get_peer_mldsa_pub().cloned();
        let remote_profile_bytes = self.inner.get_peer_profile_bytes().cloned()
            .unwrap_or_default();
        Ok(DakeOutput::from_keys_and_public(
            keys, remote_identity_pub, remote_mldsa_pub,
            remote_profile_bytes, None,  // process_dake2 doesn't generate wire
        ))
    }

    fn assemble_dake3<'py>(&self, py: Python<'py>, sigma_bytes: &[u8], mldsa_sig_bytes: Option<&[u8]>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.assemble_dake3(sigma_bytes, mldsa_sig_bytes).map_err(PyErr::from)?))
    }
    fn process_dake3(&mut self, data: &[u8]) -> PyResult<()> { self.inner.process_dake3(data).map_err(PyErr::from) }
    fn get_phase(&self) -> String {
        match self.inner.phase {
            DakePhase::Idle => "IDLE", DakePhase::SentDake1 => "SENT_DAKE1", DakePhase::ReceivedDake1 => "RECEIVED_DAKE1",
            DakePhase::SentDake2 => "SENT_DAKE2", DakePhase::ReceivedDake2 => "RECEIVED_DAKE2",
            DakePhase::Established => "ESTABLISHED", DakePhase::Failed => "FAILED",
        }.to_string()
    }
    fn is_established(&self) -> bool { self.inner.phase == DakePhase::Established }
    fn get_session_keys(&mut self) -> Option<Py<PyAny>> {
        Python::with_gil(|py| {
            if let Some(keys) = self.inner.take_session_keys() {
                let robj = Py::new(py, Dakeresult::success()).ok()?; let rb = robj.bind(py);
                rb.setattr("root_key", keys.root_key.expose()).ok()?;
                rb.setattr("chain_key_a", keys.chain_key_send.expose()).ok()?;
                rb.setattr("chain_key_b", keys.chain_key_recv.expose()).ok()?;
                rb.setattr("brace_key", keys.brace_key.expose()).ok()?;
                rb.setattr("ssid", keys.ssid.expose()).ok()?;
                rb.setattr("extra_sym_key", keys.extra_sym_key.expose()).ok()?;
                Some(robj.into_any())
            } else { None }
        })
    }
}