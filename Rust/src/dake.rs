#![cfg(feature = "pq-rust")]
// src/dake.rs — OTRv4 Deniable Authenticated Key Exchange
//
// All secret material stays inside Rust.  Wire parsing of DAKE1/2 is handled
// natively so that optional ML‑DSA‑87 fields are processed correctly.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
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

// ── DIAGNOSTIC: append-write to /tmp/otr_dake.log ─────────────────────────
// Writes appear here regardless of stderr handling.  Remove before production.
fn diag_log(line: &str) {
    use std::io::Write;
    use std::fs::OpenOptions;
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("/tmp/otr_dake.log") {
        let _ = writeln!(f, "{}", line);
    }
}



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

        diag_log(&format!("[DH-RESP] our_eph_priv first4   = {:02x?}", &self.our_eph_x448_priv.expose()[..4]));
        diag_log(&format!("[DH-RESP] our_eph_pub  first4   = {:02x?}", &self.our_eph_x448_pub[..4]));
        diag_log(&format!("[DH-RESP] our_prekey_priv first4= {:02x?}", &prekey_priv_bytes[..4]));
        diag_log(&format!("[DH-RESP] our_prekey_pub  first4= {:02x?}", &self.our_prekey_pub[..4]));
        diag_log(&format!("[DH-RESP] peer_eph_pub  first4  = {:02x?}", &self.peer_eph_x448_pub[..4]));
        diag_log(&format!("[DH-RESP] peer_prekey_pub first4= {:02x?}", &self.peer_prekey_pub()[..4]));

        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_prekey_pub())?;
        let dh3 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        diag_log(&format!("[DH-RESP] dh1 first4 = {:02x?}", &dh1[..4]));
        diag_log(&format!("[DH-RESP] dh2 first4 = {:02x?}", &dh2[..4]));
        diag_log(&format!("[DH-RESP] dh3 first4 = {:02x?}", &dh3[..4]));
        let (ct, mlkem_ss) = Self::mlkem_encapsulate(&self.peer_mlkem_ek)?;
        diag_log(&format!("[DH-RESP] mlkem_ss first4 = {:02x?}", &mlkem_ss[..4]));
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1); combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3); combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        let ssid = { let mut a = [0u8; 8]; a.copy_from_slice(&kdf::kdf_1(usage::SSID, &mixed_secret, 8)); a };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);
        diag_log(&format!("[DH-RESP] mac_key first8 = {:02x?}", &mac_key[..8]));

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
        diag_log(&format!("[DH-RESP] wire_body.len() = {}", wire_body.len()));

        // ── CRITICAL FIX (Patch-3.5): MAC over the actual wire body bytes ──
        // The previous version MACed over (transcript || eph_pub || ct ||
        // client_profile), excluding both MSG_DAKE2 and the ML-DSA pub.  The
        // parser MACs over data[..off] which IS the full wire body.  These
        // disagreed and caused MAC verification to fail.
        let mac = kdf::hmac_sha3_512(&mac_key, &wire_body);
        diag_log(&format!("[DH-RESP] computed MAC first8 = {:02x?}", &mac[..8]));

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

        diag_log(&format!("[DH-INIT] our_eph_priv first4   = {:02x?}", &self.our_eph_x448_priv.expose()[..4]));
        diag_log(&format!("[DH-INIT] our_eph_pub  first4   = {:02x?}", &self.our_eph_x448_pub[..4]));
        diag_log(&format!("[DH-INIT] our_prekey_priv first4= {:02x?}", &prekey_priv_bytes[..4]));
        diag_log(&format!("[DH-INIT] our_prekey_pub  first4= {:02x?}", &self.our_prekey_pub[..4]));
        diag_log(&format!("[DH-INIT] peer_eph_pub  first4  = {:02x?}", &self.peer_eph_x448_pub[..4]));
        diag_log(&format!("[DH-INIT] peer_prekey_pub first4= {:02x?}", &self.peer_prekey_pub()[..4]));

        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        let dh3 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_prekey_pub())?;
        diag_log(&format!("[DH-INIT] dh1 first4 = {:02x?}", &dh1[..4]));
        diag_log(&format!("[DH-INIT] dh2 first4 = {:02x?}", &dh2[..4]));
        diag_log(&format!("[DH-INIT] dh3 first4 = {:02x?}", &dh3[..4]));
        let mlkem_ss = Self::mlkem_decapsulate(self.our_mlkem_sk.expose(), &mlkem_ct)?;
        diag_log(&format!("[DH-INIT] mlkem_ss first4 = {:02x?}", &mlkem_ss[..4]));
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1); combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3); combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        let ssid = { let mut a = [0u8; 8]; a.copy_from_slice(&kdf::kdf_1(usage::SSID, &mixed_secret, 8)); a };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);
        diag_log(&format!("[DH-INIT] mac_key first8 = {:02x?}", &mac_key[..8]));
        diag_log(&format!("[DH-INIT] message_body.len() = {}", message_body.len()));

        let expected_mac = kdf::hmac_sha3_512(&mac_key, message_body);
        diag_log(&format!("[DH-INIT] expected MAC first8 = {:02x?}", &expected_mac[..8]));
        diag_log(&format!("[DH-INIT] received MAC first8 = {:02x?}", &mac_received[..8]));

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
        let (pk,sk) = pqcrypto_kyber::kyber1024::keypair(); Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }
    fn mlkem_encapsulate(ek: &[u8]) -> Result<(Vec<u8>,Vec<u8>)> {
        let pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(ek).map_err(|_| OtrError::MlKem)?;
        // CRITICAL: pqcrypto_kyber::kyber1024::encapsulate returns
        //   (SharedSecret, Ciphertext)   — NOT (Ciphertext, SharedSecret).
        // We return (Ciphertext, SharedSecret) to match the caller's
        // destructuring `let (ct, mlkem_ss) = mlkem_encapsulate(...)`.
        // Confirmed via diagnostic build: previous order produced 32-byte
        // "ciphertext" on the wire (the SS) instead of 1568 bytes, causing
        // remote parser to fail with "Invalid wire format" at MLKEM_CT offset.
        let (ss, ct) = pqcrypto_kyber::kyber1024::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }
    fn mlkem_decapsulate(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(sk).map_err(|_| OtrError::MlKem)?;
        let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ct).map_err(|_| OtrError::MlKem)?;
        Ok(pqcrypto_kyber::kyber1024::decapsulate(&ct,&sk).as_bytes().to_vec())
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