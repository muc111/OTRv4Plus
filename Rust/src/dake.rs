#![cfg(feature = "pq-rust")]
// src/dake.rs — OTRv4 Deniable Authenticated Key Exchange
//
// Uses stable pqcrypto‑kyber (Kyber1024) and pqcrypto‑dilithium (Dilithium5).

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::ZeroizeOnDrop;

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

    // ML‑KEM‑1024 secret key (decapsulation) – Kyber1024 secret key is 3168 bytes
    our_mlkem_sk:      SecretVec,
    our_mlkem_ek:      [u8; MLKEM_EK_SIZE],

    peer_identity_pub: [u8; ED448_PUB_SIZE],
    peer_eph_x448_pub: [u8; X448_PUB_SIZE],
    peer_mlkem_ek:     [u8; MLKEM_EK_SIZE],
    peer_mldsa_pub:    Option<Vec<u8>>,
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
            our_identity_priv: SecretBytes::new(ip),
            our_identity_pub:  ipub,
            our_prekey_priv:   SecretBytes::new(pp),
            our_prekey_pub:    ppub,
            our_mldsa_priv:    mldsa_priv.map(SecretVec::from_slice),
            our_mldsa_pub:     mldsa_pub.map(|b| b.to_vec()),
            our_eph_x448_priv: eph_priv,
            our_eph_x448_pub:  eph_pub,
            our_mlkem_sk:      SecretVec::from_slice(&sk),
            our_mlkem_ek:      mlek,
            peer_identity_pub: [0u8; ED448_PUB_SIZE],
            peer_eph_x448_pub: [0u8; X448_PUB_SIZE],
            peer_mlkem_ek:     [0u8; MLKEM_EK_SIZE],
            peer_mldsa_pub:    None,
            session_keys:      None,
            transcript:        Vec::new(),
            phase:             DakePhase::Idle,
            is_initiator:      false,
            sender_tag,
            receiver_tag:      0,
        })
    }

    // ── DAKE message methods (unchanged) ──────────────────────────

    pub fn generate_dake1(&mut self, client_profile: &[u8]) -> Result<Vec<u8>> {
        if self.phase != DakePhase::Idle { return Err(OtrError::Dake("wrong phase")); }
        self.is_initiator = true;
        let mut msg = vec![MSG_DAKE1];
        msg.extend_from_slice(&self.our_eph_x448_pub);
        msg.extend_from_slice(&self.our_mlkem_ek);
        msg.extend_from_slice(client_profile);
        if let Some(p) = &self.our_mldsa_pub { msg.push(0x01); msg.extend_from_slice(p); }
        else { msg.push(0x00); }
        self.transcript.extend_from_slice(&msg);
        self.phase = DakePhase::SentDake1;
        Ok(msg)
    }

    pub fn process_dake1(&mut self, data: &[u8], peer_profile: &[u8]) -> Result<()> {
        if data.len() < 1 + X448_PUB_SIZE + MLKEM_EK_SIZE + 1 {
            return Err(OtrError::TooShort { need: 1+X448_PUB_SIZE+MLKEM_EK_SIZE+1, got: data.len() });
        }
        if data[0] != MSG_DAKE1 { return Err(OtrError::WireFormat); }
        let mut off = 1;
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off+X448_PUB_SIZE]); off += X448_PUB_SIZE;
        self.peer_mlkem_ek.copy_from_slice(&data[off..off+MLKEM_EK_SIZE]);     off += MLKEM_EK_SIZE;
        off += peer_profile.len();
        if off < data.len() {
            let flag = data[off]; off += 1;
            if flag == 0x01 && off+MLDSA_PUB_SIZE <= data.len() {
                self.peer_mldsa_pub = Some(data[off..off+MLDSA_PUB_SIZE].to_vec());
            }
        }
        self.transcript.extend_from_slice(data);
        self.phase = DakePhase::ReceivedDake1;
        Ok(())
    }

    pub fn generate_dake2(&mut self, client_profile: &[u8]) -> Result<Vec<u8>> {
        if self.phase != DakePhase::ReceivedDake1 { return Err(OtrError::Dake("wrong phase")); }
        let (ct, mlkem_ss) = Self::mlkem_encapsulate(&self.peer_mlkem_ek)?;
        let x448_ss = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let brace_key    = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);
        let mixed_secret = Self::mix_dh_brace(&x448_ss, brace_key.expose());
        let ssid         = kdf::derive_ssid(&mixed_secret);
        let mac_key      = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);
        let mut mac_input = self.transcript.clone();
        mac_input.extend_from_slice(&self.our_eph_x448_pub);
        mac_input.extend_from_slice(&ct);
        mac_input.extend_from_slice(client_profile);
        let mac = kdf::hmac_sha3_512(&mac_key, &mac_input);
        let mut msg = vec![MSG_DAKE2];
        msg.extend_from_slice(&self.our_eph_x448_pub);
        msg.extend_from_slice(&ct);
        msg.extend_from_slice(client_profile);
        if let Some(p) = &self.our_mldsa_pub { msg.push(0x01); msg.extend_from_slice(p); }
        else { msg.push(0x00); }
        msg.extend_from_slice(&mac);
        self.transcript.extend_from_slice(&msg);
        self.session_keys = Some(Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?);
        self.phase = DakePhase::SentDake2;
        Ok(msg)
    }

    pub fn process_dake2(&mut self, data: &[u8], peer_profile: &[u8]) -> Result<()> {
        if self.phase != DakePhase::SentDake1 { return Err(OtrError::Dake("wrong phase")); }
        if data[0] != MSG_DAKE2 { return Err(OtrError::WireFormat); }
        let mut off = 1;
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off+X448_PUB_SIZE]); off += X448_PUB_SIZE;
        let mlkem_ct = data[off..off+MLKEM_CT_SIZE].to_vec();                  off += MLKEM_CT_SIZE;
        off += peer_profile.len();
        if off < data.len().saturating_sub(MAC_SIZE) {
            let flag = data[off]; off += 1;
            if flag == 0x01 && off+MLDSA_PUB_SIZE <= data.len().saturating_sub(MAC_SIZE) {
                self.peer_mldsa_pub = Some(data[off..off+MLDSA_PUB_SIZE].to_vec());
                off += MLDSA_PUB_SIZE;
            }
        }
        let mac_received = &data[off..off+MAC_SIZE];
        let mlkem_ss = Self::mlkem_decapsulate(self.our_mlkem_sk.expose(), &mlkem_ct)?;
        let x448_ss = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let brace_key    = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);
        let mixed_secret = Self::mix_dh_brace(&x448_ss, brace_key.expose());
        let ssid         = kdf::derive_ssid(&mixed_secret);
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);
        let mut mac_input = self.transcript.clone();
        mac_input.extend_from_slice(&self.peer_eph_x448_pub);
        mac_input.extend_from_slice(&mlkem_ct);
        mac_input.extend_from_slice(peer_profile);
        let expected_mac = kdf::hmac_sha3_512(&mac_key, &mac_input);
        if !crate::secure_mem::ct_eq(mac_received, &expected_mac) {
            return Err(OtrError::AeadDecrypt);
        }
        self.transcript.extend_from_slice(data);
        self.session_keys = Some(Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?);
        self.phase = DakePhase::ReceivedDake2;
        Ok(())
    }

    pub fn take_session_keys(&mut self) -> Option<DakeSessionKeys> { self.session_keys.take() }
    pub fn get_transcript(&self)        -> &[u8]                   { &self.transcript }
    pub fn get_peer_identity_pub(&self) -> &[u8; ED448_PUB_SIZE]   { &self.peer_identity_pub }
    pub fn get_our_identity_pub(&self)  -> &[u8; ED448_PUB_SIZE]   { &self.our_identity_pub }

    // ═════════════════════════════════════════════════════════════════
    //  Crypto helpers – stable pqcrypto‑* APIs
    // ═════════════════════════════════════════════════════════════════

    fn generate_x448_ephemeral() -> Result<(SecretBytes<56>, [u8; X448_PUB_SIZE])> {
        use x448::{Secret, PublicKey};
        let mut bytes = [0u8; 56];
        getrandom::getrandom(&mut bytes).map_err(|_| OtrError::Internal)?;
        let sk = Secret::from(bytes);
        let pk = PublicKey::from(&sk);
        Ok((SecretBytes::new(bytes), *pk.as_bytes()))
    }

    // ── ML‑KEM‑1024 (Kyber1024) ───────────────────────────────────

    fn generate_mlkem_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};
        let (pk, sk) = kyber1024::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn mlkem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};
        let pk = kyber1024::PublicKey::from_bytes(ek_bytes)
            .map_err(|_| OtrError::MlKem)?;
        let (ct, ss) = kyber1024::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn mlkem_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{SecretKey, Ciphertext, SharedSecret};
        let sk = kyber1024::SecretKey::from_bytes(sk_bytes)
            .map_err(|_| OtrError::MlKem)?;
        let ct = kyber1024::Ciphertext::from_bytes(ct_bytes)
            .map_err(|_| OtrError::MlKem)?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }

    // ── ML‑DSA‑87 (Dilithium5) ────────────────────────────────────

    fn mldsa_sign(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{SecretKey, DetachedSignature};
        let sk = dilithium5::SecretKey::from_bytes(priv_key)
            .map_err(|_| OtrError::MlDsa)?;
        let sig = dilithium5::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn mldsa_verify(pub_key: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
        let pk = dilithium5::PublicKey::from_bytes(pub_key)
            .map_err(|_| OtrError::MlDsa)?;
        let sig = dilithium5::DetachedSignature::from_bytes(sig_bytes)
            .map_err(|_| OtrError::MlDsa)?;
        dilithium5::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| OtrError::SignatureInvalid)
    }

    // ── X448 DH (unchanged) ─────────────────────────────────────

    fn x448_dh(priv_bytes: &[u8], pub_bytes: &[u8; 56]) -> Result<Vec<u8>> {
        use x448::{Secret, PublicKey};
        let sk_arr: [u8; 56] = priv_bytes.try_into().map_err(|_| OtrError::Internal)?;
        let sk = Secret::from(sk_arr);
        let pk = PublicKey::from_bytes(pub_bytes).ok_or(OtrError::Internal)?;
        let ss = sk.as_diffie_hellman(&pk).ok_or(OtrError::Internal)?;
        Ok(ss.as_bytes().to_vec())
    }

    fn mix_dh_brace(x448_ss: &[u8], brace_key: &[u8]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(x448_ss.len() + brace_key.len());
        combined.extend_from_slice(x448_ss);
        combined.extend_from_slice(brace_key);
        kdf::kdf_1(usage::SHARED_SECRET, &combined, 64)
    }

    fn derive_session_keys(mixed_secret: &[u8], brace_key: &SecretBytes<32>, ssid: &[u8; 8]) -> Result<DakeSessionKeys> {
        let root_raw  = kdf::kdf_1(usage::ROOT_KEY,      mixed_secret, 128);
        let extra_raw = kdf::kdf_1(usage::EXTRA_SYM_KEY, mixed_secret, 32);
        let mut root  = [0u8; 64]; root.copy_from_slice(&root_raw[..64]);
        let mut chain = [0u8; 64]; chain.copy_from_slice(&root_raw[64..]);
        let mut bk    = [0u8; 32]; bk.copy_from_slice(brace_key.expose());
        let mut sid   = [0u8; 8];  sid.copy_from_slice(ssid);
        let mut extra = [0u8; 32]; extra.copy_from_slice(&extra_raw);
        Ok(DakeSessionKeys {
            root_key:       SecretBytes::new(root),
            chain_key_send: SecretBytes::new(chain),
            chain_key_recv: SecretBytes::new(chain),
            brace_key:      SecretBytes::new(bk),
            ssid:           SecretBytes::new(sid),
            extra_sym_key:  SecretBytes::new(extra),
        })
    }
}

// ── PyO3 bindings (unchanged) ─────────────────────────────────────

#[pyclass(name = "RustDAKE")]
pub struct PyDake { inner: DakeState }

#[pymethods]
impl PyDake {
    #[new]
    #[pyo3(signature = (identity_priv, identity_pub, prekey_priv, prekey_pub,
                        mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn new(
        identity_priv: &[u8], identity_pub: &[u8],
        prekey_priv:   &[u8], prekey_pub:   &[u8],
        mldsa_priv: Option<&[u8]>, mldsa_pub: Option<&[u8]>,
        sender_tag: u32,
    ) -> PyResult<Self> {
        macro_rules! coerce {
            ($s:expr, $n:expr) => {
                $s.try_into().map_err(|_| PyErr::from(OtrError::TooShort { need: $n, got: $s.len() }))?
            }
        }
        let ip:  &[u8; 57]            = coerce!(identity_priv, 57);
        let ipu: &[u8; ED448_PUB_SIZE] = coerce!(identity_pub,  ED448_PUB_SIZE);
        let pp:  &[u8; 56]             = coerce!(prekey_priv,   56);
        let ppu: &[u8; X448_PUB_SIZE]  = coerce!(prekey_pub,    X448_PUB_SIZE);
        Ok(Self { inner: DakeState::new(ip, ipu, pp, ppu, mldsa_priv, mldsa_pub, sender_tag)
            .map_err(PyErr::from)? })
    }

    fn generate_dake1<'py>(&mut self, py: Python<'py>, client_profile: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.generate_dake1(client_profile).map_err(PyErr::from)?))
    }
    fn process_dake1(&mut self, data: &[u8], peer_profile: &[u8]) -> PyResult<()> {
        self.inner.process_dake1(data, peer_profile).map_err(PyErr::from)
    }
    fn generate_dake2<'py>(&mut self, py: Python<'py>, client_profile: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.generate_dake2(client_profile).map_err(PyErr::from)?))
    }
    fn process_dake2(&mut self, data: &[u8], peer_profile: &[u8]) -> PyResult<()> {
        self.inner.process_dake2(data, peer_profile).map_err(PyErr::from)
    }
    fn get_transcript<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.get_transcript())
    }
    fn generate_dake3_with_sigma<'py>(&mut self, py: Python<'py>, sigma: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut msg = vec![MSG_DAKE3];
        msg.extend_from_slice(sigma);
        if let Some(ref priv_key) = self.inner.our_mldsa_priv {
            let sig = DakeState::mldsa_sign(priv_key.expose(), self.inner.get_transcript())
                .map_err(PyErr::from)?;
            msg.push(0x01); msg.extend_from_slice(&sig);
        } else { msg.push(0x00); }
        self.inner.transcript.extend_from_slice(&msg);
        self.inner.phase = DakePhase::Established;
        Ok(PyBytes::new_bound(py, &msg))
    }
    fn process_dake3(&mut self, data: &[u8]) -> PyResult<()> {
        if data.is_empty() || data[0] != MSG_DAKE3 { return Err(PyErr::from(OtrError::WireFormat)); }
        self.inner.transcript.extend_from_slice(data);
        self.inner.phase = DakePhase::Established;
        Ok(())
    }
    fn is_established(&self) -> bool { self.inner.phase == DakePhase::Established }
    fn is_initiator(&self)   -> bool { self.inner.is_initiator }
    fn get_phase(&self) -> &'static str {
        match self.inner.phase {
            DakePhase::Idle => "IDLE", DakePhase::SentDake1 => "SENT_DAKE1",
            DakePhase::ReceivedDake1 => "GOT_DAKE1", DakePhase::SentDake2 => "SENT_DAKE2",
            DakePhase::ReceivedDake2 => "GOT_DAKE2", DakePhase::Established => "ESTABLISHED",
            DakePhase::Failed => "FAILED",
        }
    }
    fn take_session_keys<'py>(&mut self, py: Python<'py>) -> PyResult<(
        Bound<'py, PyBytes>, Bound<'py, PyBytes>, Bound<'py, PyBytes>,
        Bound<'py, PyBytes>, Bound<'py, PyBytes>,
    )> {
        let keys = self.inner.take_session_keys()
            .ok_or_else(|| PyErr::from(OtrError::Dake("no session keys")))?;
        Ok((
            PyBytes::new_bound(py, keys.root_key.expose_slice()),
            PyBytes::new_bound(py, keys.chain_key_send.expose_slice()),
            PyBytes::new_bound(py, keys.brace_key.expose_slice()),
            PyBytes::new_bound(py, keys.ssid.expose_slice()),
            PyBytes::new_bound(py, keys.extra_sym_key.expose_slice()),
        ))
    }
    fn get_peer_identity_pub<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.get_peer_identity_pub())
    }
    fn get_our_identity_pub<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.get_our_identity_pub())
    }
}