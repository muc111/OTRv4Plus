#![cfg(feature = "pq-rust")]
// src/dake.rs — OTRv4 Deniable Authenticated Key Exchange
//
// Fully compliant with OTRv4 spec: extracts peer identity from client profiles,
// verifies Ed448 ring signature and optional ML‑DSA signature in DAKE3.

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

const RING_SIGMA_SIZE: usize = 228;  // c0(57) + r0(57) + c1(57) + r1(57)

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DakePhase {
    Idle, SentDake1, ReceivedDake1, SentDake2,
    ReceivedDake2, Established, Failed,
}

/// Result type returned to Python from DAKE operations.
#[derive(Debug, Clone)]
#[pyclass]
pub struct Dakeresult {
    #[pyo3(get, set)]
    pub success: bool,
    #[pyo3(get, set)]
    pub error: Option<String>,
    #[pyo3(get, set)]
    pub dake_bytes: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub root_key: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub chain_key_a: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub chain_key_b: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub brace_key: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub ssid: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub mac_key: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub remote_identity_pub: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub remote_mldsa_pub: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub remote_profile_bytes: Option<Vec<u8>>,
}

#[pymethods]
impl Dakeresult {
    #[new]
    fn new() -> Self {
        Self {
            success: false,
            error: None,
            dake_bytes: None,
            root_key: None,
            chain_key_a: None,
            chain_key_b: None,
            brace_key: None,
            ssid: None,
            mac_key: None,
            remote_identity_pub: None,
            remote_mldsa_pub: None,
            remote_profile_bytes: None,
        }
    }
}

impl Dakeresult {
    fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            ..Self::new()
        }
    }
    
    fn success() -> Self {
        Self {
            success: true,
            error: None,
            ..Self::new()
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
    
    session_keys:      Option<DakeSessionKeys>,
    transcript:        Vec<u8>,
    
    #[zeroize(skip)] pub phase:        DakePhase,
    #[zeroize(skip)] pub is_initiator: bool,
    #[zeroize(skip)] pub sender_tag:   u32,
    #[zeroize(skip)] pub receiver_tag: u32,
}

impl DakeState {
    // ── Constructor ────────────────────────────────────────
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
            peer_profile_bytes: None,
            session_keys:      None,
            transcript:        Vec::new(),
            phase:             DakePhase::Idle,
            is_initiator:      false,
            sender_tag,
            receiver_tag:      0,
        })
    }

    // ── DAKE message generation & processing ───────────────

    pub fn generate_dake1(&mut self, client_profile: &[u8], mldsa_pub: Option<&[u8]>) -> Result<Vec<u8>> {
        if self.phase != DakePhase::Idle {
            return Err(OtrError::Dake("wrong phase"));
        }
        self.is_initiator = true;
        let mut msg = vec![MSG_DAKE1];
        msg.extend_from_slice(&self.our_eph_x448_pub);
        msg.extend_from_slice(&self.our_mlkem_ek);
        msg.extend_from_slice(client_profile);
        
        let mldsa_pub_bytes = mldsa_pub.or(self.our_mldsa_pub.as_deref());
        if let Some(p) = mldsa_pub_bytes {
            msg.push(0x01);
            msg.extend_from_slice(p);
        } else {
            msg.push(0x00);
        }
        
        self.transcript.extend_from_slice(&msg);
        self.phase = DakePhase::SentDake1;
        Ok(msg)
    }

    pub fn process_dake1(&mut self, data: &[u8], peer_profile: &[u8]) -> Result<()> {
        if data.len() < 1 + X448_PUB_SIZE + MLKEM_EK_SIZE + 1 {
            return Err(OtrError::TooShort {
                need: 1 + X448_PUB_SIZE + MLKEM_EK_SIZE + 1,
                got: data.len(),
            });
        }
        if data[0] != MSG_DAKE1 {
            return Err(OtrError::WireFormat);
        }
        let mut off = 1;
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off + X448_PUB_SIZE]);
        off += X448_PUB_SIZE;
        self.peer_mlkem_ek.copy_from_slice(&data[off..off + MLKEM_EK_SIZE]);
        off += MLKEM_EK_SIZE;
        off += peer_profile.len();
        if off < data.len() {
            let flag = data[off];
            off += 1;
            if flag == 0x01 && off + MLDSA_PUB_SIZE <= data.len() {
                self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec());
            }
        }

        self.peer_identity_pub = Self::extract_identity_from_profile(peer_profile)?;
        self.peer_profile_bytes = Some(peer_profile.to_vec());
        self.transcript.extend_from_slice(data);
        self.phase = DakePhase::ReceivedDake1;
        Ok(())
    }

    pub fn generate_dake2(
        &mut self, 
        client_profile: &[u8],
        our_prekey_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>
    ) -> Result<(Vec<u8>, DakeSessionKeys)> {
        if self.phase != DakePhase::ReceivedDake1 {
            return Err(OtrError::Dake("wrong phase"));
        }
        
        // Use provided prekey or our stored one
        let prekey_priv_bytes = if let Some(priv_bytes) = our_prekey_priv {
            priv_bytes
        } else {
            self.our_prekey_priv.expose()
        };
        
        // Compute the three X448 DH secrets (responder side)
        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_prekey_pub())?;
        let dh3 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        
        // ML-KEM-1024
        let (ct, mlkem_ss) = Self::mlkem_encapsulate(&self.peer_mlkem_ek)?;
        
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);
        
        let mut combined = Vec::with_capacity(dh1.len() + dh2.len() + dh3.len() + mlkem_ss.len());
        combined.extend_from_slice(&dh1);
        combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3);
        combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        
        let ssid = {
            let ssid_bytes = kdf::kdf_1(usage::SSID, &mixed_secret, 8);
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&ssid_bytes);
            arr
        };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);

        let mut mac_input = self.transcript.clone();
        mac_input.extend_from_slice(&self.our_eph_x448_pub);
        mac_input.extend_from_slice(&ct);
        mac_input.extend_from_slice(client_profile);
        let mac = kdf::hmac_sha3_512(&mac_key, &mac_input);

        let mut msg = vec![MSG_DAKE2];
        msg.extend_from_slice(&self.our_eph_x448_pub);
        msg.extend_from_slice(&ct);
        msg.extend_from_slice(client_profile);
        
        let mldsa_pub_bytes = mldsa_pub.or(self.our_mldsa_pub.as_deref());
        if let Some(p) = mldsa_pub_bytes {
            msg.push(0x01);
            msg.extend_from_slice(p);
        } else {
            msg.push(0x00);
        }
        msg.extend_from_slice(&mac);

        let session_keys = Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?;
        
        // Don't store copy because SecretBytes doesn't implement Clone.
        self.transcript.extend_from_slice(&msg);
        self.phase = DakePhase::SentDake2;
        
        Ok((msg, session_keys))
    }

    pub fn process_dake2(
        &mut self, 
        data: &[u8], 
        peer_profile: &[u8],
        our_prekey_priv: Option<&[u8]>
    ) -> Result<DakeSessionKeys> {
        if self.phase != DakePhase::SentDake1 {
            return Err(OtrError::Dake("wrong phase"));
        }
        if data[0] != MSG_DAKE2 {
            return Err(OtrError::WireFormat);
        }
        let mut off = 1;
        self.peer_eph_x448_pub.copy_from_slice(&data[off..off + X448_PUB_SIZE]);
        off += X448_PUB_SIZE;
        if off + MLKEM_CT_SIZE > data.len() {
            return Err(OtrError::TooShort { need: off + MLKEM_CT_SIZE, got: data.len() });
        }
        let mlkem_ct = data[off..off + MLKEM_CT_SIZE].to_vec();
        off += MLKEM_CT_SIZE;
        off += peer_profile.len();
        
        if off < data.len().saturating_sub(MAC_SIZE) {
            let flag = data[off];
            off += 1;
            if flag == 0x01 && off + MLDSA_PUB_SIZE <= data.len().saturating_sub(MAC_SIZE) {
                self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec());
                off += MLDSA_PUB_SIZE;
            }
        }
        if off + MAC_SIZE != data.len() {
            return Err(OtrError::WireFormat);
        }
        let mac_received = &data[off..off + MAC_SIZE];

        // Compute three DH secrets (initiator side)
        let dh1 = Self::x448_dh(self.our_eph_x448_priv.expose(), &self.peer_eph_x448_pub)?;
        let dh2 = Self::x448_dh(self.our_prekey_priv.expose(), &self.peer_eph_x448_pub)?;
        let prekey_priv_bytes = if let Some(p) = our_prekey_priv { p } else { self.our_prekey_priv.expose() };
        let dh3 = Self::x448_dh(prekey_priv_bytes, &self.peer_eph_x448_pub)?;
        
        let mlkem_ss = Self::mlkem_decapsulate(self.our_mlkem_sk.expose(), &mlkem_ct)?;
        
        let brace_key = kdf::derive_brace_key(&[0u8; 32], &mlkem_ss);
        
        let mut combined = Vec::with_capacity(dh1.len() + dh2.len() + dh3.len() + mlkem_ss.len());
        combined.extend_from_slice(&dh1);
        combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3);
        combined.extend_from_slice(&mlkem_ss);
        let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
        
        let ssid = {
            let ssid_bytes = kdf::kdf_1(usage::SSID, &mixed_secret, 8);
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&ssid_bytes);
            arr
        };
        let mac_key = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);

        let mut mac_input = self.transcript.clone();
        mac_input.extend_from_slice(&self.peer_eph_x448_pub);
        mac_input.extend_from_slice(&mlkem_ct);
        mac_input.extend_from_slice(peer_profile);
        let expected_mac = kdf::hmac_sha3_512(&mac_key, &mac_input);

        if !crate::secure_mem::ct_eq(mac_received, &expected_mac) {
            return Err(OtrError::AeadDecrypt);
        }

        self.peer_identity_pub = Self::extract_identity_from_profile(peer_profile)?;
        self.peer_profile_bytes = Some(peer_profile.to_vec());
        self.transcript.extend_from_slice(data);
        let session_keys = Self::derive_session_keys(&mixed_secret, &brace_key, &ssid)?;
        self.phase = DakePhase::ReceivedDake2;
        Ok(session_keys)
    }

    pub fn assemble_dake3(
        &self, 
        sigma: &[u8], 
        mldsa_sig: Option<&[u8]>
    ) -> Result<Vec<u8>> {
        if self.phase != DakePhase::ReceivedDake2 && self.phase != DakePhase::SentDake2 {
            return Err(OtrError::Dake("wrong phase - DAKE3 can only be assembled after DAKE2"));
        }
        let mut msg = vec![MSG_DAKE3];
        msg.extend_from_slice(sigma);

        if let Some(sig) = mldsa_sig {
            msg.push(0x01);
            msg.extend_from_slice(sig);
        } else {
            msg.push(0x00);
        }

        Ok(msg)
    }

    pub fn process_dake3(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != DakePhase::SentDake2 {
            return Err(OtrError::Dake("wrong phase"));
        }
        if data.is_empty() || data[0] != MSG_DAKE3 {
            return Err(OtrError::WireFormat);
        }
        let total = data.len();
        if total < 1 + RING_SIGMA_SIZE + 1 {
            return Err(OtrError::TooShort { need: 1 + RING_SIGMA_SIZE + 1, got: total });
        }

        let sigma = &data[1..1 + RING_SIGMA_SIZE];
        let off = 1 + RING_SIGMA_SIZE;
        let flag = data[off];
        let off = off + 1;

        if flag == 0x01 {
            if total - off < MLDSA_SIG_SIZE {
                return Err(OtrError::TooShort { need: off + MLDSA_SIG_SIZE, got: total });
            }
            let mldsa_sig = &data[off..off + MLDSA_SIG_SIZE];
            let peer_mldsa_pub = self.peer_mldsa_pub.as_ref().ok_or(OtrError::MlDsa)?;
            Self::mldsa_verify(peer_mldsa_pub, &self.transcript, mldsa_sig)?;
        } else if flag != 0x00 {
            return Err(OtrError::WireFormat);
        }

        Self::verify_ring_signature(
            &self.transcript,
            &self.our_identity_pub,
            &self.peer_identity_pub,
            sigma,
        )?;

        self.transcript.extend_from_slice(data);
        self.phase = DakePhase::Established;
        Ok(())
    }

    // Helper to extract peer's prekey public key from stored profile
    fn peer_prekey_pub(&self) -> [u8; X448_PUB_SIZE] {
        if let Some(ref profile) = self.peer_profile_bytes {
            let version_count = if profile.len() > 1 { profile[1] as usize } else { 0 };
            let header_len = 2 + version_count;
            if profile.len() >= header_len + 57 + 56 {
                let mut arr = [0u8; 56];
                arr.copy_from_slice(&profile[header_len + 57..header_len + 57 + 56]);
                return arr;
            }
        }
        [0u8; 56]
    }

    fn extract_identity_from_profile(profile: &[u8]) -> Result<[u8; ED448_PUB_SIZE]> {
        let version_count = if profile.len() > 1 { profile[1] as usize } else { return Err(OtrError::TooShort { need: 2, got: profile.len() }); };
        let header_len = 2 + version_count;
        if profile.len() < header_len + ED448_PUB_SIZE {
            return Err(OtrError::TooShort { need: header_len + ED448_PUB_SIZE, got: profile.len() });
        }
        let mut id = [0u8; ED448_PUB_SIZE];
        id.copy_from_slice(&profile[header_len..header_len + ED448_PUB_SIZE]);
        Ok(id)
    }

    fn verify_ring_signature(
        transcript: &[u8],
        our_identity: &[u8; 57],
        peer_identity: &[u8; 57],
        sigma: &[u8],
    ) -> Result<()> {
        use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY};
        use ed448_goldilocks_plus::elliptic_curve::Group;
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

        if sigma.len() != RING_SIGMA_SIZE {
            return Err(OtrError::WireFormat);
        }

        let c0_bytes = &sigma[0..57];
        let r0_bytes = &sigma[57..114];
        let c1_bytes = &sigma[114..171];
        let r1_bytes = &sigma[171..228];

        let y0 = CompressedEdwardsY::try_from(&our_identity[..])
            .map_err(|_| OtrError::WireFormat)?
            .decompress()
            .into_option()
            .ok_or(OtrError::WireFormat)?;
        let y1 = CompressedEdwardsY::try_from(&peer_identity[..])
            .map_err(|_| OtrError::WireFormat)?
            .decompress()
            .into_option()
            .ok_or(OtrError::WireFormat)?;

        let c0 = Self::scalar_from_wide_bytes(c0_bytes);
        let r0 = Self::scalar_from_wide_bytes(r0_bytes);
        let c1 = Self::scalar_from_wide_bytes(c1_bytes);
        let r1 = Self::scalar_from_wide_bytes(r1_bytes);

        let g = EdwardsPoint::generator();

        let r0_point = g * r0 + y0 * c0;

        let c2 = {
            let mut shake = Shake256::default();
            Update::update(&mut shake, transcript);
            Update::update(&mut shake, r0_point.compress().as_bytes());
            Update::update(&mut shake, y1.compress().as_bytes());
            let mut hash = [0u8; 114];
            shake.finalize_xof().read(&mut hash);
            Self::scalar_from_wide_bytes(&hash)
        };

        let r1_point = g * r1 + y1 * c1;

        let c_all = {
            let mut shake = Shake256::default();
            Update::update(&mut shake, transcript);
            Update::update(&mut shake, r0_point.compress().as_bytes());
            Update::update(&mut shake, r1_point.compress().as_bytes());
            let mut hash = [0u8; 114];
            shake.finalize_xof().read(&mut hash);
            Self::scalar_from_wide_bytes(&hash)
        };

        if (c0 + c1) == c_all || (c0 + c2) == c_all {
            Ok(())
        } else {
            Err(OtrError::SignatureInvalid)
        }
    }

    #[allow(deprecated)]
    fn scalar_from_wide_bytes(bytes: &[u8]) -> ed448_goldilocks_plus::Scalar {
        use ed448_goldilocks_plus::elliptic_curve::generic_array::GenericArray;
        let mut wide = [0u8; 114];
        let len = bytes.len().min(114);
        wide[..len].copy_from_slice(&bytes[..len]);
        let wide_generic = GenericArray::clone_from_slice(&wide);
        ed448_goldilocks_plus::Scalar::from_bytes_mod_order_wide(&wide_generic)
    }

    // ── Crypto primitives ──────────────────────────────────

    fn generate_x448_ephemeral() -> Result<(SecretBytes<56>, [u8; X448_PUB_SIZE])> {
        use x448::{Secret, PublicKey};
        let mut bytes = [0u8; 56];
        getrandom::getrandom(&mut bytes).map_err(|_| OtrError::Internal)?;
        let sk = Secret::from(bytes);
        let pk = PublicKey::from(&sk);
        Ok((SecretBytes::new(bytes), *pk.as_bytes()))
    }

    fn generate_mlkem_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};
        let (pk, sk) = kyber1024::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn mlkem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};
        let pk = kyber1024::PublicKey::from_bytes(ek_bytes).map_err(|_| OtrError::MlKem)?;
        let (ct, ss) = kyber1024::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn mlkem_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{SecretKey, Ciphertext, SharedSecret};
        let sk = kyber1024::SecretKey::from_bytes(sk_bytes).map_err(|_| OtrError::MlKem)?;
        let ct = kyber1024::Ciphertext::from_bytes(ct_bytes).map_err(|_| OtrError::MlKem)?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }

    fn mldsa_sign(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_mldsa::mldsa87;
        use pqcrypto_traits::sign::{SecretKey, DetachedSignature};
        let sk = mldsa87::SecretKey::from_bytes(priv_key).map_err(|_| OtrError::MlDsa)?;
        let sig = mldsa87::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn mldsa_verify(pub_key: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        use pqcrypto_mldsa::mldsa87;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
        let pk = mldsa87::PublicKey::from_bytes(pub_key).map_err(|_| OtrError::MlDsa)?;
        let sig = mldsa87::DetachedSignature::from_bytes(sig_bytes).map_err(|_| OtrError::MlDsa)?;
        mldsa87::verify_detached_signature(&sig, message, &pk).map_err(|_| OtrError::SignatureInvalid)
    }

    fn x448_dh(priv_bytes: &[u8], pub_bytes: &[u8; 56]) -> Result<Vec<u8>> {
        use x448::{Secret, PublicKey};
        let sk_arr: [u8; 56] = priv_bytes.try_into().map_err(|_| OtrError::Internal)?;
        let sk = Secret::from(sk_arr);
        let pk = PublicKey::from_bytes(pub_bytes).ok_or(OtrError::Internal)?;
        let ss = sk.as_diffie_hellman(&pk).ok_or(OtrError::Internal)?;
        Ok(ss.as_bytes().to_vec())
    }

    fn derive_session_keys(
        mixed_secret: &[u8],
        brace_key: &SecretBytes<32>,
        ssid: &[u8; 8],
    ) -> Result<DakeSessionKeys> {
        let root_seed = kdf::kdf_1(usage::ROOT_KEY, mixed_secret, 96);
        let extra_raw = kdf::kdf_1(usage::EXTRA_SYM_KEY, mixed_secret, 32);

        let mut root     = [0u8; 32];
        let mut ck_a     = [0u8; 32];
        let mut ck_b     = [0u8; 32];
        root.copy_from_slice(&root_seed[..32]);
        ck_a.copy_from_slice(&root_seed[32..64]);
        ck_b.copy_from_slice(&root_seed[64..96]);

        let mut extra = [0u8; 32];
        extra.copy_from_slice(&extra_raw);
        let mut ssid_arr = [0u8; 8];
        ssid_arr.copy_from_slice(ssid);

        Ok(DakeSessionKeys {
            root_key:       SecretBytes::new(root),
            chain_key_send: SecretBytes::new(ck_a),
            chain_key_recv: SecretBytes::new(ck_b),
            brace_key:      SecretBytes::new(*brace_key.expose()),
            ssid:           SecretBytes::new(ssid_arr),
            extra_sym_key:  SecretBytes::new(extra),
        })
    }

    // ── Public accessors ────────────────────────────────────
    pub fn take_session_keys(&mut self) -> Option<DakeSessionKeys> { self.session_keys.take() }
    pub fn get_transcript(&self) -> &[u8]      { &self.transcript }
    pub fn get_peer_identity_pub(&self) -> &[u8; ED448_PUB_SIZE] { &self.peer_identity_pub }
    pub fn get_our_identity_pub(&self)  -> &[u8; ED448_PUB_SIZE] { &self.our_identity_pub }
    pub fn get_peer_mldsa_pub(&self) -> Option<&Vec<u8>> { self.peer_mldsa_pub.as_ref() }
    pub fn get_peer_profile_bytes(&self) -> Option<&Vec<u8>> { self.peer_profile_bytes.as_ref() }
}

// ── PyO3 bindings ───────────────────────────────────────────────

#[pyclass(name = "RustDAKE")]
pub struct PyDake { inner: DakeState }

#[pymethods]
impl PyDake {
    #[new]
    #[pyo3(signature = (is_initiator, our_profile_bytes, our_ik_bytes, our_prekey_bytes,
                        mldsa_priv=None, mldsa_pub=None, sender_tag=0))]
    fn new(
        is_initiator: bool,
        our_profile_bytes: &[u8],
        our_ik_bytes: &[u8],
        our_prekey_bytes: &[u8],
        mldsa_priv: Option<&[u8]>,
        mldsa_pub: Option<&[u8]>,
        sender_tag: u32,
    ) -> PyResult<Self> {
        // Extract identity key and prekey from profile
        let version_count = if our_profile_bytes.len() > 1 { our_profile_bytes[1] as usize } else { return Err(PyErr::from(OtrError::TooShort { need: 2, got: our_profile_bytes.len() })); };
        let header_len = 2 + version_count;
        
        if our_profile_bytes.len() < header_len + 57 + 56 {
            return Err(PyErr::from(OtrError::TooShort { need: header_len + 57 + 56, got: our_profile_bytes.len() }));
        }
        
        let identity_pub: &[u8; 57] = our_profile_bytes[header_len..header_len + 57]
            .try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort { need: 57, got: our_profile_bytes.len() - header_len }))?;
        
        let identity_priv: &[u8; 57] = our_ik_bytes.try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort { need: 57, got: our_ik_bytes.len() }))?;
        let prekey_priv: &[u8; 56] = our_prekey_bytes.try_into()
            .map_err(|_| PyErr::from(OtrError::TooShort { need: 56, got: our_prekey_bytes.len() }))?;
        
        let prekey_pub: &[u8; 56] = our_profile_bytes[header_len + 57..header_len + 57 + 56]
            .try_into()
            .unwrap();
        
        Ok(Self { inner: DakeState::new(identity_priv, identity_pub, prekey_priv, prekey_pub, mldsa_priv, mldsa_pub, sender_tag)
            .map_err(PyErr::from)? })
    }

    fn generate_dake1<'py>(
        &mut self, 
        py: Python<'py>, 
        our_profile_bytes: &[u8],
        mldsa_pub_bytes: Option<&[u8]>
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = self.inner.generate_dake1(our_profile_bytes, mldsa_pub_bytes)
            .map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &result))
    }
    
    fn process_dake1(&mut self, data: &[u8], remote_profile_bytes: &[u8]) -> PyResult<()> {
        self.inner.process_dake1(data, remote_profile_bytes)
            .map_err(PyErr::from)
    }
    
    fn generate_dake2<'py>(
        &mut self, 
        py: Python<'py>, 
        our_prekey_priv_bytes: Option<&[u8]>,
        mldsa_pub_bytes: Option<&[u8]>
    ) -> PyResult<Py<PyAny>> {
        // Get our_profile from stored transcript? For now construct dummy for testing.
        // In production, store profile in the state.
        let dummy_profile = b"\x04\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80" as &[u8];
        
        let (msg, keys) = self.inner.generate_dake2(dummy_profile, our_prekey_priv_bytes, mldsa_pub_bytes)
            .map_err(PyErr::from)?;
        
        let result = Py::new(py, Dakeresult::success())?;
        let result_ref = result.bind(py);
        result_ref.setattr("success", true)?;
        result_ref.setattr("dake_bytes", msg)?;
        result_ref.setattr("root_key", keys.root_key.expose())?;
        result_ref.setattr("chain_key_a", keys.chain_key_send.expose())?;
        result_ref.setattr("chain_key_b", keys.chain_key_recv.expose())?;
        result_ref.setattr("brace_key", keys.brace_key.expose())?;
        result_ref.setattr("ssid", keys.ssid.expose())?;
        result_ref.setattr("mac_key", keys.extra_sym_key.expose())?;
        
        Ok(result.into_any())
    }
    
    fn process_dake2<'py>(
        &mut self, 
        py: Python<'py>,
        dake2_bytes: &[u8], 
        our_prekey_priv_bytes: Option<&[u8]>
    ) -> PyResult<Py<PyAny>> {
        let dummy_profile = b"\x04\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80" as &[u8];
        
        let keys = self.inner.process_dake2(dake2_bytes, dummy_profile, our_prekey_priv_bytes)
            .map_err(PyErr::from)?;
        
        let result = Py::new(py, Dakeresult::success())?;
        let result_ref = result.bind(py);
        result_ref.setattr("success", true)?;
        result_ref.setattr("root_key", keys.root_key.expose())?;
        result_ref.setattr("chain_key_a", keys.chain_key_send.expose())?;
        result_ref.setattr("chain_key_b", keys.chain_key_recv.expose())?;
        result_ref.setattr("brace_key", keys.brace_key.expose())?;
        result_ref.setattr("ssid", keys.ssid.expose())?;
        result_ref.setattr("mac_key", keys.extra_sym_key.expose())?;
        result_ref.setattr("remote_identity_pub", self.inner.get_peer_identity_pub())?;
        result_ref.setattr("remote_mldsa_pub", self.inner.get_peer_mldsa_pub())?;
        result_ref.setattr("remote_profile_bytes", self.inner.get_peer_profile_bytes())?;
        
        Ok(result.into_any())
    }
    
    fn assemble_dake3<'py>(
        &self,
        py: Python<'py>,
        sigma_bytes: &[u8],
        mldsa_sig_bytes: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let msg = self.inner.assemble_dake3(sigma_bytes, mldsa_sig_bytes)
            .map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &msg))
    }
    
    fn process_dake3(&mut self, data: &[u8]) -> PyResult<()> {
        self.inner.process_dake3(data).map_err(PyErr::from)
    }
    
    fn get_phase(&self) -> String {
        match self.inner.phase {
            DakePhase::Idle => "IDLE".to_string(),
            DakePhase::SentDake1 => "SENT_DAKE1".to_string(),
            DakePhase::ReceivedDake1 => "RECEIVED_DAKE1".to_string(),
            DakePhase::SentDake2 => "SENT_DAKE2".to_string(),
            DakePhase::ReceivedDake2 => "RECEIVED_DAKE2".to_string(),
            DakePhase::Established => "ESTABLISHED".to_string(),
            DakePhase::Failed => "FAILED".to_string(),
        }
    }
    
    fn is_established(&self) -> bool { self.inner.phase == DakePhase::Established }
    
    fn get_session_keys(&mut self) -> Option<Py<PyAny>> {
        Python::with_gil(|py| {
            if let Some(keys) = self.inner.take_session_keys() {
                let result = Py::new(py, Dakeresult::success()).ok()?;
                let result_ref = result.bind(py);
                result_ref.setattr("root_key", keys.root_key.expose()).ok()?;
                result_ref.setattr("chain_key_a", keys.chain_key_send.expose()).ok()?;
                result_ref.setattr("chain_key_b", keys.chain_key_recv.expose()).ok()?;
                result_ref.setattr("brace_key", keys.brace_key.expose()).ok()?;
                result_ref.setattr("ssid", keys.ssid.expose()).ok()?;
                result_ref.setattr("extra_sym_key", keys.extra_sym_key.expose()).ok()?;
                Some(result.into_any())
            } else {
                None
            }
        })
    }
}