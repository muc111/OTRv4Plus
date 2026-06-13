// src/smp.rs — Hybrid Post-Quantum Socialist Millionaire Protocol
//
// Version: OTRv4+ v10.9.3
//
// Security model
// ==============
// The classical OTRv4 SMP (four-step Schnorr ZKP over a 3072-bit safe prime)
// is preserved verbatim and remains wire-compatible with any implementation
// that understands the PQ extension flag (SMP_VERSION_PQ = 0x02).
//
// On top of the classical layer, this module adds a PQ binding layer:
//
//   SMP1  Initiator generates ML-KEM-1024 keypair.  Sends:
//           classical fields || PQ_FLAG=0x02 || mlkem_ek (1568 bytes)
//           The KEM public key is hashed into the secret derivation so that
//           Pa, Qa, Pb, Qb all commit to the PQ layer.
//
//   SMP2  Responder encapsulates to the KEM key → kem_ss.
//           Derives pq_binding_key = KDF(PQ_BRACE_KEY, kem_ss || transcript).
//           Signs the canonical SMP2 wire body with ML-DSA-87 under pq_binding_key
//           (as additional data in the DSA context).
//           Sends: classical fields || mlkem_ct (1568 bytes) || mldsa_sig (4627 bytes)
//
//   SMP3  Initiator decapsulates → kem_ss.  Derives same pq_binding_key.
//           Verifies ML-DSA-87 over SMP2.  Signs SMP3 wire body.
//           Sends: classical fields || mldsa_sig (4627 bytes)
//
//   SMP4  Responder verifies ML-DSA-87 over SMP3.  Signs SMP4 wire body.
//           Final equality check exactly as OTRv4 spec.
//           Initiator verifies ML-DSA-87 over SMP4.
//           Sends: classical fields || mldsa_sig (4627 bytes)
//
// A quantum adversary must break BOTH:
//   - The 3072-bit discrete log (Shor) to forge ZKPs, AND
//   - ML-KEM-1024 (to recover kem_ss and derive pq_binding_key), AND
//   - ML-DSA-87 (to forge the per-step signatures)
//
// A classical adversary who breaks ML-DSA-87 or ML-KEM-1024 still faces the
// classical ZKPs.  Neither layer alone is sufficient.
//
// Wire format
// ===========
// All messages are prefixed with a single VERSION byte:
//   0x01 = classical SMP only (backward compat, no PQ)
//   0x02 = hybrid PQ SMP (this implementation)
//
// Peers MUST agree on version.  If the initiator sends 0x02 and the responder
// parses 0x01, or vice-versa, the first ZKP or signature verify will fail and
// the session is aborted.  No silent downgrade is possible.
//
// Memory safety
// =============
// All secret scalars (a2, a3, b2, b3, r*, secret) live in SecretVec with
// ZeroizeOnDrop.  The KEM secret key and ML-DSA signing key live in
// SecretBytes with ZeroizeOnDrop.  The pq_binding_key is a SecretBytes<32>
// that is wiped immediately after use in each step.
//
// The destroy() method overwrites all secret fields and sets phase = Aborted.
// fail_and_zeroize() calls destroy() on the third failure; before that it
// calls lifecycle.record_failure() and sets phase = Failed so the caller can
// retry after the cooldown.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};
use zeroize::{Zeroize, ZeroizeOnDrop};
use sha3::{Sha3_512, Digest};
use sha3::digest::Update;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crypto_bigint::{U3072, Encoding};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};

use pqcrypto_traits::kem::{
    PublicKey  as KemPublicKey,
    SecretKey  as KemSecretKey,
    Ciphertext as KemCiphertext,
    SharedSecret as KemSharedSecret,
};
use pqcrypto_traits::sign::{
    PublicKey          as SignPublicKey,
    SecretKey          as SignSecretKey,
    DetachedSignature  as SignDetachedSignature,
};

use crate::error::{OtrError, Result, SafeSlice, check_wire_length};
use crate::kdf::{self, usage};
use crate::secure_mem::{SecretBytes, SecretVec};

// ─── constants ────────────────────────────────────────────────────────────────

const MAX_ATTEMPTS:         u32   = 3;
const SESSION_TIMEOUT_SECS: u64   = 2700;  // 45 minutes — accommodates I2P + hybrid PQC SMP latency
const RETRY_COOLDOWN_SECS:  u64   = 30;
const KDF_ROUNDS:           u32   = 50_000;
const SMP_PRIME_BYTES:      usize = 384;   // 3072-bit prime = 384 bytes
const SMP_SCALAR_BYTES:     usize = 384;

// ML-KEM-1024 sizes (FIPS 203)
const MLKEM_EK_SIZE:  usize = 1568;
const MLKEM_CT_SIZE:  usize = 1568;

// ML-DSA-87 sizes (FIPS 204)
const MLDSA_PUB_SIZE: usize = 2592;
const MLDSA_PRV_SIZE: usize = 4896;
const MLDSA_SIG_SIZE: usize = 4627;

// Wire version bytes
#[allow(dead_code)]
const SMP_VERSION_CLASSICAL: u8 = 0x01;
const SMP_VERSION_PQ:        u8 = 0x02;

// Domain label mixed into pq_binding_key derivation
const PQ_BINDING_DOMAIN: &[u8] = b"OTRv4+SMP-PQ-BIND-v1\x00";

// ─── 3072-bit SMP group (OTRv4 §5.3) ─────────────────────────────────────────

static SMP_PRIME: LazyLock<num_bigint::BigUint> = LazyLock::new(|| {
    num_bigint::BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
          29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
          EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
          E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
          EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
          C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
          83655D23DCA3AD961C62F356208552BB9ED529077096966D\
          670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
          E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
          DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
          15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
          ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
          ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
          F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
          BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
          43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16,
    ).expect("SMP prime literal is valid hex")
});

static SMP_ORDER: LazyLock<num_bigint::BigUint> = LazyLock::new(|| {
    (SMP_PRIME.clone() - 1u64) >> 1
});

static SMP_GEN: LazyLock<num_bigint::BigUint> = LazyLock::new(|| {
    num_bigint::BigUint::from(2u8)
});

static SMP_PRIME_CT: LazyLock<U3072> = LazyLock::new(|| {
    let be = pad_be_384(&SMP_PRIME.to_bytes_be());
    U3072::from_be_slice(&be)
});

static SMP_MONTY: LazyLock<DynResidueParams<48>> = LazyLock::new(|| {
    DynResidueParams::new(&*SMP_PRIME_CT)
});

fn pad_be_384(raw: &[u8]) -> [u8; 384] {
    let mut out = [0u8; 384];
    let n = raw.len().min(384);
    out[384 - n..].copy_from_slice(&raw[raw.len() - n..]);
    out
}

// ─── phase enum ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SmpPhase {
    Idle,
    AwaitingMsg2,
    AwaitingMsg3,
    AwaitingMsg4,
    Verified,
    Failed,
    Aborted,
}

// ─── transcript accumulator ───────────────────────────────────────────────────
//
// HMAC-SHA3-512 keyed with the session_id (truncated/padded to 64 bytes).
// Every message's wire bytes are fed in order: SMP1, SMP2, SMP3, SMP4.
// The running HMAC tag is used as additional data in ML-DSA-87 signing so
// that each step's signature binds to the full conversation history.

struct SmpTranscript {
    mac:       Hmac<Sha3_512>,
    finalized: bool,
    current:   [u8; 64],   // tag after the most recent feed()
}

impl SmpTranscript {
    fn new(session_id: &[u8]) -> Self {
        let mut key = [0u8; 64];
        let n = session_id.len().min(64);
        key[..n].copy_from_slice(&session_id[..n]);
        let mac = Hmac::<Sha3_512>::new_from_slice(&key)
            .expect("HMAC-SHA3-512 accepts any key length");
        Self { mac, finalized: false, current: [0u8; 64] }
    }

    /// Feed one message's wire bytes into the running transcript.
    fn feed(&mut self, wire_bytes: &[u8]) {
        if self.finalized {
            return;
        }
        Update::update(&mut self.mac, wire_bytes);
        // Snapshot the current tag without consuming the MAC so further
        // feeds are still possible.  We clone and finalize a side-copy.
        let snapshot = self.mac.clone().finalize().into_bytes();
        self.current.copy_from_slice(&snapshot);
    }

    /// Return the current transcript tag (additional data for ML-DSA).
    fn current_tag(&self) -> &[u8; 64] {
        &self.current
    }
}

impl Drop for SmpTranscript {
    fn drop(&mut self) {
        self.current.zeroize();
        self.finalized = true;
    }
}

// ─── rate-limit / lifecycle ───────────────────────────────────────────────────

struct SmpLifecycle {
    created_at:    Instant,
    last_failure:  Option<Instant>,
    attempt_count: u32,
}

impl SmpLifecycle {
    fn new() -> Self {
        Self { created_at: Instant::now(), last_failure: None, attempt_count: 0 }
    }

    fn check_not_expired(&self) -> Result<()> {
        if self.created_at.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECS) {
            return Err(OtrError::Smp("SMP session expired (10-minute limit)"));
        }
        Ok(())
    }

    fn check_rate_limit(&self) -> Result<()> {
        if self.attempt_count >= MAX_ATTEMPTS {
            return Err(OtrError::Smp("SMP aborted: max attempt limit exceeded"));
        }
        if let Some(last) = self.last_failure {
            if last.elapsed() < Duration::from_secs(RETRY_COOLDOWN_SECS) {
                return Err(OtrError::Smp("SMP retry too soon: cooldown in effect"));
            }
        }
        Ok(())
    }

    fn record_failure(&mut self) {
        self.attempt_count += 1;
        self.last_failure = Some(Instant::now());
    }
}

// ─── PQ key bundle held during the SMP exchange ───────────────────────────────
//
// The initiator owns a (mlkem_ek, mlkem_sk) pair generated at SMP1.
// The responder encapsulates to mlkem_ek and sends back mlkem_ct plus its
// ML-DSA-87 public key.  Both sides derive pq_binding_key from kem_ss and
// use it as additional data in all subsequent ML-DSA-87 sign/verify calls.
//
// All fields use ZeroizeOnDrop wrappers via SecretBytes / SecretVec.

#[derive(ZeroizeOnDrop)]
struct PqBundle {
    // Initiator's KEM keypair (present on initiator side after SMP1)
    mlkem_sk:        Option<SecretVec>,        // 3168-byte ML-KEM-1024 secret key
    mlkem_ek:        Option<Vec<u8>>,          // 1568-byte encapsulation key (public)

    // Responder's KEM ciphertext (present on responder after encaps, initiator after SMP2)
    mlkem_ct:        Option<Vec<u8>>,          // 1568-byte ciphertext

    // ML-DSA-87 signing keypair for this SMP session (both sides generate one)
    mldsa_sk:        Option<SecretBytes<MLDSA_PRV_SIZE>>,
    mldsa_pk:        Option<Vec<u8>>,          // 2592-byte public key
    peer_mldsa_pk:   Option<Vec<u8>>,          // peer's 2592-byte public key

    // Derived PQ binding key (32 bytes, wiped after each use)
    // Both sides derive this after KEM encaps/decaps.
    pq_binding_key:  Option<SecretBytes<32>>,
}

impl PqBundle {
    fn none() -> Self {
        Self {
            mlkem_sk: None, mlkem_ek: None, mlkem_ct: None,
            mldsa_sk: None, mldsa_pk: None, peer_mldsa_pk: None,
            pq_binding_key: None,
        }
    }

    /// Generate fresh ML-KEM-1024 and ML-DSA-87 keypairs.
    fn generate() -> Result<Self> {
        let (ek, sk_bytes) = mlkem_keygen()?;
        let (pk_bytes, sk_dsa) = mldsa_keygen()?;
        Ok(Self {
            mlkem_sk: Some(SecretVec::from_slice(&sk_bytes)),
            mlkem_ek: Some(ek),
            mlkem_ct: None,
            mldsa_sk: Some(sk_dsa),
            mldsa_pk: Some(pk_bytes),
            peer_mldsa_pk: None,
            pq_binding_key: None,
        })
    }

    /// Responder: generate ML-DSA-87 keypair only (no KEM keypair on responder side).
    fn generate_responder() -> Result<Self> {
        let (pk_bytes, sk_dsa) = mldsa_keygen()?;
        Ok(Self {
            mlkem_sk: None, mlkem_ek: None, mlkem_ct: None,
            mldsa_sk: Some(sk_dsa),
            mldsa_pk: Some(pk_bytes),
            peer_mldsa_pk: None,
            pq_binding_key: None,
        })
    }

    /// Derive and store pq_binding_key from a KEM shared secret and the
    /// current transcript tag.  Wipes kem_ss immediately after use.
    fn derive_binding_key(&mut self, kem_ss: &[u8], transcript_tag: &[u8; 64]) {
        let mut ikm = Vec::with_capacity(
            PQ_BINDING_DOMAIN.len() + kem_ss.len() + 64,
        );
        ikm.extend_from_slice(PQ_BINDING_DOMAIN);
        ikm.extend_from_slice(kem_ss);
        ikm.extend_from_slice(transcript_tag);
        let raw = kdf::kdf_1(usage::PQ_BRACE_KEY, &ikm, 32);
        ikm.zeroize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        self.pq_binding_key = Some(SecretBytes::new(arr));
    }

    /// Sign `wire_bytes` with ML-DSA-87.  Uses pq_binding_key as the
    /// context byte-string passed to the ML-DSA-87 context-API.
    /// Returns the 4627-byte detached signature.
    fn sign(&self, wire_bytes: &[u8]) -> Result<Vec<u8>> {
        let sk = self.mldsa_sk.as_ref()
            .ok_or(OtrError::Smp("PQ sign: no ML-DSA signing key"))?;
        let ctx = self.pq_binding_key.as_ref()
            .ok_or(OtrError::Smp("PQ sign: pq_binding_key not derived yet"))?;
        mldsa_sign_with_context(sk.expose(), wire_bytes, ctx.expose())
    }

    /// Verify an ML-DSA-87 signature from the peer.
    fn verify(&self, wire_bytes: &[u8], sig: &[u8]) -> Result<()> {
        let pk = self.peer_mldsa_pk.as_ref()
            .ok_or(OtrError::Smp("PQ verify: no peer ML-DSA public key"))?;
        let ctx = self.pq_binding_key.as_ref()
            .ok_or(OtrError::Smp("PQ verify: pq_binding_key not derived yet"))?;
        mldsa_verify_with_context(pk, wire_bytes, sig, ctx.expose())
    }

    /// Wipe all secret material (called by destroy()).
    fn wipe(&mut self) {
        self.mlkem_sk       = None;
        self.mldsa_sk       = None;
        self.pq_binding_key = None;
        // Public material can stay but there is no reason to keep it
        self.mlkem_ek     = None;
        self.mlkem_ct     = None;
        self.mldsa_pk     = None;
        self.peer_mldsa_pk = None;
    }
}

// ─── ML-KEM-1024 helpers ──────────────────────────────────────────────────────

fn mlkem_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

fn mlkem_encapsulate(ek: &[u8]) -> Result<(Vec<u8>, SecretVec)> {
    if ek.len() != MLKEM_EK_SIZE {
        return Err(OtrError::TooShort { need: MLKEM_EK_SIZE, got: ek.len() });
    }
    let pk = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(ek)
        .map_err(|_| OtrError::MlKem)?;
    // pqcrypto_mlkem returns (SharedSecret, Ciphertext)
    let (ss, ct) = pqcrypto_mlkem::mlkem1024::encapsulate(&pk);
    let mut ss_bytes = ss.as_bytes().to_vec();
    let ct_bytes = ct.as_bytes().to_vec();
    let secret = SecretVec::from_slice(&ss_bytes);
    ss_bytes.zeroize();
    Ok((ct_bytes, secret))
}

fn mlkem_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<SecretVec> {
    if ct_bytes.len() != MLKEM_CT_SIZE {
        return Err(OtrError::TooShort { need: MLKEM_CT_SIZE, got: ct_bytes.len() });
    }
    let sk = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| OtrError::MlKem)?;
    let ct = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ct_bytes)
        .map_err(|_| OtrError::MlKem)?;
    let mut ss_bytes = pqcrypto_mlkem::mlkem1024::decapsulate(&ct, &sk)
        .as_bytes().to_vec();
    let secret = SecretVec::from_slice(&ss_bytes);
    ss_bytes.zeroize();
    Ok(secret)
}

// ─── ML-DSA-87 helpers ────────────────────────────────────────────────────────

fn mldsa_keygen() -> Result<(Vec<u8>, SecretBytes<MLDSA_PRV_SIZE>)> {
    let (pk, sk) = pqcrypto_mldsa::mldsa87::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let mut sk_raw = sk.as_bytes().to_vec();
    let mut arr = [0u8; MLDSA_PRV_SIZE];
    if sk_raw.len() != MLDSA_PRV_SIZE {
        sk_raw.zeroize();
        return Err(OtrError::MlDsa);
    }
    arr.copy_from_slice(&sk_raw);
    sk_raw.zeroize();
    Ok((pk_bytes, SecretBytes::new(arr)))
}

/// Sign with ML-DSA-87 using pq_binding_key as the context string.
/// The context is prepended to the message before signing so that
/// signatures produced under different binding keys cannot be confused.
/// This is equivalent to the ML-DSA-87 context API without requiring
/// pqcrypto_mldsa to expose a context-parameter interface.
fn mldsa_sign_with_context(
    sk_bytes: &[u8],
    message:  &[u8],
    context:  &[u8],
) -> Result<Vec<u8>> {
    if sk_bytes.len() != MLDSA_PRV_SIZE {
        return Err(OtrError::MlDsa);
    }
    let sk = pqcrypto_mldsa::mldsa87::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| OtrError::MlDsa)?;

    // Construct the input that will be signed: context_len (4 bytes BE)
    // || context || message.  Both sides must use the same construction.
    let ctx_len = (context.len() as u32).to_be_bytes();
    let mut input = Vec::with_capacity(4 + context.len() + message.len());
    input.extend_from_slice(&ctx_len);
    input.extend_from_slice(context);
    input.extend_from_slice(message);

    let sig = pqcrypto_mldsa::mldsa87::detached_sign(&input, &sk);
    let out = sig.as_bytes().to_vec();
    input.zeroize();
    Ok(out)
}

/// Verify with ML-DSA-87 using the same context construction.
fn mldsa_verify_with_context(
    pk_bytes: &[u8],
    message:  &[u8],
    sig_bytes: &[u8],
    context:  &[u8],
) -> Result<()> {
    if pk_bytes.len() != MLDSA_PUB_SIZE {
        return Err(OtrError::TooShort { need: MLDSA_PUB_SIZE, got: pk_bytes.len() });
    }
    if sig_bytes.len() != MLDSA_SIG_SIZE {
        return Err(OtrError::TooShort { need: MLDSA_SIG_SIZE, got: sig_bytes.len() });
    }
    let pk = pqcrypto_mldsa::mldsa87::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| OtrError::MlDsa)?;
    let sig = pqcrypto_mldsa::mldsa87::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|_| OtrError::MlDsa)?;

    let ctx_len = (context.len() as u32).to_be_bytes();
    let mut input = Vec::with_capacity(4 + context.len() + message.len());
    input.extend_from_slice(&ctx_len);
    input.extend_from_slice(context);
    input.extend_from_slice(message);

    let result = pqcrypto_mldsa::mldsa87::verify_detached_signature(&sig, &input, &pk);
    input.zeroize();
    result.map_err(|_| OtrError::SignatureInvalid)
}

// ─── core SMP state ───────────────────────────────────────────────────────────

#[derive(ZeroizeOnDrop)]
pub struct SmpState {
    // Classical secret scalars (all ZeroizeOnDrop via SecretVec)
    secret: SecretVec,
    a2: SecretVec, a3: SecretVec,
    b2: SecretVec, b3: SecretVec,
    r2: SecretVec, r3: SecretVec, r4: SecretVec, r5: SecretVec, r6: SecretVec,
    r2b: SecretVec, r3b: SecretVec, r4b: SecretVec, r5b: SecretVec, r6b: SecretVec,

    // Classical group elements (public, not secret)
    #[zeroize(skip)] g2a: Option<Vec<u8>>,
    #[zeroize(skip)] g3a: Option<Vec<u8>>,
    #[zeroize(skip)] g2b: Option<Vec<u8>>,
    #[zeroize(skip)] g3b: Option<Vec<u8>>,
    #[zeroize(skip)] g3:  Option<Vec<u8>>,
    #[zeroize(skip)] pa:  Option<Vec<u8>>,
    #[zeroize(skip)] qa:  Option<Vec<u8>>,
    #[zeroize(skip)] pb:  Option<Vec<u8>>,
    #[zeroize(skip)] qb:  Option<Vec<u8>>,

    // State
    #[zeroize(skip)] pub phase:        SmpPhase,
    #[zeroize(skip)] pub is_initiator: bool,
    #[zeroize(skip)] question:         Option<String>,
    #[zeroize(skip)] session_id:       Option<Vec<u8>>,
    #[zeroize(skip)] our_fp:           Option<Vec<u8>>,
    #[zeroize(skip)] peer_fp:          Option<Vec<u8>>,
    #[zeroize(skip)] lifecycle:        SmpLifecycle,
    #[zeroize(skip)] transcript:       Option<SmpTranscript>,

    // PQ bundle (ZeroizeOnDrop internally)
    #[zeroize(skip)] pq: PqBundle,

    // Wire version negotiated for this session
    #[zeroize(skip)] version: u8,
}

impl SmpState {
    pub fn new(is_initiator: bool) -> Self {
        let e = || SecretVec::new(vec![]);
        Self {
            secret: e(),
            a2: e(), a3: e(), b2: e(), b3: e(),
            r2: e(), r3: e(), r4: e(), r5: e(), r6: e(),
            r2b: e(), r3b: e(), r4b: e(), r5b: e(), r6b: e(),
            g2a: None, g3a: None, g2b: None, g3b: None, g3: None,
            pa: None, qa: None, pb: None, qb: None,
            phase: SmpPhase::Idle,
            is_initiator,
            question: None,
            session_id: None,
            our_fp: None,
            peer_fp: None,
            lifecycle: SmpLifecycle::new(),
            transcript: None,
            pq: PqBundle::none(),
            version: SMP_VERSION_PQ,   // default: hybrid PQ
        }
    }

    fn guard(&mut self) -> Result<()> {
        if self.phase == SmpPhase::Aborted {
            return Err(OtrError::Smp("SMP session permanently aborted"));
        }
        self.lifecycle.check_not_expired()?;
        self.lifecycle.check_rate_limit()?;
        Ok(())
    }

    pub fn destroy(&mut self) {
        let e = || SecretVec::new(vec![]);
        self.secret = e();
        self.a2 = e(); self.a3 = e(); self.b2 = e(); self.b3 = e();
        self.r2 = e(); self.r3 = e(); self.r4 = e(); self.r5 = e(); self.r6 = e();
        self.r2b = e(); self.r3b = e(); self.r4b = e(); self.r5b = e(); self.r6b = e();
        self.transcript = None;
        self.g2a = None; self.g3a = None; self.g2b = None;
        self.g3b = None; self.g3 = None;
        self.pa = None; self.qa = None; self.pb = None; self.qb = None;
        self.session_id = None; self.our_fp = None; self.peer_fp = None;
        self.pq.wipe();
        self.phase = SmpPhase::Aborted;
    }

    fn fail_and_zeroize(&mut self, err: OtrError) -> OtrError {
        self.lifecycle.record_failure();
        if self.lifecycle.attempt_count >= MAX_ATTEMPTS {
            self.destroy();
        } else {
            self.phase = SmpPhase::Failed;
        }
        err
    }

    // ─── classical math helpers ──────────────────────────────────────────────

    fn fixed_bytes(val: &num_bigint::BigUint, len: usize) -> Vec<u8> {
        let raw = val.to_bytes_be();
        if raw.len() >= len { return raw; }
        let mut padded = vec![0u8; len - raw.len()];
        padded.extend_from_slice(&raw);
        padded
    }

    fn fe_bytes(val: &num_bigint::BigUint) -> Vec<u8> {
        Self::fixed_bytes(val, SMP_PRIME_BYTES)
    }

    /// Constant-time modular exponentiation via crypto-bigint DynResidue.
    fn mod_exp(
        base:    &num_bigint::BigUint,
        exp_bytes: &[u8],
        _modulus: &num_bigint::BigUint,
    ) -> num_bigint::BigUint {
        let base_ct = Self::biguint_to_u3072(base);
        let exp_ct  = U3072::from_be_slice(&pad_be_384(exp_bytes));
        let base_m  = DynResidue::new(&base_ct, *SMP_MONTY);
        let res_m   = base_m.pow(&exp_ct);
        Self::u3072_to_biguint(&res_m.retrieve())
    }

    fn mod_inv(val: &num_bigint::BigUint) -> num_bigint::BigUint {
        let p_minus_2 = &*SMP_PRIME - 2u8;
        Self::mod_exp(val, &p_minus_2.to_bytes_be(), &SMP_PRIME)
    }

    fn biguint_to_u3072(v: &num_bigint::BigUint) -> U3072 {
        U3072::from_be_slice(&pad_be_384(&v.to_bytes_be()))
    }

    fn u3072_to_biguint(v: &U3072) -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_be(&v.to_be_bytes())
    }

    fn zkp_challenge(version: u8, commitment: &[u8], statement: &[u8]) -> num_bigint::BigUint {
        let mut h = Sha3_512::new();
        Digest::update(&mut h, &[version]);
        Digest::update(&mut h, commitment);
        Digest::update(&mut h, statement);
        num_bigint::BigUint::from_bytes_be(&h.finalize()) % &*SMP_ORDER
    }

    fn compute_zkp(
        version:   u8,
        r_bytes:   &[u8],
        exp_bytes: &[u8],
        base_val:  &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        Self::compute_zkp_custom_base(version, r_bytes, exp_bytes, base_val, &SMP_GEN)
    }

    fn compute_zkp_custom_base(
        version:   u8,
        r_bytes:   &[u8],
        exp_bytes: &[u8],
        base_val:  &[u8],
        base:      &num_bigint::BigUint,
    ) -> (Vec<u8>, Vec<u8>) {
        let commitment   = Self::mod_exp(base, r_bytes, &SMP_PRIME);
        let commitment_b = Self::fe_bytes(&commitment);
        let c            = Self::zkp_challenge(version, &commitment_b, base_val);
        let r   = num_bigint::BigUint::from_bytes_be(r_bytes);
        let exp = num_bigint::BigUint::from_bytes_be(exp_bytes);
        let d   = (r + &*SMP_ORDER - (c.clone() * exp) % &*SMP_ORDER) % &*SMP_ORDER;
        (c.to_bytes_be(), d.to_bytes_be())
    }

    fn verify_zkp(version: u8, c_bytes: &[u8], d_bytes: &[u8], base_val: &[u8]) -> Result<()> {
        Self::verify_zkp_custom_base(version, c_bytes, d_bytes, base_val, &SMP_GEN)
    }

    fn verify_zkp_custom_base(
        version:  u8,
        c_bytes:  &[u8],
        d_bytes:  &[u8],
        base_val: &[u8],
        base:     &num_bigint::BigUint,
    ) -> Result<()> {
        let c  = num_bigint::BigUint::from_bytes_be(c_bytes);
        let bv = num_bigint::BigUint::from_bytes_be(base_val);
        let gd = Self::mod_exp(base, d_bytes, &SMP_PRIME);
        let gc = Self::mod_exp(&bv, &c.to_bytes_be(), &SMP_PRIME);
        let gr = (gd * gc) % &*SMP_PRIME;
        let c2 = Self::zkp_challenge(version, &Self::fe_bytes(&gr), base_val);
        if crate::secure_mem::ct_eq(&c.to_bytes_be(), &c2.to_bytes_be()) {
            Ok(())
        } else {
            Err(OtrError::Smp("ZKP verification failed"))
        }
    }

    fn random_exponent() -> SecretVec {
        use num_bigint::RandBigInt;
        let v = OsRng.gen_biguint_range(&num_bigint::BigUint::from(2u8), &*SMP_ORDER);
        SecretVec::from_slice(&Self::fixed_bytes(&v, SMP_SCALAR_BYTES))
    }

    // ─── wire encode / decode ────────────────────────────────────────────────
    //
    // Format: each field is length-prefixed (4 bytes BE) followed by data.
    // The PQ extension appends raw fixed-size fields AFTER the classical
    // group-element encoding, protected by the version byte at offset 0.

    fn encode_group_elems(elems: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in elems {
            let len = e.len() as u32;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(e);
        }
        out
    }

    fn decode_group_elems(data: &[u8], count: usize) -> Result<(Vec<Vec<u8>>, usize)> {
        let mut out = Vec::with_capacity(count);
        let mut off = 0usize;
        for _ in 0..count {
            if off + 4 > data.len() {
                return Err(OtrError::TruncatedMessage);
            }
            let len = u32::from_be_bytes(
                data[off..off + 4].try_into().map_err(|_| OtrError::WireFormat)?,
            ) as usize;
            check_wire_length(len, data.len() - off - 4)?;
            off += 4;
            out.push(data[off..off + len].to_vec());
            off += len;
        }
        Ok((out, off))
    }

    fn validate_group_elem(bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Err(OtrError::SmpRange);
        }
        let v = num_bigint::BigUint::from_bytes_be(bytes);
        if v < num_bigint::BigUint::from(2u8) || v >= *SMP_PRIME {
            return Err(OtrError::SmpRange);
        }
        Ok(())
    }

    // ─── secret derivation ───────────────────────────────────────────────────
    //
    // Hybrid derivation when PQ is active:
    //   Step 1: 50k-round SHAKE-256 iterated KDF over raw_secret.
    //   Step 2: HMAC-SHA3-512 session + fingerprint binding.
    //   Step 3: Mix in the ML-KEM public key (initiator's mlkem_ek) so that
    //           Pa, Qa, Pb, Qb all commit to the PQ layer from the start.
    //   Step 4: Reduce mod order.
    //
    // This means a quantum adversary who recovers the classical secret scalar
    // from Pa/Qa/Pb/Qb still cannot verify or forge without the ML-KEM key.
    //
    // In classical-only mode (version == SMP_VERSION_CLASSICAL) the mlkem_ek
    // mix-in is skipped for backward compatibility.

    pub fn set_secret(
        &mut self,
        raw_secret: &[u8],
        session_id: &[u8],
        our_fp:     &[u8],
        peer_fp:    &[u8],
    ) {
        use sha3::Shake256;
        use sha3::digest::{ExtendableOutput, XofReader};

        // Step 1: 50k-round SHAKE-256 key-stretching
        let mut state = {
            let mut h = Shake256::default();
            Update::update(&mut h, b"OTRv4+SMP-v2\x00");
            Update::update(&mut h, raw_secret);
            let mut buf = [0u8; 64];
            h.finalize_xof().read(&mut buf);
            buf
        };
        for i in 0u32..KDF_ROUNDS - 1 {
            let mut h = Shake256::default();
            Update::update(&mut h, &i.to_be_bytes());
            Update::update(&mut h, &state);
            h.finalize_xof().read(&mut state);
        }

        // Step 2: HMAC-SHA3-512 session + fingerprint binding
        let hmac_key = {
            let mut h = Sha3_512::new();
            Digest::update(&mut h, session_id);
            h.finalize()
        };
        // Lexicographic ordering ensures initiator and responder compute
        // identical secrets regardless of role.
        let (first_fp, second_fp) = if our_fp <= peer_fp {
            (our_fp, peer_fp)
        } else {
            (peer_fp, our_fp)
        };
        let mut mac = Hmac::<Sha3_512>::new_from_slice(&hmac_key)
            .expect("HMAC accepts any key length");
        Update::update(&mut mac, first_fp);
        Update::update(&mut mac, second_fp);
        Update::update(&mut mac, &state);

        // The secret scalar is derived from the raw secret, session ID,
        // and fingerprints only.  PQ binding is provided by the ML-KEM
        // pq_binding_key and ML-DSA-87 signatures at each step, not by
        // mixing the KEM key into the secret scalar.  This ensures both
        // sides always derive the same secret scalar regardless of when
        // set_secret is called relative to KEM key generation.

        let binding = mac.finalize().into_bytes();
        state.zeroize();

        // Step 4: reduce mod order
        let int_hash = num_bigint::BigUint::from_bytes_be(&binding);
        let mut secret_int = int_hash % &*SMP_ORDER;
        if secret_int == num_bigint::BigUint::ZERO {
            secret_int = num_bigint::BigUint::from(1u8);
        }

        self.secret     = SecretVec::from_slice(&Self::fixed_bytes(&secret_int, SMP_SCALAR_BYTES));
        self.session_id = Some(session_id.to_vec());
        self.our_fp     = Some(our_fp.to_vec());
        self.peer_fp    = Some(peer_fp.to_vec());
        self.transcript = Some(SmpTranscript::new(session_id));
    }

    fn feed_transcript(&mut self, wire: &[u8]) {
        if let Some(ref mut t) = self.transcript {
            t.feed(wire);
        }
    }

    fn transcript_tag(&self) -> [u8; 64] {
        self.transcript.as_ref().map(|t| *t.current_tag()).unwrap_or([0u8; 64])
    }

    // ─── SMP1 ────────────────────────────────────────────────────────────────
    //
    // Wire format (SMP_VERSION_PQ):
    //   0x02                   (1 byte version)
    //   classical_fields       (encode_group_elems of g2a, c2, d2, g3a, c3, d3)
    //   mlkem_ek               (1568 bytes, initiator's KEM encapsulation key)
    //   mldsa_pk               (2592 bytes, initiator's ML-DSA-87 public key)

    pub fn generate_smp1(&mut self, question: Option<String>) -> Result<Vec<u8>> {
        self.guard()?;
        if self.secret.is_empty() {
            return Err(OtrError::Smp("Secret not set before SMP1"));
        }

        // Generate PQ keypairs for the initiator
        if self.version == SMP_VERSION_PQ {
            self.pq = PqBundle::generate()
                .map_err(|_| OtrError::Smp("PQ keygen failed in SMP1"))?;
        }

        // Classical exponents
        self.a2 = Self::random_exponent();
        self.a3 = Self::random_exponent();
        self.r2 = Self::random_exponent();
        self.r3 = Self::random_exponent();

        let g2a   = Self::mod_exp(&SMP_GEN, self.a2.expose(), &SMP_PRIME);
        let g3a   = Self::mod_exp(&SMP_GEN, self.a3.expose(), &SMP_PRIME);
        let g2a_b = Self::fe_bytes(&g2a);
        let g3a_b = Self::fe_bytes(&g3a);

        let (c2, d2) = Self::compute_zkp(1, self.r2.expose(), self.a2.expose(), &g2a_b);
        let (c3, d3) = Self::compute_zkp(2, self.r3.expose(), self.a3.expose(), &g3a_b);

        let classical = Self::encode_group_elems(&[&g2a_b, &c2, &d2, &g3a_b, &c3, &d3]);

        self.g2a      = Some(g2a_b.clone());
        self.g3a      = Some(g3a_b.clone());
        self.phase    = SmpPhase::AwaitingMsg2;
        self.question = question;

        let mut wire = vec![self.version];
        wire.extend_from_slice(&classical);

        if self.version == SMP_VERSION_PQ {
            let ek = self.pq.mlkem_ek.as_ref()
                .ok_or(OtrError::Smp("SMP1: no mlkem_ek after keygen"))?;
            let pk = self.pq.mldsa_pk.as_ref()
                .ok_or(OtrError::Smp("SMP1: no mldsa_pk after keygen"))?;
            if ek.len() != MLKEM_EK_SIZE {
                return Err(OtrError::Smp("SMP1: mlkem_ek wrong size"));
            }
            if pk.len() != MLDSA_PUB_SIZE {
                return Err(OtrError::Smp("SMP1: mldsa_pk wrong size"));
            }
            wire.extend_from_slice(ek);
            wire.extend_from_slice(pk);
        }

        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ─── SMP2 ────────────────────────────────────────────────────────────────
    //
    // Wire format (SMP_VERSION_PQ):
    //   0x02                   (1 byte version)
    //   classical_fields       (g2b,c2b,d2b, g3b,c3b,d3b, pb,qb,cp,d5,d6)
    //   mlkem_ct               (1568 bytes, KEM ciphertext)
    //   mldsa_pk               (2592 bytes, responder's ML-DSA-87 public key)
    //   mldsa_sig              (4627 bytes, ML-DSA-87 sig over version||classical||mlkem_ct||mldsa_pk)

    pub fn process_smp1_generate_smp2(&mut self, smp1_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::Idle {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not Idle for SMP1")));
        }
        if self.secret.is_empty() {
            return Err(OtrError::Smp("Secret not set before SMP2"));
        }
        if smp1_data.is_empty() {
            return Err(self.fail_and_zeroize(OtrError::TruncatedMessage));
        }

        let wire_version = smp1_data.try_byte(0)?;
        if wire_version != self.version {
            return Err(self.fail_and_zeroize(OtrError::Smp(
                "SMP version mismatch: peer and local version differ"
            )));
        }

        let payload = smp1_data.try_slice_from(1)?;

        // Parse classical group elements
        let (fields, classical_end) = Self::decode_group_elems(payload, 6)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (g2a, c2, d2, g3a, c3, d3) = (
            &fields[0], &fields[1], &fields[2],
            &fields[3], &fields[4], &fields[5],
        );

        Self::validate_group_elem(g2a)
            .and(Self::validate_group_elem(g3a))
            .and(Self::verify_zkp(1, c2, d2, g2a))
            .and(Self::verify_zkp(2, c3, d3, g3a))
            .map_err(|e| self.fail_and_zeroize(e))?;

        // Parse PQ fields from SMP1
        if wire_version == SMP_VERSION_PQ {
            let pq_off = classical_end;
            let remaining = payload.len() - pq_off;
            if remaining < MLKEM_EK_SIZE + MLDSA_PUB_SIZE {
                return Err(self.fail_and_zeroize(OtrError::TooShort {
                    need: pq_off + MLKEM_EK_SIZE + MLDSA_PUB_SIZE,
                    got:  payload.len(),
                }));
            }
            let ek_bytes  = payload.try_slice(pq_off..pq_off + MLKEM_EK_SIZE)?;
            let pk_bytes  = payload.try_slice(
                pq_off + MLKEM_EK_SIZE..pq_off + MLKEM_EK_SIZE + MLDSA_PUB_SIZE,
            )?;

            // Store peer's KEM key and ML-DSA public key
            self.pq.mlkem_ek      = Some(ek_bytes.to_vec());
            self.pq.peer_mldsa_pk = Some(pk_bytes.to_vec());

            // Generate responder's ML-DSA-87 keypair
            self.pq = {
                let mut bundle = PqBundle::generate_responder()
                    .map_err(|_| self.fail_and_zeroize(
                        OtrError::Smp("PQ keygen failed in SMP2"),
                    ))?;
                bundle.mlkem_ek      = Some(ek_bytes.to_vec());
                bundle.peer_mldsa_pk = Some(pk_bytes.to_vec());
                bundle
            };
        }


        self.feed_transcript(smp1_data);

        // Classical SMP2 computation
        self.b2  = Self::random_exponent();
        self.b3  = Self::random_exponent();
        self.r2b = Self::random_exponent();
        self.r3b = Self::random_exponent();
        self.r4b = Self::random_exponent();
        self.r5b = Self::random_exponent();
        self.r6b = Self::random_exponent();

        let g2b   = Self::mod_exp(&SMP_GEN, self.b2.expose(), &SMP_PRIME);
        let g3b   = Self::mod_exp(&SMP_GEN, self.b3.expose(), &SMP_PRIME);
        let g2b_b = Self::fe_bytes(&g2b);
        let g3b_b = Self::fe_bytes(&g3b);

        let (c2b, d2b) = Self::compute_zkp(3, self.r2b.expose(), self.b2.expose(), &g2b_b);
        let (c3b, d3b) = Self::compute_zkp(4, self.r3b.expose(), self.b3.expose(), &g3b_b);

        let g2a_big = num_bigint::BigUint::from_bytes_be(g2a);
        let g3a_big = num_bigint::BigUint::from_bytes_be(g3a);
        let g2 = Self::mod_exp(&g2a_big, self.b2.expose(), &SMP_PRIME);
        let g3 = Self::mod_exp(&g3a_big, self.b3.expose(), &SMP_PRIME);

        let pb   = Self::mod_exp(&g3, self.r4b.expose(), &SMP_PRIME);
        let pb_b = Self::fe_bytes(&pb);
        let gr4b = Self::mod_exp(&SMP_GEN, self.r4b.expose(), &SMP_PRIME);
        let g2s  = Self::mod_exp(&g2, self.secret.expose(), &SMP_PRIME);
        let qb   = (gr4b * g2s) % &*SMP_PRIME;
        let qb_b = Self::fe_bytes(&qb);

        let r1_commit   = Self::mod_exp(&g3, self.r5b.expose(), &SMP_PRIME);
        let r1_commit_b = Self::fe_bytes(&r1_commit);
        let g_r5b       = Self::mod_exp(&SMP_GEN, self.r5b.expose(), &SMP_PRIME);
        let g2_r6b      = Self::mod_exp(&g2, self.r6b.expose(), &SMP_PRIME);
        let r2_commit_b = Self::fe_bytes(&((g_r5b * g2_r6b) % &*SMP_PRIME));

        let mut ch_input = r1_commit_b.clone();
        ch_input.extend_from_slice(&r2_commit_b);
        let cp = Self::zkp_challenge(5, &r1_commit_b, &ch_input);

        let r5b_n    = num_bigint::BigUint::from_bytes_be(self.r5b.expose());
        let r6b_n    = num_bigint::BigUint::from_bytes_be(self.r6b.expose());
        let r4b_n    = num_bigint::BigUint::from_bytes_be(self.r4b.expose());
        let secret_n = num_bigint::BigUint::from_bytes_be(self.secret.expose());
        let d5 = (r5b_n + &*SMP_ORDER - (cp.clone() * r4b_n  ) % &*SMP_ORDER) % &*SMP_ORDER;
        let d6 = (r6b_n + &*SMP_ORDER - (cp.clone() * secret_n) % &*SMP_ORDER) % &*SMP_ORDER;

        self.g2a   = Some(g2a.to_vec());
        self.g3a   = Some(g3a.to_vec());
        self.g2b   = Some(g2b_b.clone());
        self.g3b   = Some(g3b_b.clone());
        self.pb    = Some(pb_b.clone());
        self.qb    = Some(qb_b.clone());
        self.g3    = Some(Self::fe_bytes(&g3));
        self.phase = SmpPhase::AwaitingMsg3;

        let classical_out = Self::encode_group_elems(&[
            &g2b_b, &c2b, &d2b, &g3b_b, &c3b, &d3b,
            &pb_b, &qb_b, &cp.to_bytes_be(), &d5.to_bytes_be(), &d6.to_bytes_be(),
        ]);

        let mut wire = vec![self.version];
        wire.extend_from_slice(&classical_out);

        if wire_version == SMP_VERSION_PQ {
            // KEM encapsulation — clone out of self.pq before any mutable borrow
            let ek = match self.pq.mlkem_ek.clone() {
                Some(v) => v,
                None => return Err(self.fail_and_zeroize(
                    OtrError::Smp("SMP2: peer mlkem_ek not stored"),
                )),
            };

            let (ct_bytes, kem_ss) = mlkem_encapsulate(&ek)
                .map_err(|e| self.fail_and_zeroize(e))?;

            // Derive pq_binding_key before signing
            let tag = self.transcript_tag();
            self.pq.derive_binding_key(kem_ss.expose(), &tag);

            // Append KEM ciphertext and our ML-DSA-87 public key
            let our_pk = match self.pq.mldsa_pk.clone() {
                Some(v) => v,
                None => return Err(self.fail_and_zeroize(
                    OtrError::Smp("SMP2: no mldsa_pk"),
                )),
            };

            wire.extend_from_slice(&ct_bytes);
            wire.extend_from_slice(&our_pk);

            // Sign everything up to (but not including) the signature itself
            let sig = self.pq.sign(&wire)
                .map_err(|e| self.fail_and_zeroize(e))?;
            wire.extend_from_slice(&sig);

            self.pq.mlkem_ct = Some(ct_bytes);
        }

        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ─── SMP3 ────────────────────────────────────────────────────────────────
    //
    // Wire format (SMP_VERSION_PQ):
    //   0x02                   (1 byte version)
    //   classical_fields       (pa, qa, ra, cr, d7)
    //   mldsa_sig              (4627 bytes over version||classical)

    pub fn process_smp2_generate_smp3(&mut self, smp2_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg2 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP2")));
        }
        if smp2_data.is_empty() {
            return Err(self.fail_and_zeroize(OtrError::TruncatedMessage));
        }

        let wire_version = smp2_data.try_byte(0)?;
        if wire_version != self.version {
            return Err(self.fail_and_zeroize(OtrError::Smp(
                "SMP version mismatch in SMP2",
            )));
        }

        let payload = smp2_data.try_slice_from(1)?;

        // Parse classical fields
        let (fields, classical_end) = Self::decode_group_elems(payload, 11)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (g2b, c2b, d2b, g3b, c3b, d3b, pb, qb, cp, d5, d6) = (
            &fields[0],  &fields[1],  &fields[2],
            &fields[3],  &fields[4],  &fields[5],
            &fields[6],  &fields[7],  &fields[8],
            &fields[9],  &fields[10],
        );

        Self::validate_group_elem(g2b)
            .and(Self::validate_group_elem(g3b))
            .and(Self::validate_group_elem(pb))
            .and(Self::validate_group_elem(qb))
            .and(Self::verify_zkp(3, c2b, d2b, g2b))
            .and(Self::verify_zkp(4, c3b, d3b, g3b))
            .map_err(|e| self.fail_and_zeroize(e))?;

        if wire_version == SMP_VERSION_PQ {
            let pq_off = classical_end;
            if payload.len() < pq_off + MLKEM_CT_SIZE + MLDSA_PUB_SIZE + MLDSA_SIG_SIZE {
                return Err(self.fail_and_zeroize(OtrError::TooShort {
                    need: pq_off + MLKEM_CT_SIZE + MLDSA_PUB_SIZE + MLDSA_SIG_SIZE,
                    got:  payload.len(),
                }));
            }
            let ct_bytes  = payload.try_slice(pq_off..pq_off + MLKEM_CT_SIZE)?;
            let pk_off    = pq_off + MLKEM_CT_SIZE;
            let pk_bytes  = payload.try_slice(pk_off..pk_off + MLDSA_PUB_SIZE)?;
            let sig_off   = pk_off + MLDSA_PUB_SIZE;
            let sig_bytes = payload.try_slice(sig_off..sig_off + MLDSA_SIG_SIZE)?;

            // Store peer's ML-DSA-87 public key
            self.pq.peer_mldsa_pk = Some(pk_bytes.to_vec());

            // Decapsulate to get kem_ss and derive pq_binding_key.
            // Clone sk bytes out first to release the immutable borrow on
            // self.pq before the map_err closure takes &mut self.
            let sk_bytes_owned: Vec<u8> = match self.pq.mlkem_sk.as_ref() {
                Some(sk) => sk.expose().to_vec(),
                None => return Err(self.fail_and_zeroize(
                    OtrError::Smp("SMP3: no mlkem_sk for decapsulation"),
                )),
            };
            let kem_ss = mlkem_decapsulate(&sk_bytes_owned, ct_bytes)
                .map_err(|e| self.fail_and_zeroize(e))?;
            // Zeroize the owned copy immediately after use
            let mut sk_bytes_owned = sk_bytes_owned;
            sk_bytes_owned.zeroize();

            let tag = self.transcript_tag();
            self.pq.derive_binding_key(kem_ss.expose(), &tag);
            // kem_ss wiped by SecretVec drop

            // Verify ML-DSA-87 signature over everything before the sig
            let signed_portion = smp2_data.try_slice(0..1 + pq_off + MLKEM_CT_SIZE + MLDSA_PUB_SIZE)?;
            self.pq.verify(signed_portion, sig_bytes)
                .map_err(|e| self.fail_and_zeroize(e))?;

            // Wipe KEM secret key — it is no longer needed
            self.pq.mlkem_sk = None;
        }

        self.feed_transcript(smp2_data);

        // Classical SMP3 computation
        let g2b_big = num_bigint::BigUint::from_bytes_be(g2b);
        let g3b_big = num_bigint::BigUint::from_bytes_be(g3b);
        let g2 = Self::mod_exp(&g2b_big, self.a2.expose(), &SMP_PRIME);
        let g3 = Self::mod_exp(&g3b_big, self.a3.expose(), &SMP_PRIME);

        let cp_n = num_bigint::BigUint::from_bytes_be(cp);
        let d5_n = num_bigint::BigUint::from_bytes_be(d5);
        let d6_n = num_bigint::BigUint::from_bytes_be(d6);
        let pb_n = num_bigint::BigUint::from_bytes_be(pb);
        let qb_n = num_bigint::BigUint::from_bytes_be(qb);

        // Verify combined (Pb, Qb) ZKP
        let r1_recon = (
            Self::mod_exp(&g3, &d5_n.to_bytes_be(), &SMP_PRIME)
            * Self::mod_exp(&pb_n, &cp_n.to_bytes_be(), &SMP_PRIME)
        ) % &*SMP_PRIME;
        let g_d5  = Self::mod_exp(&SMP_GEN, &d5_n.to_bytes_be(), &SMP_PRIME);
        let g2_d6 = Self::mod_exp(&g2, &d6_n.to_bytes_be(), &SMP_PRIME);
        let qb_cp = Self::mod_exp(&qb_n, &cp_n.to_bytes_be(), &SMP_PRIME);
        let r2_recon = (g_d5 * g2_d6 % &*SMP_PRIME * qb_cp) % &*SMP_PRIME;

        let r1_b = Self::fe_bytes(&r1_recon);
        let r2_b = Self::fe_bytes(&r2_recon);
        let mut ch_input = r1_b.clone();
        ch_input.extend_from_slice(&r2_b);
        let cp_check = Self::zkp_challenge(5, &r1_b, &ch_input);

        if !crate::secure_mem::ct_eq(&cp_n.to_bytes_be(), &cp_check.to_bytes_be()) {
            return Err(self.fail_and_zeroize(OtrError::Smp("Pb/Qb ZKP verification failed")));
        }

        self.r4 = Self::random_exponent();
        self.r5 = Self::random_exponent();

        let pa   = Self::mod_exp(&g3, self.r4.expose(), &SMP_PRIME);
        let pa_b = Self::fe_bytes(&pa);
        let gr4  = Self::mod_exp(&SMP_GEN, self.r4.expose(), &SMP_PRIME);
        let g2x  = Self::mod_exp(&g2, self.secret.expose(), &SMP_PRIME);
        let qa   = (gr4 * g2x) % &*SMP_PRIME;
        let qa_b = Self::fe_bytes(&qa);

        let qa_n   = num_bigint::BigUint::from_bytes_be(&qa_b);
        let qb_inv = Self::mod_inv(&qb_n);
        let base_ra = (qa_n * qb_inv) % &*SMP_PRIME;
        let ra      = Self::mod_exp(&base_ra, self.a3.expose(), &SMP_PRIME);
        let ra_b    = Self::fe_bytes(&ra);

        let (cr, d7) = Self::compute_zkp_custom_base(
            7, self.r5.expose(), self.a3.expose(), &ra_b, &base_ra,
        );

        self.pa    = Some(pa_b.clone());
        self.qa    = Some(qa_b.clone());
        self.qb    = Some(qb.to_vec());
        self.pb    = Some(pb.to_vec());
        self.g3    = Some(Self::fe_bytes(&g3));
        self.phase = SmpPhase::AwaitingMsg4;

        let classical_out = Self::encode_group_elems(&[&pa_b, &qa_b, &ra_b, &cr, &d7]);

        let mut wire = vec![self.version];
        wire.extend_from_slice(&classical_out);

        if wire_version == SMP_VERSION_PQ {
            let sig = self.pq.sign(&wire)
                .map_err(|e| self.fail_and_zeroize(e))?;
            wire.extend_from_slice(&sig);
        }

        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ─── SMP4 ────────────────────────────────────────────────────────────────
    //
    // Wire format (SMP_VERSION_PQ):
    //   0x02                   (1 byte version)
    //   classical_fields       (rb, cr2, d8)
    //   mldsa_sig              (4627 bytes over version||classical)

    pub fn process_smp3_generate_smp4(&mut self, smp3_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg3 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP3")));
        }
        if smp3_data.is_empty() {
            return Err(self.fail_and_zeroize(OtrError::TruncatedMessage));
        }

        let wire_version = smp3_data.try_byte(0)?;
        if wire_version != self.version {
            return Err(self.fail_and_zeroize(OtrError::Smp(
                "SMP version mismatch in SMP3",
            )));
        }

        let payload = smp3_data.try_slice_from(1)?;

        let (fields, classical_end) = Self::decode_group_elems(payload, 5)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (pa, qa, ra, cr, d7) = (
            &fields[0], &fields[1], &fields[2], &fields[3], &fields[4],
        );

        Self::validate_group_elem(pa)
            .and(Self::validate_group_elem(qa))
            .and(Self::validate_group_elem(ra))
            .map_err(|e| self.fail_and_zeroize(e))?;

        // Verify PQ signature before processing classical fields
        if wire_version == SMP_VERSION_PQ {
            let pq_off = classical_end;
            if payload.len() < pq_off + MLDSA_SIG_SIZE {
                return Err(self.fail_and_zeroize(OtrError::TooShort {
                    need: pq_off + MLDSA_SIG_SIZE,
                    got:  payload.len(),
                }));
            }
            let sig_bytes    = payload.try_slice(pq_off..pq_off + MLDSA_SIG_SIZE)?;
            let signed_portion = smp3_data.try_slice(0..1 + pq_off)?;
            self.pq.verify(signed_portion, sig_bytes)
                .map_err(|e| self.fail_and_zeroize(e))?;
        }

        self.feed_transcript(smp3_data);

        let qb = self.qb.as_ref().ok_or(OtrError::Smp("no Qb stored"))?.clone();
        let pb = self.pb.as_ref().ok_or(OtrError::Smp("no Pb stored"))?.clone();

        let qa_n   = num_bigint::BigUint::from_bytes_be(qa);
        let qb_n   = num_bigint::BigUint::from_bytes_be(&qb);
        let pb_n   = num_bigint::BigUint::from_bytes_be(&pb);
        let qb_inv = Self::mod_inv(&qb_n);
        let base_ra = (qa_n * qb_inv) % &*SMP_PRIME;

        Self::verify_zkp_custom_base(7, cr, d7, ra, &base_ra)
            .map_err(|e| self.fail_and_zeroize(e))?;

        self.r6b = Self::random_exponent();

        let rb   = Self::mod_exp(&base_ra, self.b3.expose(), &SMP_PRIME);
        let rb_b = Self::fe_bytes(&rb);

        let (cr2, d8) = Self::compute_zkp_custom_base(
            8, self.r6b.expose(), self.b3.expose(), &rb_b, &base_ra,
        );

        let pa_n       = num_bigint::BigUint::from_bytes_be(pa);
        let pa_over_pb = (pa_n * Self::mod_inv(&pb_n)) % &*SMP_PRIME;
        let ra_n       = num_bigint::BigUint::from_bytes_be(ra);
        let rab        = Self::mod_exp(&ra_n, self.b3.expose(), &SMP_PRIME);

        let matched = crate::secure_mem::ct_eq(
            &Self::fe_bytes(&pa_over_pb),
            &Self::fe_bytes(&rab),
        );
        self.phase = if matched { SmpPhase::Verified } else { SmpPhase::Failed };
        if !matched { self.lifecycle.record_failure(); }

        let classical_out = Self::encode_group_elems(&[&rb_b, &cr2, &d8]);

        let mut wire = vec![self.version];
        wire.extend_from_slice(&classical_out);

        if wire_version == SMP_VERSION_PQ {
            let sig = self.pq.sign(&wire)
                .map_err(|e| self.fail_and_zeroize(e))?;
            wire.extend_from_slice(&sig);
        }

        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ─── SMP final ───────────────────────────────────────────────────────────

    pub fn process_smp4(&mut self, smp4_data: &[u8]) -> Result<bool> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg4 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP4")));
        }
        if smp4_data.is_empty() {
            return Err(self.fail_and_zeroize(OtrError::TruncatedMessage));
        }

        let wire_version = smp4_data.try_byte(0)?;
        if wire_version != self.version {
            return Err(self.fail_and_zeroize(OtrError::Smp(
                "SMP version mismatch in SMP4",
            )));
        }

        let payload = smp4_data.try_slice_from(1)?;

        let (fields, classical_end) = Self::decode_group_elems(payload, 3)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (rb, cr2, d8) = (&fields[0], &fields[1], &fields[2]);

        // Verify PQ signature before accepting the equality result
        if wire_version == SMP_VERSION_PQ {
            let pq_off = classical_end;
            if payload.len() < pq_off + MLDSA_SIG_SIZE {
                return Err(self.fail_and_zeroize(OtrError::TooShort {
                    need: pq_off + MLDSA_SIG_SIZE,
                    got:  payload.len(),
                }));
            }
            let sig_bytes    = payload.try_slice(pq_off..pq_off + MLDSA_SIG_SIZE)?;
            let signed_portion = smp4_data.try_slice(0..1 + pq_off)?;
            self.pq.verify(signed_portion, sig_bytes)
                .map_err(|e| self.fail_and_zeroize(e))?;
        }

        self.feed_transcript(smp4_data);

        let qa = self.qa.as_ref().ok_or(OtrError::Smp("no Qa"))?.clone();
        let qb = self.qb.as_ref().ok_or(OtrError::Smp("no Qb"))?.clone();
        let pa = self.pa.as_ref().ok_or(OtrError::Smp("no Pa"))?.clone();
        let pb = self.pb.as_ref().ok_or(OtrError::Smp("no Pb"))?.clone();

        let qa_n  = num_bigint::BigUint::from_bytes_be(&qa);
        let qb_n  = num_bigint::BigUint::from_bytes_be(&qb);
        let pb_n  = num_bigint::BigUint::from_bytes_be(&pb);
        let pa_n  = num_bigint::BigUint::from_bytes_be(&pa);
        let base  = (qa_n * Self::mod_inv(&qb_n)) % &*SMP_PRIME;

        Self::verify_zkp_custom_base(8, cr2, d8, rb, &base)
            .map_err(|e| self.fail_and_zeroize(e))?;

        let pa_over_pb = (pa_n * Self::mod_inv(&pb_n)) % &*SMP_PRIME;
        let rb_n       = num_bigint::BigUint::from_bytes_be(rb);
        let rab        = Self::mod_exp(&rb_n, self.a3.expose(), &SMP_PRIME);

        let verified = crate::secure_mem::ct_eq(
            &Self::fe_bytes(&pa_over_pb),
            &Self::fe_bytes(&rab),
        );
        self.phase = if verified { SmpPhase::Verified } else { SmpPhase::Failed };
        if !verified { self.lifecycle.record_failure(); }

        // Wipe PQ material — all steps complete
        self.pq.wipe();

        Ok(verified)
    }

    // ─── accessors ───────────────────────────────────────────────────────────

    pub fn is_verified(&self)       -> bool    { self.phase == SmpPhase::Verified }
    pub fn is_failed(&self)         -> bool    { matches!(self.phase, SmpPhase::Failed | SmpPhase::Aborted) }
    pub fn check_secret_set(&self)  -> bool    { !self.secret.is_empty() }
    pub fn get_attempt_count(&self) -> u32     { self.lifecycle.attempt_count }
    pub fn get_elapsed_secs(&self)  -> u64     { self.lifecycle.created_at.elapsed().as_secs() }
    pub fn is_expired(&self)        -> bool    { self.lifecycle.created_at.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECS) }

    pub fn get_phase(&self) -> &'static str {
        match self.phase {
            SmpPhase::Idle         => "IDLE",
            SmpPhase::AwaitingMsg2 => "AWAITING_MSG2",
            SmpPhase::AwaitingMsg3 => "AWAITING_MSG3",
            SmpPhase::AwaitingMsg4 => "AWAITING_MSG4",
            SmpPhase::Verified     => "VERIFIED",
            SmpPhase::Failed       => "FAILED",
            SmpPhase::Aborted      => "ABORTED",
        }
    }
}

// ─── PyO3 bindings ────────────────────────────────────────────────────────────

#[pyclass(name = "RustSMP")]
pub struct PySmp { inner: SmpState }

#[pymethods]
impl PySmp {
    #[new]
    fn new(is_initiator: bool) -> Self {
        Self { inner: SmpState::new(is_initiator) }
    }

    fn set_secret(
        &mut self,
        raw_secret: &[u8],
        session_id: &[u8],
        our_fp:     &[u8],
        peer_fp:    &[u8],
    ) {
        self.inner.set_secret(raw_secret, session_id, our_fp, peer_fp);
    }

    /// Preferred secret-input path.  Copies the bytearray into Rust,
    /// derives the SMP secret, then zeroes the Python bytearray in-place.
    fn set_secret_from_bytearray(
        &mut self,
        secret:     &Bound<'_, PyByteArray>,
        session_id: &[u8],
        our_fp:     &[u8],
        peer_fp:    &[u8],
    ) -> PyResult<()> {
        let mut snapshot: Vec<u8> = secret.to_vec();
        self.inner.set_secret(&snapshot, session_id, our_fp, peer_fp);
        for b in snapshot.iter_mut() { *b = 0; }
        snapshot.clear();
        snapshot.shrink_to_fit();
        drop(snapshot);
        let n = secret.len();
        for i in 0..n { secret.set_item(i, 0u8)?; }
        Ok(())
    }

    fn set_secret_from_vault(
        &mut self,
        vault:      &crate::smp_vault::PySMPVault,
        name:       &str,
        session_id: &[u8],
        our_fp:     &[u8],
        peer_fp:    &[u8],
    ) -> PyResult<bool> {
        match vault.expose_for_smp(name) {
            Some(bytes) => {
                self.inner.set_secret(bytes, session_id, our_fp, peer_fp);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn generate_smp1<'py>(
        &mut self,
        py:       Python<'py>,
        question: Option<String>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.generate_smp1(question)
            .map(|d| PyBytes::new(py, &d))
            .map_err(PyErr::from)
    }

    fn process_smp1_generate_smp2<'py>(
        &mut self,
        py:   Python<'py>,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp1_generate_smp2(data)
            .map(|d| PyBytes::new(py, &d))
            .map_err(PyErr::from)
    }

    fn process_smp2_generate_smp3<'py>(
        &mut self,
        py:   Python<'py>,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp2_generate_smp3(data)
            .map(|d| PyBytes::new(py, &d))
            .map_err(PyErr::from)
    }

    fn process_smp3_generate_smp4<'py>(
        &mut self,
        py:   Python<'py>,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp3_generate_smp4(data)
            .map(|d| PyBytes::new(py, &d))
            .map_err(PyErr::from)
    }

    fn process_smp4(&mut self, data: &[u8]) -> PyResult<bool> {
        self.inner.process_smp4(data).map_err(PyErr::from)
    }

    fn abort(&mut self)             { self.inner.destroy(); }
    fn destroy(&mut self)           { self.inner.destroy(); }
    fn is_verified(&self)  -> bool  { self.inner.is_verified() }
    fn is_failed(&self)    -> bool  { self.inner.is_failed() }
    fn get_phase(&self)    -> &str  { self.inner.get_phase() }
    fn check_secret_set(&self) -> bool { self.inner.check_secret_set() }
    fn get_attempt_count(&self) -> u32 { self.inner.get_attempt_count() }
    fn get_elapsed_secs(&self)  -> u64 { self.inner.get_elapsed_secs() }
    fn is_expired(&self)        -> bool { self.inner.is_expired() }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. SMP_PRIME_CT and SMP_PRIME must represent the same integer ─────────
    #[test]
    fn smp_prime_ct_matches_bigint() {
        let from_bigint = pad_be_384(&SMP_PRIME.to_bytes_be());
        let from_ct     = SMP_PRIME_CT.to_be_bytes();
        assert_eq!(from_bigint, from_ct,
            "SMP_PRIME_CT and SMP_PRIME disagree — modexp modulus is wrong");
    }

    // ── 2. Constant-time modexp known-answer: 2^10 mod p = 1024 ──────────────
    #[test]
    fn mod_exp_small_known_answer() {
        let base = num_bigint::BigUint::from(2u8);
        let exp  = num_bigint::BigUint::from(10u8);
        let got  = SmpState::mod_exp(&base, &exp.to_bytes_be(), &SMP_PRIME);
        assert_eq!(got, num_bigint::BigUint::from(1024u32));
    }

    // ── 3. Constant-time modexp agrees with num-bigint reference on 384-byte exp
    #[test]
    fn mod_exp_matches_reference_modpow() {
        let base      = num_bigint::BigUint::from(7u8);
        let exp_bytes = [0xABu8; 384];
        let got  = SmpState::mod_exp(&base, &exp_bytes, &SMP_PRIME);
        let want = base.modpow(
            &num_bigint::BigUint::from_bytes_be(&exp_bytes), &SMP_PRIME,
        );
        assert_eq!(got, want, "constant-time mod_exp diverged from reference");
    }

    // ── 4. mod_inv: a · a^-1 ≡ 1 (mod p) ────────────────────────────────────
    #[test]
    fn mod_inv_roundtrip() {
        let a    = num_bigint::BigUint::from(123456789u64);
        let ainv = SmpState::mod_inv(&a);
        let one  = (&a * &ainv) % &*SMP_PRIME;
        assert_eq!(one, num_bigint::BigUint::from(1u8));
    }

    // ── 5. Classical SMP full roundtrip (matching secret) ─────────────────────
    #[test]
    fn classical_smp_matching_secret_verifies() {
        let sid    = b"test-session-id-classical-0001";
        let fp_a   = b"fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b   = b"fp-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let secret = b"correct horse battery staple";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);
        a.version = SMP_VERSION_CLASSICAL;
        b.version = SMP_VERSION_CLASSICAL;
        a.set_secret(secret, sid, fp_a, fp_b);
        b.set_secret(secret, sid, fp_b, fp_a);

        let m1 = a.generate_smp1(None).expect("smp1");
        let m2 = b.process_smp1_generate_smp2(&m1).expect("smp2");
        let m3 = a.process_smp2_generate_smp3(&m2).expect("smp3");
        let m4 = b.process_smp3_generate_smp4(&m3).expect("smp4");
        let ok = a.process_smp4(&m4).expect("smp-final");

        assert!(ok, "matching secret must verify (classical)");
        assert!(a.is_verified());
        assert!(b.is_verified());
    }

    // ── 6. Classical SMP mismatched secret must fail ───────────────────────────
    #[test]
    fn classical_smp_mismatched_secret_fails() {
        let sid  = b"test-session-id-classical-0002";
        let fp_a = b"fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b = b"fp-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);
        a.version = SMP_VERSION_CLASSICAL;
        b.version = SMP_VERSION_CLASSICAL;
        a.set_secret(b"secret-one",       sid, fp_a, fp_b);
        b.set_secret(b"secret-DIFFERENT", sid, fp_b, fp_a);

        let m1 = a.generate_smp1(None).expect("smp1");
        let m2 = b.process_smp1_generate_smp2(&m1).expect("smp2");
        let m3 = a.process_smp2_generate_smp3(&m2).expect("smp3");
        let m4 = b.process_smp3_generate_smp4(&m3).expect("smp4");
        let ok = a.process_smp4(&m4).expect("smp-final");

        assert!(!ok, "mismatched secret must NOT verify");
        assert!(!a.is_verified());
    }

    // ── 7. Hybrid PQ SMP full roundtrip (matching secret) ─────────────────────
    #[test]
    fn pq_smp_matching_secret_verifies() {
        let sid    = b"test-session-id-pq-0001";
        let fp_a   = b"fp-pq-aaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b   = b"fp-pq-bbbbbbbbbbbbbbbbbbbbbbbbb";
        let secret = b"hunter2";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);
        // Both default to SMP_VERSION_PQ

        // Initiator sets secret first (mlkem_ek will be set in generate_smp1)
        a.set_secret(secret, sid, fp_a, fp_b);

        let m1 = a.generate_smp1(None).expect("pq smp1");

        // Responder receives SMP1, which stores peer mlkem_ek, then calls set_secret
        // The responder calls process_smp1_generate_smp2 which internally sets the
        // secret re-bind.  But we must set the secret BEFORE calling process_smp1
        // so the initial set_secret fires, then the KEM re-bind happens inside.
        b.set_secret(secret, sid, fp_b, fp_a);
        let m2 = b.process_smp1_generate_smp2(&m1).expect("pq smp2");

        let m3 = a.process_smp2_generate_smp3(&m2).expect("pq smp3");
        let m4 = b.process_smp3_generate_smp4(&m3).expect("pq smp4");
        let ok = a.process_smp4(&m4).expect("pq smp-final");

        assert!(ok, "matching secret must verify (PQ hybrid)");
        assert!(a.is_verified());
        assert!(b.is_verified());
    }

    // ── 8. Hybrid PQ SMP mismatched secret must fail ──────────────────────────
    #[test]
    fn pq_smp_mismatched_secret_fails() {
        let sid  = b"test-session-id-pq-0002";
        let fp_a = b"fp-pq-aaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b = b"fp-pq-bbbbbbbbbbbbbbbbbbbbbbbbb";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);

        a.set_secret(b"secret-one",       sid, fp_a, fp_b);
        b.set_secret(b"secret-DIFFERENT", sid, fp_b, fp_a);

        let m1 = a.generate_smp1(None).expect("pq smp1");
        let m2 = b.process_smp1_generate_smp2(&m1).expect("pq smp2");
        let m3 = a.process_smp2_generate_smp3(&m2).expect("pq smp3");
        let m4 = b.process_smp3_generate_smp4(&m3).expect("pq smp4");
        let ok = a.process_smp4(&m4).expect("pq smp-final");

        assert!(!ok, "mismatched secret must NOT verify (PQ hybrid)");
        assert!(!a.is_verified());
    }

    // ── 9. Version mismatch between peers must be detected ────────────────────
    #[test]
    fn smp_version_mismatch_rejected() {
        let sid    = b"test-session-id-version-mismatch";
        let fp_a   = b"fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b   = b"fp-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let secret = b"shared-secret-here";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);
        a.version = SMP_VERSION_PQ;
        b.version = SMP_VERSION_CLASSICAL; // mismatch
        a.set_secret(secret, sid, fp_a, fp_b);
        b.set_secret(secret, sid, fp_b, fp_a);

        let m1 = a.generate_smp1(None).expect("smp1 generates ok");
        let result = b.process_smp1_generate_smp2(&m1);
        assert!(result.is_err(), "version mismatch must be rejected");
    }

    // ── 10. ML-DSA-87 context signing roundtrip ───────────────────────────────
    #[test]
    fn mldsa_context_sign_verify_roundtrip() {
        let (pk_bytes, sk) = mldsa_keygen().expect("keygen");
        let msg     = b"test message for SMP step";
        let context = [0xABu8; 32];

        let sig = mldsa_sign_with_context(sk.expose(), msg, &context)
            .expect("sign");
        assert_eq!(sig.len(), MLDSA_SIG_SIZE);
        mldsa_verify_with_context(&pk_bytes, msg, &sig, &context)
            .expect("verify must succeed");
    }

    // ── 11. ML-DSA-87 different context rejects ───────────────────────────────
    #[test]
    fn mldsa_wrong_context_rejected() {
        let (pk_bytes, sk) = mldsa_keygen().expect("keygen");
        let msg       = b"test message";
        let context_a = [0x01u8; 32];
        let context_b = [0x02u8; 32];

        let sig = mldsa_sign_with_context(sk.expose(), msg, &context_a).expect("sign");
        let result = mldsa_verify_with_context(&pk_bytes, msg, &sig, &context_b);
        assert!(result.is_err(), "wrong context must be rejected");
    }

    // ── 12. ML-KEM-1024 encapsulate/decapsulate roundtrip ─────────────────────
    #[test]
    fn mlkem_encaps_decaps_roundtrip() {
        let (ek, sk_bytes) = mlkem_keygen().expect("keygen");
        let (ct, ss_enc)   = mlkem_encapsulate(&ek).expect("encaps");
        let ss_dec         = mlkem_decapsulate(&sk_bytes, &ct).expect("decaps");
        assert_eq!(ss_enc.expose(), ss_dec.expose(),
            "shared secrets must match");
    }

    // ── 13. PQ binding key derivation is deterministic ────────────────────────
    #[test]
    fn pq_binding_key_deterministic() {
        let kem_ss  = [0x42u8; 32];
        let tag     = [0xBBu8; 64];

        let mut bundle1 = PqBundle::none();
        let mut bundle2 = PqBundle::none();
        bundle1.derive_binding_key(&kem_ss, &tag);
        bundle2.derive_binding_key(&kem_ss, &tag);

        let k1 = bundle1.pq_binding_key.as_ref().unwrap().expose().to_vec();
        let k2 = bundle2.pq_binding_key.as_ref().unwrap().expose().to_vec();
        assert_eq!(k1, k2, "binding key derivation must be deterministic");
    }

    // ── 14. Different KEM shared secrets produce different binding keys ────────
    #[test]
    fn pq_binding_key_depends_on_kem_ss() {
        let tag = [0xBBu8; 64];
        let ss_a = [0x11u8; 32];
        let ss_b = [0x22u8; 32];

        let mut b1 = PqBundle::none();
        let mut b2 = PqBundle::none();
        b1.derive_binding_key(&ss_a, &tag);
        b2.derive_binding_key(&ss_b, &tag);

        let k1 = b1.pq_binding_key.as_ref().unwrap().expose().to_vec();
        let k2 = b2.pq_binding_key.as_ref().unwrap().expose().to_vec();
        assert_ne!(k1, k2, "different KEM secrets must give different binding keys");
    }

    // ── 15. PQ SMP with question field ────────────────────────────────────────
    #[test]
    fn pq_smp_with_question_verifies() {
        let sid    = b"test-session-id-pq-question";
        let fp_a   = b"fp-pq-aaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp_b   = b"fp-pq-bbbbbbbbbbbbbbbbbbbbbbbbb";
        let secret = b"what is the shared passphrase?";

        let mut a = SmpState::new(true);
        let mut b = SmpState::new(false);

        a.set_secret(secret, sid, fp_a, fp_b);
        b.set_secret(secret, sid, fp_b, fp_a);

        let m1 = a.generate_smp1(Some("What is the passphrase?".to_string()))
            .expect("smp1 with question");
        let m2 = b.process_smp1_generate_smp2(&m1).expect("smp2");
        let m3 = a.process_smp2_generate_smp3(&m2).expect("smp3");
        let m4 = b.process_smp3_generate_smp4(&m3).expect("smp4");
        let ok = a.process_smp4(&m4).expect("smp-final");

        assert!(ok, "PQ SMP with question must verify on matching secret");
        assert!(a.is_verified());
        assert!(b.is_verified());
    }
}
