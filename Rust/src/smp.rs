// src/smp.rs — Socialist Millionaire Protocol (OTRv4 §5) — hardened production build
//
// Fixes applied vs previous revision:
//   1. Removed redundant `Update as _` import inside set_secret()
//   2. fail_and_zeroize() now returns OtrError (not Result<()>) — call sites use Err(self.fail_and_zeroize(...))
//   3. All .map_err(|e| self.fail_and_zeroize(e))? chains replace the old return self.fail_and_zeroize() pattern
//   4. Digest::update() used explicitly for Sha3_512 to avoid Update trait ambiguity
//   5. No unsafe code — mlock removed entirely (was blocked by #![forbid(unsafe_code)])

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};
use sha3::{Sha3_512, Digest};
use sha3::digest::Update;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

use crate::error::{OtrError, Result};
use crate::secure_mem::SecretVec;

const MAX_ATTEMPTS: u32         = 3;
const SESSION_TIMEOUT_SECS: u64 = 600;
const RETRY_COOLDOWN_SECS: u64  = 30;
const KDF_ROUNDS: u32           = 50_000;
const SMP_PRIME_BYTES:  usize   = 256;
const SMP_SCALAR_BYTES: usize   = 256;

lazy_static::lazy_static! {
    static ref SMP_PRIME: num_bigint::BigUint = {
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
        ).expect("SMP prime parse failed")
    };
    static ref SMP_ORDER: num_bigint::BigUint = (SMP_PRIME.clone() - 1u64) >> 1;
    static ref SMP_GEN:   num_bigint::BigUint = num_bigint::BigUint::from(2u8);
}

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

// ── Transcript accumulator ────────────────────────────────────────────────────
struct SmpTranscript {
    mac:       Hmac<Sha3_512>,
    digest:    [u8; 64],
    finalized: bool,
}

impl SmpTranscript {
    fn new(session_id: &[u8]) -> Self {
        let mut key = [0u8; 64];
        let n = session_id.len().min(64);
        key[..n].copy_from_slice(&session_id[..n]);
        let mac = Hmac::<Sha3_512>::new_from_slice(&key)
            .expect("HMAC accepts any key length");
        Self { mac, digest: [0u8; 64], finalized: false }
    }

    fn feed(&mut self, wire_bytes: &[u8]) {
        if !self.finalized {
            Update::update(&mut self.mac, wire_bytes);
        }
    }
}

impl Drop for SmpTranscript {
    fn drop(&mut self) {
        self.digest.zeroize();
    }
}

// ── Rate-limit / lifecycle ────────────────────────────────────────────────────
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

// ── Core SMP state ────────────────────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct SmpState {
    secret: SecretVec,
    a2: SecretVec, a3: SecretVec,
    b2: SecretVec, b3: SecretVec,
    r2: SecretVec, r3: SecretVec, r4: SecretVec, r5: SecretVec, r6: SecretVec,
    r2b: SecretVec, r3b: SecretVec, r4b: SecretVec, r5b: SecretVec, r6b: SecretVec,

    #[zeroize(skip)] g2a: Option<Vec<u8>>,
    #[zeroize(skip)] g3a: Option<Vec<u8>>,
    #[zeroize(skip)] g2b: Option<Vec<u8>>,
    #[zeroize(skip)] g3b: Option<Vec<u8>>,
    #[zeroize(skip)] g3:  Option<Vec<u8>>,
    #[zeroize(skip)] pa:  Option<Vec<u8>>,
    #[zeroize(skip)] qa:  Option<Vec<u8>>,
    #[zeroize(skip)] pb:  Option<Vec<u8>>,
    #[zeroize(skip)] qb:  Option<Vec<u8>>,

    #[zeroize(skip)] pub phase:        SmpPhase,
    #[zeroize(skip)] pub is_initiator: bool,
    #[zeroize(skip)] question:         Option<String>,
    #[zeroize(skip)] session_id:       Option<Vec<u8>>,
    #[zeroize(skip)] our_fp:           Option<Vec<u8>>,
    #[zeroize(skip)] peer_fp:          Option<Vec<u8>>,
    #[zeroize(skip)] lifecycle:        SmpLifecycle,
    #[zeroize(skip)] transcript:       Option<SmpTranscript>,
}

impl SmpState {
    pub fn new(is_initiator: bool) -> Self {
        let e = || SecretVec::new(vec![]);
        Self {
            secret: e(),
            a2: e(), a3: e(),
            b2: e(), b3: e(),
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
        self.a2 = e(); self.a3 = e();
        self.b2 = e(); self.b3 = e();
        self.r2 = e(); self.r3 = e(); self.r4 = e(); self.r5 = e(); self.r6 = e();
        self.r2b = e(); self.r3b = e(); self.r4b = e(); self.r5b = e(); self.r6b = e();
        self.transcript = None;
        self.g2a = None; self.g3a = None;
        self.g2b = None; self.g3b = None; self.g3 = None;
        self.pa  = None; self.qa  = None;
        self.pb  = None; self.qb  = None;
        self.session_id = None;
        self.our_fp     = None;
        self.peer_fp    = None;
        self.phase = SmpPhase::Aborted;
    }

    /// Record failure and return the error. Caller must use: Err(self.fail_and_zeroize(e))
    fn fail_and_zeroize(&mut self, err: OtrError) -> OtrError {
        self.lifecycle.record_failure();
        if self.lifecycle.attempt_count >= MAX_ATTEMPTS {
            self.destroy();
        } else {
            self.phase = SmpPhase::Failed;
        }
        err
    }

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

    fn mod_exp(base: &num_bigint::BigUint, exp_bytes: &[u8], modulus: &num_bigint::BigUint) -> num_bigint::BigUint {
        base.modpow(&num_bigint::BigUint::from_bytes_be(exp_bytes), modulus)
    }

    fn mod_inv(val: &num_bigint::BigUint) -> num_bigint::BigUint {
        val.modpow(&(&*SMP_PRIME - 2u8), &*SMP_PRIME)
    }

    fn zkp_challenge(version: u8, commitment: &[u8], statement: &[u8]) -> num_bigint::BigUint {
        let mut h = Sha3_512::new();
        Digest::update(&mut h, &[version]);
        Digest::update(&mut h, commitment);
        Digest::update(&mut h, statement);
        num_bigint::BigUint::from_bytes_be(&h.finalize()) % &*SMP_ORDER
    }

    fn compute_zkp(version: u8, r_bytes: &[u8], exp_bytes: &[u8], base_val: &[u8]) -> (Vec<u8>, Vec<u8>) {
        Self::compute_zkp_custom_base(version, r_bytes, exp_bytes, base_val, &*SMP_GEN)
    }

    fn compute_zkp_custom_base(
        version: u8, r_bytes: &[u8], exp_bytes: &[u8], base_val: &[u8], base: &num_bigint::BigUint,
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
        Self::verify_zkp_custom_base(version, c_bytes, d_bytes, base_val, &*SMP_GEN)
    }

    fn verify_zkp_custom_base(
        version: u8, c_bytes: &[u8], d_bytes: &[u8], base_val: &[u8], base: &num_bigint::BigUint,
    ) -> Result<()> {
        let c  = num_bigint::BigUint::from_bytes_be(c_bytes);
        let bv = num_bigint::BigUint::from_bytes_be(base_val);
        let gd = Self::mod_exp(base, d_bytes, &SMP_PRIME);
        let gc = bv.modpow(&c, &SMP_PRIME);
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

    fn encode_group_elems(elems: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in elems {
            out.extend_from_slice(&(e.len() as u32).to_be_bytes());
            out.extend_from_slice(e);
        }
        out
    }

    fn decode_group_elems(data: &[u8], count: usize) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(count);
        let mut off = 0usize;
        for _ in 0..count {
            if off + 4 > data.len() { return Err(OtrError::WireFormat); }
            let len = u32::from_be_bytes(
                data[off..off+4].try_into().map_err(|_| OtrError::WireFormat)?,
            ) as usize;
            off += 4;
            if off + len > data.len() { return Err(OtrError::WireFormat); }
            out.push(data[off..off+len].to_vec());
            off += len;
        }
        Ok(out)
    }

    fn validate_group_elem(bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() { return Err(OtrError::SmpRange); }
        let v = num_bigint::BigUint::from_bytes_be(bytes);
        if v < num_bigint::BigUint::from(2u8) || v >= *SMP_PRIME {
            return Err(OtrError::SmpRange);
        }
        Ok(())
    }

    pub fn set_secret(&mut self, raw_secret: &[u8], session_id: &[u8], our_fp: &[u8], peer_fp: &[u8]) {
        use sha3::Shake256;
        use sha3::digest::{ExtendableOutput, XofReader};

        // 1. SHAKE-256 chain: 50 000 rounds
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

        // 2. HMAC-SHA3-512 session binding
        let hmac_key = {
            let mut h = Sha3_512::new();
            Digest::update(&mut h, session_id);
            h.finalize()
        };
        // Canonical ordering: both sides MUST see fingerprints in the same order.
        // Sorting lexicographically ensures initiator and responder compute identical secrets.
        // DO NOT use role bytes or role-dependent ordering — that breaks SMP.
        let (first_fp, second_fp) = if our_fp <= peer_fp { (our_fp, peer_fp) } else { (peer_fp, our_fp) };
        let mut mac = Hmac::<Sha3_512>::new_from_slice(&hmac_key).expect("HMAC key ok");
        
        Update::update(&mut mac, first_fp);
        Update::update(&mut mac, second_fp);
        Update::update(&mut mac, &state);
        let binding = mac.finalize().into_bytes();
        state.zeroize();

        // 3. Reduce mod order
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
        if let Some(ref mut t) = self.transcript { t.feed(wire); }
    }

    // ── SMP1 ─────────────────────────────────────────────────────────────────
    pub fn generate_smp1(&mut self, question: Option<String>) -> Result<Vec<u8>> {
        self.guard()?;
        if self.secret.is_empty() { return Err(OtrError::Smp("Secret not set")); }

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

        self.g2a      = Some(g2a_b.clone());
        self.g3a      = Some(g3a_b.clone());
        self.phase    = SmpPhase::AwaitingMsg2;
        self.question = question;

        let wire = Self::encode_group_elems(&[&g2a_b, &c2, &d2, &g3a_b, &c3, &d3]);
        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ── SMP2 ─────────────────────────────────────────────────────────────────
    pub fn process_smp1_generate_smp2(&mut self, smp1_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::Idle {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not in Idle for SMP1")));
        }
        if self.secret.is_empty() { return Err(OtrError::Smp("Secret not set")); }

        self.feed_transcript(smp1_data);

        let fields = Self::decode_group_elems(smp1_data, 6)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (g2a, c2, d2, g3a, c3, d3) = (
            &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5],
        );

        Self::validate_group_elem(g2a)
            .and(Self::validate_group_elem(g3a))
            .and(Self::verify_zkp(1, c2, d2, g2a))
            .and(Self::verify_zkp(2, c3, d3, g3a))
            .map_err(|e| self.fail_and_zeroize(e))?;

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
        let g2 = g2a_big.modpow(&num_bigint::BigUint::from_bytes_be(self.b2.expose()), &*SMP_PRIME);
        let g3 = g3a_big.modpow(&num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME);

        let pb   = Self::mod_exp(&g3, self.r4b.expose(), &SMP_PRIME);
        let pb_b = Self::fe_bytes(&pb);

        let gr4b = Self::mod_exp(&SMP_GEN, self.r4b.expose(), &SMP_PRIME);
        let g2s  = g2.modpow(&num_bigint::BigUint::from_bytes_be(self.secret.expose()), &*SMP_PRIME);
        let qb   = (gr4b * g2s) % &*SMP_PRIME;
        let qb_b = Self::fe_bytes(&qb);

        // Combined (Pb,Qb) ZKP
        let r1_commit   = Self::mod_exp(&g3, self.r5b.expose(), &SMP_PRIME);
        let r1_commit_b = Self::fe_bytes(&r1_commit);
        let g_r5b       = Self::mod_exp(&SMP_GEN, self.r5b.expose(), &SMP_PRIME);
        let g2_r6b      = g2.modpow(&num_bigint::BigUint::from_bytes_be(self.r6b.expose()), &*SMP_PRIME);
        let r2_commit_b = Self::fe_bytes(&((g_r5b * g2_r6b) % &*SMP_PRIME));

        let mut ch_input = r1_commit_b.clone();
        ch_input.extend_from_slice(&r2_commit_b);
        let cp = Self::zkp_challenge(5, &r1_commit_b, &ch_input);

        let r5b_n    = num_bigint::BigUint::from_bytes_be(self.r5b.expose());
        let r6b_n    = num_bigint::BigUint::from_bytes_be(self.r6b.expose());
        let r4b_n    = num_bigint::BigUint::from_bytes_be(self.r4b.expose());
        let secret_n = num_bigint::BigUint::from_bytes_be(self.secret.expose());
        let d5 = (r5b_n + &*SMP_ORDER - (cp.clone() * r4b_n   ) % &*SMP_ORDER) % &*SMP_ORDER;
        let d6 = (r6b_n + &*SMP_ORDER - (cp.clone() * secret_n) % &*SMP_ORDER) % &*SMP_ORDER;

        self.g2a   = Some(g2a.to_vec());
        self.g3a   = Some(g3a.to_vec());
        self.g2b   = Some(g2b_b.clone());
        self.g3b   = Some(g3b_b.clone());
        self.pb    = Some(pb_b.clone());
        self.qb    = Some(qb_b.clone());
        self.g3    = Some(Self::fe_bytes(&g3));
        self.phase = SmpPhase::AwaitingMsg3;

        let wire = Self::encode_group_elems(&[
            &g2b_b, &c2b, &d2b, &g3b_b, &c3b, &d3b,
            &pb_b, &qb_b, &cp.to_bytes_be(), &d5.to_bytes_be(), &d6.to_bytes_be(),
        ]);
        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ── SMP3 ─────────────────────────────────────────────────────────────────
    pub fn process_smp2_generate_smp3(&mut self, smp2_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg2 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP2")));
        }

        self.feed_transcript(smp2_data);

        let fields = Self::decode_group_elems(smp2_data, 11)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (g2b, c2b, d2b, g3b, c3b, d3b, pb, qb, cp, d5, d6) = (
            &fields[0], &fields[1], &fields[2],  &fields[3], &fields[4],
            &fields[5], &fields[6], &fields[7],  &fields[8], &fields[9], &fields[10],
        );

        Self::validate_group_elem(g2b)
            .and(Self::validate_group_elem(g3b))
            .and(Self::validate_group_elem(pb))
            .and(Self::validate_group_elem(qb))
            .and(Self::verify_zkp(3, c2b, d2b, g2b))
            .and(Self::verify_zkp(4, c3b, d3b, g3b))
            .map_err(|e| self.fail_and_zeroize(e))?;

        let g2b_big = num_bigint::BigUint::from_bytes_be(g2b);
        let g3b_big = num_bigint::BigUint::from_bytes_be(g3b);
        let g2 = g2b_big.modpow(&num_bigint::BigUint::from_bytes_be(self.a2.expose()), &*SMP_PRIME);
        let g3 = g3b_big.modpow(&num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME);

        let cp_n = num_bigint::BigUint::from_bytes_be(cp);
        let d5_n = num_bigint::BigUint::from_bytes_be(d5);
        let d6_n = num_bigint::BigUint::from_bytes_be(d6);
        let pb_n = num_bigint::BigUint::from_bytes_be(pb);
        let qb_n = num_bigint::BigUint::from_bytes_be(qb);

        // Verify combined (Pb,Qb) ZKP: R1'=g3^d5·Pb^cp, R2'=G^d5·g2^d6·Qb^cp
        let r1_recon = (Self::mod_exp(&g3, &d5_n.to_bytes_be(), &SMP_PRIME)
            * pb_n.modpow(&cp_n, &SMP_PRIME)) % &*SMP_PRIME;
        let g_d5     = Self::mod_exp(&SMP_GEN, &d5_n.to_bytes_be(), &SMP_PRIME);
        let g2_d6    = g2.modpow(&d6_n, &SMP_PRIME);
        let qb_cp    = qb_n.modpow(&cp_n, &SMP_PRIME);
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
        let g2x  = g2.modpow(&num_bigint::BigUint::from_bytes_be(self.secret.expose()), &*SMP_PRIME);
        let qa   = (gr4 * g2x) % &*SMP_PRIME;
        let qa_b = Self::fe_bytes(&qa);

        let qa_n    = num_bigint::BigUint::from_bytes_be(&qa_b);
        let qb_inv  = Self::mod_inv(&qb_n);
        let base_ra = (qa_n * qb_inv) % &*SMP_PRIME;
        let ra      = base_ra.modpow(&num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME);
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

        let wire = Self::encode_group_elems(&[&pa_b, &qa_b, &ra_b, &cr, &d7]);
        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ── SMP4 ─────────────────────────────────────────────────────────────────
    pub fn process_smp3_generate_smp4(&mut self, smp3_data: &[u8]) -> Result<Vec<u8>> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg3 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP3")));
        }

        self.feed_transcript(smp3_data);

        let fields = Self::decode_group_elems(smp3_data, 5)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (pa, qa, ra, cr, d7) = (
            &fields[0], &fields[1], &fields[2], &fields[3], &fields[4],
        );

        Self::validate_group_elem(pa)
            .and(Self::validate_group_elem(qa))
            .and(Self::validate_group_elem(ra))
            .map_err(|e| self.fail_and_zeroize(e))?;

        let qb = self.qb.as_ref().ok_or(OtrError::Smp("no Qb stored"))?.clone();
        let pb = self.pb.as_ref().ok_or(OtrError::Smp("no Pb stored"))?.clone();

        let qa_n    = num_bigint::BigUint::from_bytes_be(qa);
        let qb_n    = num_bigint::BigUint::from_bytes_be(&qb);
        let pb_n    = num_bigint::BigUint::from_bytes_be(&pb);
        let qb_inv  = Self::mod_inv(&qb_n);
        let base_ra = (qa_n * qb_inv) % &*SMP_PRIME;

        Self::verify_zkp_custom_base(7, cr, d7, ra, &base_ra)
            .map_err(|e| self.fail_and_zeroize(e))?;

        self.r6b = Self::random_exponent();

        let rb   = base_ra.modpow(&num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME);
        let rb_b = Self::fe_bytes(&rb);

        let (cr2, d8) = Self::compute_zkp_custom_base(
            8, self.r6b.expose(), self.b3.expose(), &rb_b, &base_ra,
        );

        let pa_n       = num_bigint::BigUint::from_bytes_be(pa);
        let pa_over_pb = (pa_n * Self::mod_inv(&pb_n)) % &*SMP_PRIME;
        let ra_n       = num_bigint::BigUint::from_bytes_be(ra);
        let rab        = ra_n.modpow(&num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME);

        let matched = crate::secure_mem::ct_eq(&Self::fe_bytes(&pa_over_pb), &Self::fe_bytes(&rab));
        self.phase = if matched { SmpPhase::Verified } else { SmpPhase::Failed };
        if !matched { self.lifecycle.record_failure(); }

        let wire = Self::encode_group_elems(&[&rb_b, &cr2, &d8]);
        self.feed_transcript(&wire);
        Ok(wire)
    }

    // ── SMP final ────────────────────────────────────────────────────────────
    pub fn process_smp4(&mut self, smp4_data: &[u8]) -> Result<bool> {
        self.guard()?;
        if self.phase != SmpPhase::AwaitingMsg4 {
            return Err(self.fail_and_zeroize(OtrError::Smp("SMP not awaiting SMP4")));
        }

        self.feed_transcript(smp4_data);

        let fields = Self::decode_group_elems(smp4_data, 3)
            .map_err(|e| self.fail_and_zeroize(e))?;
        let (rb, cr2, d8) = (&fields[0], &fields[1], &fields[2]);

        let qa = self.qa.as_ref().ok_or(OtrError::Smp("no Qa"))?.clone();
        let qb = self.qb.as_ref().ok_or(OtrError::Smp("no Qb"))?.clone();
        let pa = self.pa.as_ref().ok_or(OtrError::Smp("no Pa"))?.clone();
        let pb = self.pb.as_ref().ok_or(OtrError::Smp("no Pb"))?.clone();

        let qa_n   = num_bigint::BigUint::from_bytes_be(&qa);
        let qb_n   = num_bigint::BigUint::from_bytes_be(&qb);
        let pb_n   = num_bigint::BigUint::from_bytes_be(&pb);
        let pa_n   = num_bigint::BigUint::from_bytes_be(&pa);
        let base   = (qa_n * Self::mod_inv(&qb_n)) % &*SMP_PRIME;

        Self::verify_zkp_custom_base(8, cr2, d8, rb, &base)
            .map_err(|e| self.fail_and_zeroize(e))?;

        let pa_over_pb = (pa_n * Self::mod_inv(&pb_n)) % &*SMP_PRIME;
        let rb_n       = num_bigint::BigUint::from_bytes_be(rb);
        let rab        = rb_n.modpow(&num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME);

        let verified = crate::secure_mem::ct_eq(&Self::fe_bytes(&pa_over_pb), &Self::fe_bytes(&rab));
        self.phase = if verified { SmpPhase::Verified } else { SmpPhase::Failed };
        if !verified { self.lifecycle.record_failure(); }
        Ok(verified)
    }

    pub fn is_verified(&self)       -> bool    { self.phase == SmpPhase::Verified }
    pub fn is_failed(&self)         -> bool    { matches!(self.phase, SmpPhase::Failed | SmpPhase::Aborted) }
    pub fn get_phase(&self)         -> &'static str {
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
    pub fn check_secret_set(&self)  -> bool  { !self.secret.is_empty() }
    pub fn get_attempt_count(&self) -> u32   { self.lifecycle.attempt_count }
    pub fn get_elapsed_secs(&self)  -> u64   { self.lifecycle.created_at.elapsed().as_secs() }
    pub fn is_expired(&self)        -> bool  { self.lifecycle.created_at.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECS) }
}

// ── PyO3 bindings ─────────────────────────────────────────────────────────────
#[pyclass(name = "RustSMP")]
pub struct PySmp { inner: SmpState }

#[pymethods]
impl PySmp {
    #[new]
    fn new(is_initiator: bool) -> Self { Self { inner: SmpState::new(is_initiator) } }

    fn set_secret(&mut self, raw_secret: &[u8], session_id: &[u8], our_fp: &[u8], peer_fp: &[u8]) {
        self.inner.set_secret(raw_secret, session_id, our_fp, peer_fp);
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
            Some(bytes) => { self.inner.set_secret(bytes, session_id, our_fp, peer_fp); Ok(true) }
            None => Ok(false),
        }
    }

    fn generate_smp1<'py>(&mut self, py: Python<'py>, question: Option<String>) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.generate_smp1(question).map(|d| PyBytes::new_bound(py, &d)).map_err(PyErr::from)
    }

    fn process_smp1_generate_smp2<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp1_generate_smp2(data).map(|d| PyBytes::new_bound(py, &d)).map_err(PyErr::from)
    }

    fn process_smp2_generate_smp3<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp2_generate_smp3(data).map(|d| PyBytes::new_bound(py, &d)).map_err(PyErr::from)
    }

    fn process_smp3_generate_smp4<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.process_smp3_generate_smp4(data).map(|d| PyBytes::new_bound(py, &d)).map_err(PyErr::from)
    }

    fn process_smp4(&mut self, data: &[u8]) -> PyResult<bool> {
        self.inner.process_smp4(data).map_err(PyErr::from)
    }

    fn abort(&mut self)   { self.inner.destroy(); }
    fn destroy(&mut self) { self.inner.destroy(); }

    fn is_verified(&self)       -> bool  { self.inner.is_verified() }
    fn is_failed(&self)         -> bool  { self.inner.is_failed() }
    fn get_phase(&self)         -> &str  { self.inner.get_phase() }
    fn check_secret_set(&self)  -> bool  { self.inner.check_secret_set() }
    fn get_attempt_count(&self) -> u32   { self.inner.get_attempt_count() }
    fn get_elapsed_secs(&self)  -> u64   { self.inner.get_elapsed_secs() }
    fn is_expired(&self)        -> bool  { self.inner.is_expired() }
}
