#![cfg(feature = "pq-rust")]
// src/smp.rs — Socialist Millionaire Protocol (OTRv4 spec §5)
//
// All secret exponents are ZeroizeOnDrop. Modular arithmetic uses
// num‑bigint (with "rand" feature) and constant‑time comparisons.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::ZeroizeOnDrop;
use sha3::{Sha3_512, Digest};
use rand::rngs::OsRng;

use crate::error::{OtrError, Result};
use crate::secure_mem::SecretVec;

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

    static ref SMP_ORDER: num_bigint::BigUint = {
        (SMP_PRIME.clone() - 1u64) >> 1
    };

    static ref SMP_GEN: num_bigint::BigUint = num_bigint::BigUint::from(2u8);
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SmpPhase {
    Idle,
    AwaitingMsg2,
    AwaitingMsg3,
    AwaitingMsg4,
    Verified,
    Failed,
}

#[derive(ZeroizeOnDrop)]
pub struct SmpState {
    secret: SecretVec,
    a2: SecretVec, a3: SecretVec,
    r2: SecretVec, r3: SecretVec, r4: SecretVec, r5: SecretVec, r6: SecretVec,
    b2: SecretVec, b3: SecretVec,
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
}

impl SmpState {
    pub fn new(
        raw_secret:   &[u8],
        session_id:   &[u8],
        our_fp:       &[u8],
        peer_fp:      &[u8],
        is_initiator: bool,
        question:     Option<String>,
    ) -> Self {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
        let mut h = Shake256::default();
        h.update(raw_secret);
        h.update(session_id);
        if is_initiator { h.update(our_fp); h.update(peer_fp); }
        else            { h.update(peer_fp); h.update(our_fp); }
        let mut bound = vec![0u8; 64];
        h.finalize_xof().read(&mut bound);
        let empty = || SecretVec::new(vec![]);
        Self {
            secret: SecretVec::from_slice(&bound),
            a2: empty(), a3: empty(),
            r2: empty(), r3: empty(), r4: empty(), r5: empty(), r6: empty(),
            b2: empty(), b3: empty(),
            r2b: empty(), r3b: empty(), r4b: empty(), r5b: empty(), r6b: empty(),
            g2a: None, g3a: None, g2b: None, g3b: None, g3: None,
            pa: None, qa: None, pb: None, qb: None,
            phase: SmpPhase::Idle,
            is_initiator,
            question,
        }
    }

    fn random_exponent() -> SecretVec {
        use num_bigint::RandBigInt;
        let v = OsRng.gen_biguint_range(
            &num_bigint::BigUint::from(2u8),
            &*SMP_ORDER
        );
        SecretVec::from_slice(&v.to_bytes_be())
    }

    fn mod_exp(base: &num_bigint::BigUint, exp_bytes: &[u8], modulus: &num_bigint::BigUint) -> num_bigint::BigUint {
        let e = num_bigint::BigUint::from_bytes_be(exp_bytes);
        base.modpow(&e, modulus)
    }

    fn zkp_challenge(version: u8, gr_bytes: &[u8], statement: &[u8]) -> num_bigint::BigUint {
        let mut h = Sha3_512::new();
        h.update(&[version]);
        h.update(gr_bytes);
        h.update(statement);
        num_bigint::BigUint::from_bytes_be(&h.finalize()) % &*SMP_ORDER
    }

    fn compute_zkp(version: u8, r_bytes: &[u8], exp_bytes: &[u8], base_val_bytes: &[u8])
        -> (Vec<u8>, Vec<u8>)
    {
        let gr = Self::mod_exp(&SMP_GEN, r_bytes, &SMP_PRIME);
        let gr_bytes = gr.to_bytes_be();
        let c = Self::zkp_challenge(version, &gr_bytes, base_val_bytes);
        let r = num_bigint::BigUint::from_bytes_be(r_bytes);
        let e = num_bigint::BigUint::from_bytes_be(exp_bytes);
        let d = (r + &*SMP_ORDER - (c.clone() * e) % &*SMP_ORDER) % &*SMP_ORDER;
        (c.to_bytes_be(), d.to_bytes_be())
    }

    fn verify_zkp(version: u8, c_bytes: &[u8], d_bytes: &[u8], base_val: &[u8])
        -> Result<()>
    {
        let c  = num_bigint::BigUint::from_bytes_be(c_bytes);
        let gd = Self::mod_exp(&SMP_GEN, d_bytes, &SMP_PRIME);
        let bv = num_bigint::BigUint::from_bytes_be(base_val);
        let gc = bv.modpow(&c, &SMP_PRIME);
        let gr = (gd * gc) % &*SMP_PRIME;
        let c2 = Self::zkp_challenge(version, &gr.to_bytes_be(), base_val);
        if crate::secure_mem::ct_eq(&c.to_bytes_be(), &c2.to_bytes_be()) {
            Ok(())
        } else {
            Err(OtrError::Smp("ZKP verification failed"))
        }
    }

    // ── SMP1 (Alice initiates) ────────────────────────────────
    pub fn generate_smp1(&mut self) -> Result<Vec<u8>> {
        self.a2 = Self::random_exponent();
        self.a3 = Self::random_exponent();
        self.r2 = Self::random_exponent();
        self.r3 = Self::random_exponent();

        let g2a = Self::mod_exp(&SMP_GEN, self.a2.expose(), &SMP_PRIME);
        let g3a = Self::mod_exp(&SMP_GEN, self.a3.expose(), &SMP_PRIME);
        let g2a_b = g2a.to_bytes_be();
        let g3a_b = g3a.to_bytes_be();

        let (c2, d2) = Self::compute_zkp(1, self.r2.expose(), self.a2.expose(), &g2a_b);
        let (c3, d3) = Self::compute_zkp(2, self.r3.expose(), self.a3.expose(), &g3a_b);

        self.g2a = Some(g2a_b.clone());
        self.g3a = Some(g3a_b.clone());
        self.phase = SmpPhase::AwaitingMsg2;
        Ok(Self::encode_group_elems(&[&g2a_b, &c2, &d2, &g3a_b, &c3, &d3]))
    }

    // ── SMP2 (Bob responds) ───────────────────────────────────
    pub fn process_smp1_generate_smp2(&mut self, smp1_data: &[u8]) -> Result<Vec<u8>> {
        let fields = Self::decode_group_elems(smp1_data, 6)?;
        let (g2a, c2, d2, g3a, c3, d3) = (&fields[0], &fields[1], &fields[2],
                                            &fields[3], &fields[4], &fields[5]);
        Self::validate_group_elem(g2a)?;
        Self::validate_group_elem(g3a)?;
        Self::verify_zkp(1, c2, d2, g2a)?;
        Self::verify_zkp(2, c3, d3, g3a)?;

        self.b2  = Self::random_exponent();
        self.b3  = Self::random_exponent();
        self.r2b = Self::random_exponent();
        self.r3b = Self::random_exponent();
        self.r4b = Self::random_exponent();
        self.r5b = Self::random_exponent();
        self.r6b = Self::random_exponent();

        let g2b = Self::mod_exp(&SMP_GEN, self.b2.expose(), &SMP_PRIME);
        let g3b = Self::mod_exp(&SMP_GEN, self.b3.expose(), &SMP_PRIME);
        let g2b_b = g2b.to_bytes_be();
        let g3b_b = g3b.to_bytes_be();

        let (c2b, d2b) = Self::compute_zkp(3, self.r2b.expose(), self.b2.expose(), &g2b_b);
        let (c3b, d3b) = Self::compute_zkp(4, self.r3b.expose(), self.b3.expose(), &g3b_b);

        // g2 = g2a^b2, g3 = g3a^b3
        let g2a_big = num_bigint::BigUint::from_bytes_be(g2a);
        let g3a_big = num_bigint::BigUint::from_bytes_be(g3a);
        let g2 = g2a_big.modpow(&num_bigint::BigUint::from_bytes_be(self.b2.expose()), &*SMP_PRIME);
        let g3 = g3a_big.modpow(&num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME);

        // Pb = g3^r4b, Qb = g^r4b * g2^secret
        let pb = Self::mod_exp(&g3, self.r4b.expose(), &SMP_PRIME);
        let pb_b = pb.to_bytes_be();
        let qb = {
            let gr4b = Self::mod_exp(&SMP_GEN, self.r4b.expose(), &SMP_PRIME);
            let g2s  = g2.modpow(&num_bigint::BigUint::from_bytes_be(self.secret.expose()), &*SMP_PRIME);
            (gr4b * g2s % &*SMP_PRIME).to_bytes_be()
        };

        // ZKP for Pb/Qb
        let gr5b  = Self::mod_exp(&SMP_GEN, self.r5b.expose(), &SMP_PRIME);
        let g3r6b = Self::mod_exp(&g3,      self.r6b.expose(), &SMP_PRIME);
        let gr5b_b  = gr5b.to_bytes_be();
        let g3r6b_b = g3r6b.to_bytes_be();
        let mut cp_input = gr5b_b.clone();
        cp_input.extend_from_slice(&g3r6b_b);
        let cp_big = Self::zkp_challenge(5, &gr5b_b, &cp_input);

        let r5b_n = num_bigint::BigUint::from_bytes_be(self.r5b.expose());
        let r6b_n = num_bigint::BigUint::from_bytes_be(self.r6b.expose());
        let r4b_n = num_bigint::BigUint::from_bytes_be(self.r4b.expose());
        let sec_n = num_bigint::BigUint::from_bytes_be(self.secret.expose());
        let d5 = (r5b_n + &*SMP_ORDER - (cp_big.clone() * r4b_n) % &*SMP_ORDER) % &*SMP_ORDER;
        let d6 = (r6b_n + &*SMP_ORDER - (cp_big.clone() * sec_n) % &*SMP_ORDER) % &*SMP_ORDER;

        self.g2b = Some(g2b_b.clone());
        self.g3b = Some(g3b_b.clone());
        self.pb  = Some(pb_b.clone());
        self.qb  = Some(qb.clone());
        self.g3  = Some(g3.to_bytes_be());
        self.phase = SmpPhase::AwaitingMsg3;

        Ok(Self::encode_group_elems(&[
            &g2b_b, &c2b, &d2b, &g3b_b, &c3b, &d3b,
            &pb_b, &qb, &cp_big.to_bytes_be(), &d5.to_bytes_be(), &d6.to_bytes_be()
        ]))
    }

    // ── SMP3 (Alice processes SMP2, sends SMP3) ───────────────
    pub fn process_smp2_generate_smp3(&mut self, smp2_data: &[u8]) -> Result<Vec<u8>> {
        let fields = Self::decode_group_elems(smp2_data, 11)?;
        let (g2b, c2b, d2b, g3b, c3b, d3b, pb, qb, _cp, _d5, _d6) =
            (&fields[0], &fields[1], &fields[2], &fields[3], &fields[4],
             &fields[5], &fields[6], &fields[7], &fields[8], &fields[9], &fields[10]);

        Self::validate_group_elem(g2b)?;
        Self::validate_group_elem(g3b)?;
        Self::verify_zkp(3, c2b, d2b, g2b)?;
        Self::verify_zkp(4, c3b, d3b, g3b)?;

        self.r4 = Self::random_exponent();
        self.r5 = Self::random_exponent();
        self.r6 = Self::random_exponent();

        let g2b_big = num_bigint::BigUint::from_bytes_be(g2b);
        let g3b_big = num_bigint::BigUint::from_bytes_be(g3b);
        let g2 = g2b_big.modpow(&num_bigint::BigUint::from_bytes_be(self.a2.expose()), &*SMP_PRIME);
        let g3 = g3b_big.modpow(&num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME);

        let pa = Self::mod_exp(&g3, self.r4.expose(), &SMP_PRIME);
        let pa_b = pa.to_bytes_be();
        let qa = {
            let gr4 = Self::mod_exp(&SMP_GEN, self.r4.expose(), &SMP_PRIME);
            let g2s = g2.modpow(&num_bigint::BigUint::from_bytes_be(self.secret.expose()), &*SMP_PRIME);
            (gr4 * g2s % &*SMP_PRIME).to_bytes_be()
        };

        // Ra = (Qa/Qb)^a3
        let qa_big = num_bigint::BigUint::from_bytes_be(&qa);
        let qb_big = num_bigint::BigUint::from_bytes_be(qb);
        let qb_inv = qb_big.modpow(&(&*SMP_PRIME - 2u8), &*SMP_PRIME);
        let qa_over_qb = (qa_big * qb_inv) % &*SMP_PRIME;
        let ra = qa_over_qb.modpow(
            &num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME
        );
        let ra_b = ra.to_bytes_be();

        let (cr, d7) = Self::compute_zkp(7, self.r5.expose(), self.a3.expose(), &ra_b);

        self.pa = Some(pa_b.clone());
        self.qa = Some(qa.clone());
        self.qb = Some(qb.to_vec());
        self.pb = Some(pb.to_vec());
        self.g3 = Some(g3.to_bytes_be());
        self.phase = SmpPhase::AwaitingMsg4;

        Ok(Self::encode_group_elems(&[&pa_b, &qa, &cr, &d7]))
    }

    // ── SMP4 (Bob processes SMP3, sends SMP4) ────────────────
    pub fn process_smp3_generate_smp4(&mut self, smp3_data: &[u8]) -> Result<Vec<u8>> {
        let fields = Self::decode_group_elems(smp3_data, 4)?;
        let (pa, qa, _cr, _d7) = (&fields[0], &fields[1], &fields[2], &fields[3]);

        Self::validate_group_elem(pa)?;
        Self::validate_group_elem(qa)?;

        self.r6b = Self::random_exponent();

        let pb  = self.pb.as_ref().ok_or(OtrError::Smp("no Pb"))?;
        let qb  = self.qb.as_ref().ok_or(OtrError::Smp("no Qb"))?;

        let qa_big = num_bigint::BigUint::from_bytes_be(qa);
        let qb_big = num_bigint::BigUint::from_bytes_be(qb);
        let qb_inv = qb_big.modpow(&(&*SMP_PRIME - 2u8), &*SMP_PRIME);
        let qa_over_qb = (qa_big * qb_inv) % &*SMP_PRIME;
        let rb = qa_over_qb.modpow(
            &num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME
        );
        let rb_b = rb.to_bytes_be();

        // Verify Pa/Pb == Rab
        let pa_big = num_bigint::BigUint::from_bytes_be(pa);
        let pb_big = num_bigint::BigUint::from_bytes_be(pb);
        let pa_over_pb = pa_big * pb_big.modpow(&(&*SMP_PRIME - 2u8), &*SMP_PRIME) % &*SMP_PRIME;
        let rab = rb.modpow(
            &num_bigint::BigUint::from_bytes_be(self.b3.expose()), &*SMP_PRIME
        );

        let (cr2, d8) = Self::compute_zkp(8, self.r6b.expose(), self.b3.expose(), &rb_b);

        if crate::secure_mem::ct_eq(&pa_over_pb.to_bytes_be(), &rab.to_bytes_be()) {
            self.phase = SmpPhase::Verified;
        } else {
            self.phase = SmpPhase::Failed;
        }

        Ok(Self::encode_group_elems(&[&rb_b, &cr2, &d8]))
    }

    // ── SMP final (Alice verifies SMP4) ──────────────────────
    pub fn process_smp4(&mut self, smp4_data: &[u8]) -> Result<bool> {
        let fields = Self::decode_group_elems(smp4_data, 3)?;
        let (rb, _cr, _d8) = (&fields[0], &fields[1], &fields[2]);

        let pa = self.pa.as_ref().ok_or(OtrError::Smp("no Pa"))?;
        let pb = self.pb.as_ref().ok_or(OtrError::Smp("no Pb"))?;

        let pa_big = num_bigint::BigUint::from_bytes_be(pa);
        let pb_big = num_bigint::BigUint::from_bytes_be(pb);
        let pa_over_pb = pa_big * pb_big.modpow(&(&*SMP_PRIME - 2u8), &*SMP_PRIME) % &*SMP_PRIME;

        let rab = num_bigint::BigUint::from_bytes_be(rb).modpow(
            &num_bigint::BigUint::from_bytes_be(self.a3.expose()), &*SMP_PRIME
        );

        let verified = crate::secure_mem::ct_eq(&pa_over_pb.to_bytes_be(), &rab.to_bytes_be());
        self.phase = if verified { SmpPhase::Verified } else { SmpPhase::Failed };
        Ok(verified)
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
            let len = u32::from_be_bytes(data[off..off+4].try_into()
                .map_err(|_| OtrError::WireFormat)?) as usize;
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

    pub fn is_verified(&self) -> bool { self.phase == SmpPhase::Verified }
    pub fn is_failed(&self)   -> bool { self.phase == SmpPhase::Failed }
    pub fn get_phase(&self) -> &'static str {
        match self.phase {
            SmpPhase::Idle         => "IDLE",
            SmpPhase::AwaitingMsg2 => "AWAITING_MSG2",
            SmpPhase::AwaitingMsg3 => "AWAITING_MSG3",
            SmpPhase::AwaitingMsg4 => "AWAITING_MSG4",
            SmpPhase::Verified     => "VERIFIED",
            SmpPhase::Failed       => "FAILED",
        }
    }
}

// ── PyO3 bindings ────────────────────────────────────
#[pyclass(name = "RustSMP")]
pub struct PySmp { inner: SmpState }

#[pymethods]
impl PySmp {
    #[new]
    #[pyo3(signature = (raw_secret, session_id, our_fp, peer_fp, is_initiator, question=None))]
    fn new(
        raw_secret: &[u8], session_id: &[u8], our_fp: &[u8], peer_fp: &[u8],
        is_initiator: bool, question: Option<String>,
    ) -> Self {
        Self { inner: SmpState::new(raw_secret, session_id, our_fp, peer_fp, is_initiator, question) }
    }

    fn generate_smp1<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.generate_smp1().map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &data))
    }

    fn process_smp1_generate_smp2<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let resp = self.inner.process_smp1_generate_smp2(data).map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &resp))
    }

    fn process_smp2_generate_smp3<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let resp = self.inner.process_smp2_generate_smp3(data).map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &resp))
    }

    fn process_smp3_generate_smp4<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let resp = self.inner.process_smp3_generate_smp4(data).map_err(PyErr::from)?;
        Ok(PyBytes::new_bound(py, &resp))
    }

    fn process_smp4(&mut self, data: &[u8]) -> PyResult<bool> {
        self.inner.process_smp4(data).map_err(PyErr::from)
    }

    fn abort(&mut self) { self.inner.phase = SmpPhase::Failed; }
    fn is_verified(&self) -> bool { self.inner.is_verified() }
    fn get_phase(&self) -> &str { self.inner.get_phase() }
}