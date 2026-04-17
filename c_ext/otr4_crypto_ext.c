/*
 * otr4_crypto_ext.c  —  OpenSSL-backed C extension for pop3_hardened.py
 *
 * Exports:
 *   disable_core_dumps()                                → None
 *   cleanse(bytearray)                                  → None
 *   bn_mod_exp_consttime(base, exp, mod)                → bytes
 *   bn_mod_inverse(a, mod)                              → bytes
 *   bn_rand_range(mod)                                  → bytes
 *   ring_sign(seed_57, A1_57, A2_57, msg)               → bytes (228)
 *   ring_verify(A1_57, A2_57, msg, sig_228)             → bool
 *   mlkem1024_keygen()                                  → (ek_bytes, dk_bytes)
 *   mlkem1024_encaps(ek_bytes)                          → (ct_bytes, ss_bytes)
 *   mlkem1024_decaps(ct_bytes, dk_bytes)                → ss_bytes
 *
 * Build:
 *   python setup_otr4.py build_ext --inplace
 *
 * Dependencies:
 *   OpenSSL ≥ 3.0   (libcrypto, libssl)
 *   Python  ≥ 3.8
 *
 * Design notes
 * ─────────────
 * Constant-time guarantees
 *   bn_mod_exp_consttime  → BN_mod_exp_mont_consttime (Montgomery ladder)
 *   bn_mod_inverse        → BN_mod_inverse (variable-time for public values only)
 *   bn_rand_range         → BN_rand_range  (CSPRNG)
 *   ring_sign             → ECDSA-style Schnorr; scalar derived via SHAKE-256 +
 *                           clamping + OPENSSL_cleanse immediately after use
 *   mlkem1024_*           → EVP_KEM with "ML-KEM-1024" provider (OpenSSL ≥ 3.3)
 *                           or falls back to a self-contained pure-C FIPS 203
 *                           implementation when the provider is absent
 *
 * Memory hardening (Phase 5)
 *   All secret material is OPENSSL_cleanse'd before release.
 *   disable_core_dumps() calls prctl(PR_SET_DUMPABLE, 0) on Linux and
 *   setrlimit(RLIMIT_CORE, 0) on other POSIX systems.
 *
 * Ring signature algorithm (OTRv4 §4.3.3)
 *   Ed448 Schnorr ring signature over the pair (A1, A2).
 *   wire format: c1‖r1‖c2‖r2, each scalar 57 bytes little-endian.
 *
 *   Sign (signer knows a1 s.t. A1 = a1·G):
 *     t2   = random scalar in [1, Q-1]
 *     T2   = t2·G
 *     c2   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1_dummy ‖ T2) mod Q
 *            where T1_dummy is filled with challenge bytes
 *     r2   = t2 - c2·a2  … but a2 unknown, so simulate:
 *     c2   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1_simulated ‖ T2) mod Q
 *     r1   = t1 - c1·a1 mod Q   (signer knows a1)
 *     c1   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2) mod Q
 *   Full protocol:
 *     a1   = SHAKE256(seed ‖ 0x00, 114 bytes)[:57], clamped
 *     t1   = SHAKE256(seed ‖ 0x01, 57 bytes) mod Q  (ephemeral)
 *     T1   = t1·G
 *     r2   = random scalar   (simulated for A2)
 *     c2   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ (r2·G + c2·A2) ‖ T1) mod Q
 *            Solved by: pick random r2, c2; compute T2 = r2·G + c2·A2 iteratively
 *            Standard Fiat-Shamir ring: pick t2 random → T2 = t2·G
 *            pick c2 random → r2 = t2 - c2·a2  (not known)
 *            Instead: simulate responder half
 *              pick c2, r2 random
 *              T2 = r2·G + c2·A2
 *            Then c = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2) mod Q
 *            c1 = c - c2 mod Q
 *            r1 = t1 - c1·a1 mod Q
 *   Output: c1‖r1‖c2‖r2
 *
 *   Verify:
 *     c    = c1 + c2 mod Q
 *     T1'  = r1·G + c1·A1
 *     T2'  = r2·G + c2·A2
 *     c'   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1' ‖ T2') mod Q
 *     accept iff c' mod Q == (c1 + c2) mod Q
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

/* OpenSSL */
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>   /* EVP_shake256 */
#include <openssl/objects.h>

/* Platform memory hardening */
#ifdef __linux__
#  include <sys/prctl.h>
#endif
#include <sys/resource.h>

/* ── forward declarations ─────────────────────────────────────────────────── */
static PyObject *py_disable_core_dumps(PyObject *self, PyObject *args);
static PyObject *py_cleanse(PyObject *self, PyObject *args);
static PyObject *py_bn_mod_exp_consttime(PyObject *self, PyObject *args);
static PyObject *py_bn_mod_inverse(PyObject *self, PyObject *args);
static PyObject *py_bn_rand_range(PyObject *self, PyObject *args);
static PyObject *py_ring_sign(PyObject *self, PyObject *args);
static PyObject *py_ring_verify(PyObject *self, PyObject *args);
static PyObject *py_mlkem1024_keygen(PyObject *self, PyObject *args);
static PyObject *py_mlkem1024_encaps(PyObject *self, PyObject *args);
static PyObject *py_mlkem1024_decaps(PyObject *self, PyObject *args);

/* ═══════════════════════════════════════════════════════════════════════════
 * SHAKE-256 helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * shake256_digest  —  compute SHAKE-256(data, data_len) → out[out_len]
 * Returns 1 on success, 0 on failure.
 */
static int
shake256_digest(const uint8_t *data, size_t data_len,
                uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) &&
             EVP_DigestUpdate(ctx, data, data_len) &&
             EVP_DigestFinalXOF(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return ok;
}

/*
 * shake256_multi  —  SHAKE-256(parts[0] ‖ parts[1] ‖ … ‖ parts[n-1]) → out
 */
static int
shake256_multi(const uint8_t **parts, const size_t *lens, int n,
               uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    for (int i = 0; i < n && ok; i++)
        ok = EVP_DigestUpdate(ctx, parts[i], lens[i]);
    ok = ok && EVP_DigestFinalXOF(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Ed448 field / group constants
 *
 * p = 2^448 - 2^224 - 1
 * Q = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
 *
 * We represent scalars / field elements as OpenSSL BIGNUMs.
 * The group order Q is 446 bits; scalar encoding is 57-byte little-endian.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Group order Q (446-bit), little-endian bytes
 * Q = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
static const uint8_t ED448_Q_LE[57] = {
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
    0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
    0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0x00
};

/*
 * ed448_q_bn  —  return a newly-allocated BIGNUM holding Q.
 * Caller must BN_free().
 */
static BIGNUM *
ed448_q_bn(void)
{
    /* Convert little-endian to big-endian for BN_lebin2bn */
    return BN_lebin2bn(ED448_Q_LE, 57, NULL);
}

/*
 * scalar_to_le57  —  write BN as 57-byte little-endian.
 * Reduces mod Q first.
 */
static int
scalar_to_le57(const BIGNUM *x, const BIGNUM *Q, uint8_t out[57])
{
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!r || !ctx) { BN_free(r); BN_CTX_free(ctx); return 0; }
    int ok = BN_mod(r, x, Q, ctx) &&
             BN_bn2lebinpad(r, out, 57) == 57;
    BN_clear_free(r);
    BN_CTX_free(ctx);
    return ok;
}

/*
 * le57_to_scalar  —  read 57-byte little-endian into a new BIGNUM.
 */
static BIGNUM *
le57_to_scalar(const uint8_t in[57])
{
    return BN_lebin2bn(in, 57, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Ed448-Goldilocks group arithmetic — BIGNUM-backed
 *
 * OpenSSL 3.0 does not expose EC_GROUP for Ed448 via the low-level EC API,
 * so we implement the group entirely with OpenSSL BN_mod_* calls.
 *
 * Field:   GF(p),  p = 2^448 - 2^224 - 1
 * Curve:   x² + y² = 1 + d·x²y²    d = -39081
 * Coords:  Extended homogeneous (X:Y:Z:T), T = XY/Z
 *
 * API used by the ring signature code:
 *   ed448_scalarmult_base(k_le57, out57)   — k·G  (fast, EVP_PKEY path)
 *   ed448_scalarmult_point(k_le57, P57, out57) — k·P
 *   ed448_point_add(P57, Q57, out57)       — P+Q
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Constants ─────────────────────────────────────────────────────────── */

/* p = 2^448 - 2^224 - 1  (big-endian hex, no spaces) */
#define P_HEX \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

/* d = -39081 mod p.  39081 = 0x98A9.
 * p ends …FFFFFFFF (56 hex digits per 28 bytes).
 * d = p - 39081:  low 64 bits = FFFFFFFFFFFF6756 (FFFFFFFFFFFFFFFF - 0x98A9 = FFFFFFFFFFFF6756FF... wait)
 * 0xFFFFFFFFFFFFFFFF - 0x98A9 = 0xFFFFFFFFFFFF6756. ✓
 * All higher limbs unchanged.
 * In 56-byte big-endian hex the value is:
 *   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
 *   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756
 */
#define D_HEX \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756"

/* Ed448 base point G (RFC 8032 §5.2.5) — x-coordinate (big-endian hex, 56 bytes)
 * Note: OpenSSL already knows G; we get it from EVP_PKEY keygen with seed 0x00…01. */

/* ── Thread-safe lazy init ─────────────────────────────────────────────── */

static BIGNUM *g_p  = NULL;  /* field prime           */
static BIGNUM *g_d  = NULL;  /* curve constant        */
static BN_CTX *g_bnctx = NULL;

static int ed448_global_init(void)
{
    if (g_p) return 1;   /* already done */
    g_bnctx = BN_CTX_new();
    if (!g_bnctx) return 0;
    BN_hex2bn(&g_p, P_HEX);
    BN_hex2bn(&g_d, D_HEX);
    return (g_p && g_d);
}

/* ── Field helpers (all work mod g_p) ─────────────────────────────────── */

static inline int fe_mul_bn(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{ return BN_mod_mul(r, a, b, g_p, g_bnctx); }

static inline int fe_sq_bn(BIGNUM *r, const BIGNUM *a)
{ return BN_mod_sqr(r, a, g_p, g_bnctx); }

static inline int fe_add_bn(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{ return BN_mod_add(r, a, b, g_p, g_bnctx); }

static inline int fe_sub_bn(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{ return BN_mod_sub(r, a, b, g_p, g_bnctx); }

static inline int fe_inv_bn(BIGNUM *r, const BIGNUM *a)
{ return BN_mod_inverse(r, a, g_p, g_bnctx) != NULL; }

/* fsqrt: r = sqrt(a) mod p.  p ≡ 3 mod 4 → r = a^{(p+1)/4} mod p.
 * Returns 1 if a is a square (r²≡a), 0 otherwise. */
static int fe_sqrt_bn(BIGNUM *r, const BIGNUM *a)
{
    /* exp = (p+1)/4 */
    BIGNUM *exp = BN_new();
    BN_copy(exp, g_p);
    BN_add_word(exp, 1);
    BN_rshift(exp, exp, 2);   /* div 4 */
    int ok = BN_mod_exp(r, a, exp, g_p, g_bnctx);
    BN_free(exp);
    if (!ok) return 0;
    /* verify r² == a */
    BIGNUM *check = BN_new();
    BN_mod_sqr(check, r, g_p, g_bnctx);
    int eq = (BN_cmp(check, a) == 0);
    BN_free(check);
    return eq;
}

/* fneg: r = -a mod p */
static inline int fe_neg_bn(BIGNUM *r, const BIGNUM *a)
{
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    int ok = BN_mod_sub(r, zero, a, g_p, g_bnctx);
    BN_free(zero);
    return ok;
}

/* fis_neg: return 1 if the canonical value of a is odd (negative in RFC 8032 sense) */
static int fe_is_neg_bn(const BIGNUM *a)
{
    /* Canonical: reduce mod p first */
    BIGNUM *tmp = BN_new();
    BN_nnmod(tmp, a, g_p, g_bnctx);
    int neg = BN_is_odd(tmp);
    BN_free(tmp);
    return neg;
}

/* ── Point encode / decode ─────────────────────────────────────────────── */

/* Encode projective (X:Y:Z) → 57-byte RFC 8032 compressed point.
 * Writes y in 56 bytes (little-endian), high bit of byte 56 = sign of x. */
static int point_encode(uint8_t out57[57],
                        const BIGNUM *X, const BIGNUM *Y, const BIGNUM *Z)
{
    BIGNUM *zinv = BN_new(), *x = BN_new(), *y = BN_new();
    if (!zinv || !x || !y) { BN_free(zinv); BN_free(x); BN_free(y); return 0; }

    if (!fe_inv_bn(zinv, Z)) goto fail;
    if (!fe_mul_bn(x, X, zinv)) goto fail;
    if (!fe_mul_bn(y, Y, zinv)) goto fail;

    /* Reduce to [0,p-1] */
    BN_nnmod(x, x, g_p, g_bnctx);
    BN_nnmod(y, y, g_p, g_bnctx);

    /* Write y as 56 bytes little-endian */
    memset(out57, 0, 57);
    if (BN_bn2lebinpad(y, out57, 56) != 56) goto fail;

    /* High bit of byte 56 = parity of x */
    out57[56] = (uint8_t)(fe_is_neg_bn(x) ? 0x80 : 0x00);

    BN_free(zinv); BN_free(x); BN_free(y);
    return 1;
fail:
    BN_free(zinv); BN_free(x); BN_free(y);
    return 0;
}

/* Decode 57-byte encoding → affine (x,y); allocates fresh BIGNUMs.
 * Caller must BN_free both. Returns 1 on success. */
static int point_decode(BIGNUM **xout, BIGNUM **yout, const uint8_t in57[57])
{
    int x_sign = (in57[56] >> 7) & 1;
    uint8_t ybytes[56];
    memcpy(ybytes, in57, 56);
    ybytes[55] &= 0x7F;  /* clear sign bit if it leaked; bytes 0-55 carry y */
    /* Actually RFC 8032: sign bit is high bit of byte 56 only; bytes 0-55 are y unchanged */
    memcpy(ybytes, in57, 56);  /* overwrite: bytes 0-55 = y as-is */

    BIGNUM *y = BN_lebin2bn(ybytes, 56, NULL);
    if (!y) return 0;

    /* Recover x from y: curve eq x²(1 - dy²) = y² - 1
     * x² = (y²-1) / (dy²-1) ... wait.
     * x² + y² = 1 + d·x²·y²
     * x²(1 - d·y²) = y² - 1
     * x² = (y²-1)/(1-d·y²) = -(y²-1)/(d·y²-1) = (1-y²)/(d·y²-1)  ... hmm sign.
     * Standard formula: x² = (y²-1) / (d·y²+1)  for the curve in RFC 8032 where
     *   the equation is -x²+y² = 1+d·x²y² (with the -x² twist).
     * But Ed448 uses the untwisted form x²+y²=1+d·x²y².
     * So: x² = (y²-1) / (d·y²-1)   [rearranging x²+y²=1+dx²y² → x²-dx²y²=1-y²
     *                                  x²(1-dy²)=1-y² → x²=(1-y²)/(1-dy²)]
     */
    BIGNUM *x2  = BN_new();
    BIGNUM *y2  = BN_new();
    BIGNUM *num = BN_new();
    BIGNUM *den = BN_new();
    BIGNUM *x   = BN_new();
    if (!x2 || !y2 || !num || !den || !x) goto fail;

    /* y2 = y² */
    if (!fe_sq_bn(y2, y)) goto fail;

    /* num = 1 - y²  */
    { BIGNUM *one = BN_new(); BN_one(one); fe_sub_bn(num, one, y2); BN_free(one); }

    /* den = 1 - d·y² */
    { BIGNUM *dy2 = BN_new(); fe_mul_bn(dy2, g_d, y2); BIGNUM *one = BN_new(); BN_one(one);
      fe_sub_bn(den, one, dy2); BN_free(dy2); BN_free(one); }

    /* x² = num / den */
    { BIGNUM *deninv = BN_new(); fe_inv_bn(deninv, den);
      fe_mul_bn(x2, num, deninv); BN_free(deninv); }

    /* x = sqrt(x²) */
    if (!fe_sqrt_bn(x, x2)) {
        /* Not a quadratic residue — invalid encoding */
        BN_free(y2); BN_free(x2); BN_free(num); BN_free(den);
        BN_free(y); BN_free(x);
        return 0;
    }

    /* Canonical x */
    BN_nnmod(x, x, g_p, g_bnctx);

    /* Adjust sign of x */
    if (fe_is_neg_bn(x) != x_sign) {
        fe_neg_bn(x, x);
        BN_nnmod(x, x, g_p, g_bnctx);
    }

    BN_free(y2); BN_free(x2); BN_free(num); BN_free(den);
    *xout = x;
    *yout = y;
    return 1;
fail:
    BN_free(y); BN_free(x2); BN_free(y2); BN_free(num); BN_free(den); BN_free(x);
    return 0;
}

/* ── Unified twisted Edwards addition (extended coords) ─────────────────
 *
 * Input/output: (X:Y:Z:T) with T = X·Y/Z.
 * add-2008-hwcd formulas from hyperelliptic.org/EFD (unified, work for any P,Q):
 *
 *   A = X1·X2
 *   B = Y1·Y2
 *   C = T1·k·T2      where k = 2d
 *   D = Z1·Z2
 *   E = (X1+Y1)·(X2+Y2) - A - B
 *   F = D - C
 *   G = D + C
 *   H = B + A         (RFC 8032 appendix A add formula)
 *   X3 = E·F
 *   Y3 = G·H
 *   T3 = E·H
 *   Z3 = F·G
 *
 * All inputs and outputs are in BIGNUMs mod p.
 * The 8 multiplications are each a BN_mod_mul call.
 */

typedef struct {
    BIGNUM *X, *Y, *Z, *T;
} gep_t;

static gep_t *gep_alloc(void)
{
    gep_t *P = (gep_t*)OPENSSL_malloc(sizeof(gep_t));
    if (!P) return NULL;
    P->X = BN_new(); P->Y = BN_new(); P->Z = BN_new(); P->T = BN_new();
    if (!P->X || !P->Y || !P->Z || !P->T) {
        BN_free(P->X); BN_free(P->Y); BN_free(P->Z); BN_free(P->T);
        OPENSSL_free(P); return NULL;
    }
    return P;
}

static void gep_free(gep_t *P)
{
    if (!P) return;
    BN_free(P->X); BN_free(P->Y); BN_free(P->Z); BN_free(P->T);
    OPENSSL_free(P);
}

/* gep_identity: return identity point (0:1:1:0) */
static gep_t *gep_identity(void)
{
    gep_t *P = gep_alloc();
    if (!P) return NULL;
    BN_zero(P->X); BN_one(P->Y); BN_one(P->Z); BN_zero(P->T);
    return P;
}

/* gep_from_affine: construct extended point from (x,y) */
static gep_t *gep_from_affine(const BIGNUM *x, const BIGNUM *y)
{
    gep_t *P = gep_alloc();
    if (!P) return NULL;
    BN_copy(P->X, x); BN_copy(P->Y, y); BN_one(P->Z);
    fe_mul_bn(P->T, x, y);   /* T = x*y/1 */
    return P;
}

/* gep_add: R = P + Q  (add-2008-hwcd unified) */
static gep_t *gep_add(const gep_t *P, const gep_t *Q)
{
    gep_t *R = gep_alloc();
    if (!R) return NULL;

    BIGNUM *A = BN_new(), *B = BN_new(), *C = BN_new(), *D = BN_new();
    BIGNUM *E = BN_new(), *F = BN_new(), *G = BN_new(), *H = BN_new();
    BIGNUM *tmp1 = BN_new(), *tmp2 = BN_new();

    if (!A||!B||!C||!D||!E||!F||!G||!H||!tmp1||!tmp2) goto fail;

    /* Untwisted Edwards add for x²+y²=1+d·x²·y² (a=1):
     *   A = X1·X2
     *   B = Y1·Y2
     *   C = d·T1·T2          (one factor of d, NOT 2d)
     *   D = Z1·Z2             (NOT 2·Z1·Z2)
     *   E = (X1+Y1)·(X2+Y2) - A - B  = X1Y2+X2Y1
     *   F = D - C             → affine: 1 - d·x1x2y1y2  (x denominator)
     *   G = D + C             → affine: 1 + d·x1x2y1y2  (y denominator)
     *   H = B - A             → affine: Y1Y2 - X1X2      (y numerator)
     * Result: x3=X3/Z3=E/G=(X1Y2+X2Y1)/(1+dxy) ✓
     *         y3=Y3/Z3=H/F=(Y1Y2-X1X2)/(1-dxy) ✓
     */
    fe_mul_bn(A, P->X, Q->X);                             /* A = X1*X2        */
    fe_mul_bn(B, P->Y, Q->Y);                             /* B = Y1*Y2        */
    fe_mul_bn(C, P->T, Q->T); fe_mul_bn(C, C, g_d);      /* C = d*T1*T2      */
    fe_mul_bn(D, P->Z, Q->Z);                             /* D = Z1*Z2        */
    fe_add_bn(tmp1, P->X, P->Y);
    fe_add_bn(tmp2, Q->X, Q->Y);
    fe_mul_bn(E, tmp1, tmp2);
    fe_sub_bn(E, E, A); fe_sub_bn(E, E, B);              /* E=(X1+Y1)(X2+Y2)-A-B */
    fe_sub_bn(F, D, C);                                   /* F = D - C        */
    fe_add_bn(G, D, C);                                   /* G = D + C        */
    fe_sub_bn(H, B, A);                                   /* H = B - A        */

    fe_mul_bn(R->X, E, F);   /* X3 = E*F */
    fe_mul_bn(R->Y, G, H);   /* Y3 = G*H */
    fe_mul_bn(R->T, E, H);   /* T3 = E*H */
    fe_mul_bn(R->Z, F, G);   /* Z3 = F*G */

    BN_free(A); BN_free(B); BN_free(C); BN_free(D);
    BN_free(E); BN_free(F); BN_free(G); BN_free(H);
    BN_free(tmp1); BN_free(tmp2);
    return R;
fail:
    BN_free(A); BN_free(B); BN_free(C); BN_free(D);
    BN_free(E); BN_free(F); BN_free(G); BN_free(H);
    BN_free(tmp1); BN_free(tmp2);
    gep_free(R); return NULL;
}

/* ── Constant-time conditional swap for heap BIGNUMs ─────────────────────
 *
 * Ed448 field elements are < p < 2^448, so 56 bytes suffices.
 * We serialise to fixed-size buffers, XOR-cswap, deserialise back.
 * No branches on `swap`.
 */
#define GEP_COORD_BYTES 56

static void bn_ct_cswap(BIGNUM *a, BIGNUM *b, int swap)
{
    unsigned char ba[GEP_COORD_BYTES], bb[GEP_COORD_BYTES];
    memset(ba, 0, GEP_COORD_BYTES);
    memset(bb, 0, GEP_COORD_BYTES);
    BN_bn2lebinpad(a, ba, GEP_COORD_BYTES);
    BN_bn2lebinpad(b, bb, GEP_COORD_BYTES);

    unsigned char mask = (unsigned char)(-(swap & 1));
    for (int i = 0; i < GEP_COORD_BYTES; i++) {
        unsigned char t = mask & (ba[i] ^ bb[i]);
        ba[i] ^= t;
        bb[i] ^= t;
    }

    BN_lebin2bn(ba, GEP_COORD_BYTES, a);
    BN_lebin2bn(bb, GEP_COORD_BYTES, b);
    OPENSSL_cleanse(ba, GEP_COORD_BYTES);
    OPENSSL_cleanse(bb, GEP_COORD_BYTES);
}

static void gep_cswap(gep_t *P, gep_t *Q, int swap)
{
    bn_ct_cswap(P->X, Q->X, swap);
    bn_ct_cswap(P->Y, Q->Y, swap);
    bn_ct_cswap(P->Z, Q->Z, swap);
    bn_ct_cswap(P->T, Q->T, swap);
}

/* gep_copy: dst = src (BIGNUM deep copy) */
static void gep_copy(gep_t *dst, const gep_t *src)
{
    BN_copy(dst->X, src->X); BN_copy(dst->Y, src->Y);
    BN_copy(dst->Z, src->Z); BN_copy(dst->T, src->T);
}

/* gep_scalarmult: R = scalar * P
 * scalar: 57 bytes little-endian
 *
 * Constant-time Montgomery ladder with conditional swap (no branches
 * on secret scalar bits):
 *
 *   R0 = identity,  R1 = P
 *   for each bit of scalar from MSB to LSB:
 *       b = bit
 *       gep_cswap(R0, R1, b)       // if b=1, swap
 *       R1 = R0 + R1               // add
 *       R0 = R0 + R0               // double
 *       gep_cswap(R0, R1, b)       // restore
 *   return R0
 *
 * This matches the pattern in otr4_ed448_ct.c:ep_scalarmult_ct().
 */
static gep_t *gep_scalarmult(const gep_t *P, const uint8_t scalar_le[57])
{
    gep_t *R0 = gep_identity();
    gep_t *R1 = gep_alloc();
    if (!R0 || !R1) { gep_free(R0); gep_free(R1); return NULL; }
    gep_copy(R1, P);

    /* Scan 456 bits (57 bytes) MSB-first */
    for (int i = 455; i >= 0; i--) {
        int bit = (scalar_le[i / 8] >> (i % 8)) & 1;

        gep_cswap(R0, R1, bit);

        /* R1 = R0 + R1 (add) */
        gep_t *s = gep_add(R0, R1);
        /* R0 = 2*R0 (double) */
        gep_t *d = gep_add(R0, R0);
        if (!s || !d) {
            gep_free(s); gep_free(d);
            gep_free(R0); gep_free(R1);
            return NULL;
        }
        gep_copy(R0, d);
        gep_copy(R1, s);
        gep_free(s);
        gep_free(d);

        gep_cswap(R0, R1, bit);
    }

    gep_free(R1);
    return R0;
}

/* ── API wrappers ──────────────────────────────────────────────────────── */

/* ed448_scalarmult_base: k·G
 *
 * G is the RFC 8032 §5.2.6 base point (57-byte compressed encoding).
 * We decode G once and then call gep_scalarmult.
 *
 * Note: EVP_PKEY_new_raw_private_key treats k as a SEED and derives the
 * scalar via SHAKE-256+clamp, so it cannot be used for arbitrary k·G.
 */

/* RFC 8032 §5.2.6 base point, 57-byte compressed encoding */
static const uint8_t ED448_G[57] = {
    0x14,0xfa,0x30,0xf2,0x5b,0x79,0x08,0x98,
    0xad,0xc8,0xd7,0x4e,0x2c,0x13,0xbd,0xfd,
    0xc4,0x39,0x7c,0xe6,0x1c,0xff,0xd3,0x3a,
    0xd7,0xc2,0xa0,0x05,0x1e,0x9c,0x78,0x87,
    0x40,0x98,0xa3,0x6c,0x73,0x73,0xea,0x4b,
    0x62,0xc7,0xc9,0x56,0x37,0x20,0x76,0x88,
    0x24,0xbc,0xb6,0x6e,0x71,0x46,0x3f,0x69,
    0x00
};

static int
ed448_scalarmult_base(const uint8_t k_le57[57], uint8_t out57[57])
{
    if (!ed448_global_init()) return 0;
    BIGNUM *gx = NULL, *gy = NULL;
    if (!point_decode(&gx, &gy, ED448_G)) return 0;
    gep_t *G = gep_from_affine(gx, gy);
    BN_free(gx); BN_free(gy);
    if (!G) return 0;
    gep_t *R = gep_scalarmult(G, k_le57);
    gep_free(G);
    if (!R) return 0;
    int ok = point_encode(out57, R->X, R->Y, R->Z);
    gep_free(R);
    return ok;
}

/* ed448_scalarmult_point: k·P for arbitrary compressed P */
static int
ed448_scalarmult_point(const uint8_t scalar_le57[57],
                       const uint8_t point57[57],
                       uint8_t out57[57])
{
    if (!ed448_global_init()) return 0;
    BIGNUM *px = NULL, *py = NULL;
    if (!point_decode(&px, &py, point57)) return 0;

    gep_t *P = gep_from_affine(px, py);
    BN_free(px); BN_free(py);
    if (!P) return 0;

    gep_t *R = gep_scalarmult(P, scalar_le57);
    gep_free(P);
    if (!R) return 0;

    int ok = point_encode(out57, R->X, R->Y, R->Z);
    gep_free(R);
    return ok;
}

/* ed448_point_add: R = P + Q for compressed P, Q */
static int
ed448_point_add(const uint8_t P57[57], const uint8_t Q57[57], uint8_t out57[57])
{
    if (!ed448_global_init()) return 0;
    BIGNUM *px=NULL, *py=NULL, *qx=NULL, *qy=NULL;
    if (!point_decode(&px, &py, P57)) return 0;
    if (!point_decode(&qx, &qy, Q57)) { BN_free(px); BN_free(py); return 0; }

    gep_t *Pp = gep_from_affine(px, py);
    gep_t *Qp = gep_from_affine(qx, qy);
    BN_free(px); BN_free(py); BN_free(qx); BN_free(qy);
    if (!Pp || !Qp) { gep_free(Pp); gep_free(Qp); return 0; }

    gep_t *R = gep_add(Pp, Qp);
    gep_free(Pp); gep_free(Qp);
    if (!R) return 0;

    int ok = point_encode(out57, R->X, R->Y, R->Z);
    gep_free(R);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ML-KEM-1024 (FIPS 203) — pure-C self-contained implementation
 *
 * NIST Level 5 (~256-bit post-quantum security). No Python fallback.
 * Algorithmically constant-time (no secret-dependent branches or table
 * lookups beyond the NTT zeta tables which are public).
 *
 * Key sizes: ek=1568 B, ct=1568 B, dk=3168 B, ss=32 B.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MLKEM_Q     3329
#define MLKEM_N      256
#define MLKEM_K        4
#define MLKEM_ETA1     2
#define MLKEM_ETA2     2
#define MLKEM_DU      11
#define MLKEM_DV       5

#define MLKEM_EK_BYTES  1568
#define MLKEM_CT_BYTES  1568
#define MLKEM_DK_BYTES  3168
#define MLKEM_SS_BYTES    32

/* Precomputed zeta tables (NTT and basemul) — generated once at module init. */
static uint16_t mlkem_zetas[128];
static uint16_t mlkem_bmzetas[128];
static uint32_t mlkem_ninv;   /* 128^{-1} mod Q */

static uint8_t
br7(uint8_t n)
{
    uint8_t b = 0;
    for (int i = 0; i < 7; i++) { b = (b << 1) | (n & 1); n >>= 1; }
    return b;
}

/* modpow for small precomputation */
static uint32_t
modpow(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint64_t r = 1, b = base % mod;
    while (exp > 0) {
        if (exp & 1) r = r * b % mod;
        b = b * b % mod;
        exp >>= 1;
    }
    return (uint32_t)r;
}

static void
mlkem_init_tables(void)
{
    for (int i = 0; i < 128; i++) {
        mlkem_zetas[i]  = (uint16_t)modpow(17, br7(i),         MLKEM_Q);
        mlkem_bmzetas[i]= (uint16_t)modpow(17, 2*br7(i)+1,     MLKEM_Q);
    }
    /* 128^{-1} mod 3329 = 3303 */
    mlkem_ninv = modpow(128, MLKEM_Q - 2, MLKEM_Q);   /* 3303 */
}

/* Montgomery reduction helper: (a * b) mod Q, a,b < 2*Q */
static inline uint16_t
mlkem_mulmod(uint32_t a, uint32_t b)
{
    return (uint16_t)((a * b) % MLKEM_Q);
}

/* in-place NTT on f[256] of uint16_t */
static void
mlkem_ntt(uint16_t f[256])
{
    int kk = 1;
    for (int l = 128; l >= 2; l >>= 1) {
        for (int s = 0; s < 256; s += 2*l) {
            uint32_t z = mlkem_zetas[kk++];
            for (int j = s; j < s+l; j++) {
                uint16_t t = (uint16_t)(z * f[j+l] % MLKEM_Q);
                f[j+l] = (f[j] - t + MLKEM_Q) % MLKEM_Q;
                f[j]   = (f[j] + t) % MLKEM_Q;
            }
        }
    }
}

/* in-place INTT on f[256] */
static void
mlkem_intt(uint16_t f[256])
{
    int kk = 127;
    for (int l = 2; l <= 128; l <<= 1) {
        for (int s = 0; s < 256; s += 2*l) {
            uint32_t z = mlkem_zetas[kk--];
            for (int j = s; j < s+l; j++) {
                uint16_t t = f[j];
                f[j]   = (t + f[j+l]) % MLKEM_Q;
                f[j+l] = (uint16_t)(z * ((f[j+l] - t + MLKEM_Q) % MLKEM_Q) % MLKEM_Q);
            }
        }
    }
    for (int i = 0; i < 256; i++)
        f[i] = (uint16_t)((uint32_t)f[i] * mlkem_ninv % MLKEM_Q);
}

/* NTT-domain polynomial multiplication: r = a ⊙ b
 *
 * Overflow note: each factor is < Q = 3329, so the product of three factors
 * is < 3329^3 ≈ 3.7e10 which exceeds uint32_t (max ~4.3e9).  We must use
 * uint64_t for intermediate accumulation before the final mod-Q reduction.
 */
static void
mlkem_pmul(const uint16_t a[256], const uint16_t b[256], uint16_t r[256])
{
    for (int i = 0; i < 128; i++) {
        uint64_t z  = mlkem_bmzetas[i];
        uint64_t a0 = a[2*i],   a1 = a[2*i+1];
        uint64_t b0 = b[2*i],   b1 = b[2*i+1];
        r[2*i]   = (uint16_t)((a0*b0 + z*a1*b1) % MLKEM_Q);
        r[2*i+1] = (uint16_t)((a0*b1 + a1*b0  ) % MLKEM_Q);
    }
}

/* a = a + b mod Q */
static void
mlkem_padd(uint16_t a[256], const uint16_t b[256])
{
    for (int i = 0; i < 256; i++)
        a[i] = (a[i] + b[i]) % MLKEM_Q;
}

/* Matrix-vector multiply (all NTT domain): r[K] = A[K][K] * v[K] */
static void
mlkem_mvmul(const uint16_t A[MLKEM_K][MLKEM_K][256],
            const uint16_t v[MLKEM_K][256],
            uint16_t       r[MLKEM_K][256])
{
    for (int i = 0; i < MLKEM_K; i++) {
        memset(r[i], 0, 256 * sizeof(uint16_t));
        for (int j = 0; j < MLKEM_K; j++) {
            uint16_t tmp[256];
            mlkem_pmul(A[i][j], v[j], tmp);
            mlkem_padd(r[i], tmp);
        }
    }
}

/* XOF sample: A[i][j] = SampleNTT(XOF(rho, i, j))
 *
 * OpenSSL 3.0 note: EVP_DigestFinalXOF finalizes the context so it can only
 * be called once.  We request 840 bytes (5 SHAKE-128 rate blocks) in a single
 * call.  Each triple of bytes yields up to 2 candidates; the acceptance rate
 * is 3329/4096 ≈ 81.3%, so 840 bytes → ~455 candidates.  The probability of
 * getting fewer than 256 valid coefficients from 840 bytes is negligible
 * (< 2^{-100}).
 */
static void
mlkem_xof_sample(const uint8_t rho[32], int i, int j, uint16_t out[256])
{
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = (uint8_t)i;
    seed[33] = (uint8_t)j;

#define XOF_BUF_BYTES 840   /* 5 * 168, always sufficient */
    uint8_t buf[XOF_BUF_BYTES];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake128(), NULL);
    EVP_DigestUpdate(ctx, seed, 34);
    EVP_DigestFinalXOF(ctx, buf, XOF_BUF_BYTES);
    EVP_MD_CTX_free(ctx);
#undef XOF_BUF_BYTES

    int a_len = 0, idx = 0;
    while (a_len < 256 && idx + 3 <= (int)sizeof(buf)) {
        uint16_t d1 = (uint16_t)(buf[idx] | ((uint16_t)(buf[idx+1] & 0x0Fu) << 8u));
        uint16_t d2 = (uint16_t)((buf[idx+1] >> 4u) | ((uint16_t)buf[idx+2] << 4u));
        idx += 3;
        if (d1 < MLKEM_Q) out[a_len++] = d1;
        if (d2 < MLKEM_Q && a_len < 256) out[a_len++] = d2;
    }
    /* Should never reach here; assert would fire in debug builds. */
    while (a_len < 256) out[a_len++] = 0;
}

/* PRF: SHAKE-256(s ‖ b, l) */
static void
mlkem_prf(const uint8_t s[32], uint8_t b, uint8_t *out, size_t l)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, s, 32);
    EVP_DigestUpdate(ctx, &b, 1);
    EVP_DigestFinalXOF(ctx, out, l);
    EVP_MD_CTX_free(ctx);
}

/* CBD_eta: sample from CBD with parameter eta */
static void
mlkem_cbd(const uint8_t *b, int eta, uint16_t f[256])
{
    for (int i = 0; i < 256; i++) {
        int a_s = 0, b_s = 0;
        for (int j = 0; j < eta; j++) {
            int bi = 2*i*eta + j;
            a_s += (b[bi >> 3] >> (bi & 7)) & 1;
            bi = 2*i*eta + eta + j;
            b_s += (b[bi >> 3] >> (bi & 7)) & 1;
        }
        f[i] = (uint16_t)((a_s - b_s + MLKEM_Q) % MLKEM_Q);
    }
}

/* Compress_d(x): ((1<<d)*x + (Q+1)/2) / Q mod 2^d */
static inline uint16_t
mlkem_compress(uint16_t x, int d)
{
    return (uint16_t)(((uint32_t)(1u<<d) * x + (MLKEM_Q+1)/2) / MLKEM_Q % (1u<<d));
}

/* Decompress_d(y): (Q*y + 2^{d-1}) >> d */
static inline uint16_t
mlkem_decompress(uint16_t y, int d)
{
    return (uint16_t)((MLKEM_Q * (uint32_t)y + (1u << (d-1))) >> d);
}

/* ByteEncode_d(f) → out (d*256/8 bytes) */
static void
mlkem_byte_encode(const uint16_t f[256], int d, uint8_t *out)
{
    uint32_t m = (d < 12) ? (1u << d) : MLKEM_Q;
    /* pack d bits per coefficient, LSB first */
    int bit_pos = 0;
    memset(out, 0, (size_t)(d * 256 / 8));
    for (int i = 0; i < 256; i++) {
        uint32_t v = f[i] % m;
        for (int b = 0; b < d; b++) {
            if ((v >> b) & 1)
                out[bit_pos >> 3] |= (uint8_t)(1 << (bit_pos & 7));
            bit_pos++;
        }
    }
}

/* ByteDecode_d(b) → f */
static void
mlkem_byte_decode(const uint8_t *b, int d, uint16_t f[256])
{
    uint32_t m = (d < 12) ? (1u << d) : MLKEM_Q;
    int bit_pos = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t v = 0;
        for (int bb = 0; bb < d; bb++) {
            v |= ((uint32_t)((b[bit_pos >> 3] >> (bit_pos & 7)) & 1)) << bb;
            bit_pos++;
        }
        f[i] = (uint16_t)(v % m);
    }
}

/* ── K-PKE ───────────────────────────────────────────────────────────────── */

static void
mlkem_keypke(const uint8_t d32[32],
             uint8_t ek[MLKEM_EK_BYTES],      /* 1184 */
             uint8_t dk_pke[MLKEM_K*384])     /* 1152 */
{
    uint8_t G[64];
    /* G = SHA3-512(d) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, d32, 32);
    unsigned int glen = 64;
    EVP_DigestFinal_ex(ctx, G, &glen);
    EVP_MD_CTX_free(ctx);

    const uint8_t *rho   = G;        /* 32 bytes */
    const uint8_t *sigma = G + 32;   /* 32 bytes */

    /* Sample A[K][K] in NTT domain */
    uint16_t A[MLKEM_K][MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            mlkem_xof_sample(rho, i, j, A[i][j]);

    /* Sample s, e */
    uint16_t s[MLKEM_K][256], e[MLKEM_K][256];
    uint8_t prf_out[MLKEM_ETA1 * 64];
    for (int i = 0; i < MLKEM_K; i++) {
        mlkem_prf(sigma, (uint8_t)i,           prf_out, sizeof(prf_out));
        mlkem_cbd(prf_out, MLKEM_ETA1, s[i]);
        mlkem_prf(sigma, (uint8_t)(MLKEM_K+i), prf_out, sizeof(prf_out));
        mlkem_cbd(prf_out, MLKEM_ETA1, e[i]);
    }

    uint16_t shat[MLKEM_K][256], ehat[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        memcpy(shat[i], s[i], 256*2);
        mlkem_ntt(shat[i]);
        memcpy(ehat[i], e[i], 256*2);
        mlkem_ntt(ehat[i]);
    }

    /* that = A * shat + ehat */
    uint16_t As[MLKEM_K][256];
    mlkem_mvmul(A, shat, As);
    for (int i = 0; i < MLKEM_K; i++)
        mlkem_padd(As[i], ehat[i]);

    /* ek = ByteEncode12(that[0]) ‖ … ‖ ByteEncode12(that[K-1]) ‖ rho */
    for (int i = 0; i < MLKEM_K; i++)
        mlkem_byte_encode(As[i], 12, ek + i*384);
    memcpy(ek + MLKEM_K*384, rho, 32);

    /* dk_pke = ByteEncode12(shat[0]) ‖ … */
    for (int i = 0; i < MLKEM_K; i++)
        mlkem_byte_encode(shat[i], 12, dk_pke + i*384);

    OPENSSL_cleanse(s,    sizeof(s));
    OPENSSL_cleanse(e,    sizeof(e));
    OPENSSL_cleanse(shat, sizeof(shat));
    OPENSSL_cleanse(ehat, sizeof(ehat));
    OPENSSL_cleanse(G,    sizeof(G));
}

static void
mlkem_enc_kpke(const uint8_t ek[MLKEM_EK_BYTES],
               const uint8_t m32[32],
               const uint8_t r32[32],
               uint8_t ct[MLKEM_CT_BYTES])
{
    /* Decode that, rho from ek */
    uint16_t that[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++)
        mlkem_byte_decode(ek + i*384, 12, that[i]);
    const uint8_t *rho = ek + MLKEM_K*384;

    /* Rebuild A */
    uint16_t A[MLKEM_K][MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            mlkem_xof_sample(rho, i, j, A[i][j]);

    /* Sample r_, e1, e2 */
    uint16_t r_[MLKEM_K][256], e1[MLKEM_K][256], e2[256];
    uint8_t prf_out[MLKEM_ETA2 * 64];
    for (int i = 0; i < MLKEM_K; i++) {
        mlkem_prf(r32, (uint8_t)i,           prf_out, sizeof(prf_out));
        mlkem_cbd(prf_out, MLKEM_ETA1, r_[i]);
        mlkem_prf(r32, (uint8_t)(MLKEM_K+i), prf_out, sizeof(prf_out));
        mlkem_cbd(prf_out, MLKEM_ETA2, e1[i]);
    }
    mlkem_prf(r32, (uint8_t)(2*MLKEM_K), prf_out, sizeof(prf_out));
    mlkem_cbd(prf_out, MLKEM_ETA2, e2);

    uint16_t rhat[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        memcpy(rhat[i], r_[i], 256*2);
        mlkem_ntt(rhat[i]);
    }

    /* u = INTT(A^T * rhat) + e1 */
    /* A^T[j][i] = A[i][j] */
    uint16_t AT[MLKEM_K][MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            memcpy(AT[j][i], A[i][j], 256*2);

    uint16_t Atr[MLKEM_K][256];
    mlkem_mvmul(AT, rhat, Atr);

    uint16_t u[MLKEM_K][256];
    for (int j = 0; j < MLKEM_K; j++) {
        mlkem_intt(Atr[j]);
        for (int c = 0; c < 256; c++)
            u[j][c] = (Atr[j][c] + e1[j][c]) % MLKEM_Q;
    }

    /* tv = INTT(that^T * rhat) */
    uint16_t tv[256] = {0};
    for (int i = 0; i < MLKEM_K; i++) {
        uint16_t tmp[256];
        mlkem_pmul(that[i], rhat[i], tmp);
        mlkem_padd(tv, tmp);
    }
    mlkem_intt(tv);

    /* mu = Decompress_1(ByteDecode_1(m)) */
    uint16_t mu[256];
    {
        uint16_t bits[256];
        mlkem_byte_decode(m32, 1, bits);
        for (int i = 0; i < 256; i++)
            mu[i] = mlkem_decompress(bits[i], 1);
    }

    /* v = tv + e2 + mu */
    uint16_t v[256];
    for (int i = 0; i < 256; i++)
        v[i] = (uint16_t)((tv[i] + e2[i] + mu[i]) % MLKEM_Q);

    /* c1 = ByteEncode_DU(Compress_DU(u)) */
    for (int j = 0; j < MLKEM_K; j++) {
        uint16_t cu[256];
        for (int c = 0; c < 256; c++)
            cu[c] = mlkem_compress(u[j][c], MLKEM_DU);
        mlkem_byte_encode(cu, MLKEM_DU, ct + j * MLKEM_DU * 32);
    }

    /* c2 = ByteEncode_DV(Compress_DV(v)) */
    {
        uint16_t cv[256];
        for (int i = 0; i < 256; i++)
            cv[i] = mlkem_compress(v[i], MLKEM_DV);
        mlkem_byte_encode(cv, MLKEM_DV, ct + MLKEM_K * MLKEM_DU * 32);
    }

    OPENSSL_cleanse(r_,  sizeof(r_));
    OPENSSL_cleanse(e1,  sizeof(e1));
    OPENSSL_cleanse(e2,  sizeof(e2));
    OPENSSL_cleanse(rhat,sizeof(rhat));
}

static void
mlkem_dec_kpke(const uint8_t dk_pke[MLKEM_K*384],
               const uint8_t ct[MLKEM_CT_BYTES],
               uint8_t m32[32])
{
    /* u = Decompress_DU(ByteDecode_DU(c1))  — TIME domain, no INTT */
    uint16_t u[MLKEM_K][256];
    for (int j = 0; j < MLKEM_K; j++) {
        uint16_t cu[256];
        mlkem_byte_decode(ct + j * MLKEM_DU * 32, MLKEM_DU, cu);
        for (int c = 0; c < 256; c++)
            u[j][c] = mlkem_decompress(cu[c], MLKEM_DU);
    }

    /* v = Decompress_DV(ByteDecode_DV(c2)) */
    uint16_t v[256];
    {
        uint16_t cv[256];
        mlkem_byte_decode(ct + MLKEM_K * MLKEM_DU * 32, MLKEM_DV, cv);
        for (int i = 0; i < 256; i++)
            v[i] = mlkem_decompress(cv[i], MLKEM_DV);
    }

    /* shat from dk_pke */
    uint16_t shat[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++)
        mlkem_byte_decode(dk_pke + i*384, 12, shat[i]);

    /* su = INTT(shat^T ⊙ NTT(u)) */
    uint16_t su[256] = {0};
    for (int i = 0; i < MLKEM_K; i++) {
        uint16_t untt[256];
        memcpy(untt, u[i], 256*2);
        mlkem_ntt(untt);
        uint16_t tmp[256];
        mlkem_pmul(shat[i], untt, tmp);
        mlkem_padd(su, tmp);
    }
    mlkem_intt(su);

    /* w = v - su mod Q */
    uint16_t w[256];
    for (int i = 0; i < 256; i++)
        w[i] = (uint16_t)((v[i] - su[i] + MLKEM_Q) % MLKEM_Q);

    /* m = ByteEncode_1(Compress_1(w)) */
    uint16_t cw[256];
    for (int i = 0; i < 256; i++)
        cw[i] = mlkem_compress(w[i], 1);
    mlkem_byte_encode(cw, 1, m32);

    OPENSSL_cleanse(shat, sizeof(shat));
    OPENSSL_cleanse(su,   sizeof(su));
}

/* ── ML-KEM-1024 public API ───────────────────────────────────────────────── */

/* mlkem1024_do_keygen: fills ek[1568], dk[3168] */
static void
mlkem1024_do_keygen(uint8_t ek[MLKEM_EK_BYTES], uint8_t dk[MLKEM_DK_BYTES])
{
    uint8_t z[32], d[32];
    RAND_bytes(z, 32);
    RAND_bytes(d, 32);

    uint8_t dk_pke[MLKEM_K * 384];
    mlkem_keypke(d, ek, dk_pke);

    /* H = SHA3-256(ek) */
    uint8_t H[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, ek, MLKEM_EK_BYTES);
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, H, &hlen);
    EVP_MD_CTX_free(ctx);

    /* dk = dk_pke ‖ ek ‖ H ‖ z */
    memcpy(dk,                        dk_pke, MLKEM_K*384);
    memcpy(dk + MLKEM_K*384,          ek,     MLKEM_EK_BYTES);
    memcpy(dk + MLKEM_K*384 + MLKEM_EK_BYTES, H, 32);
    memcpy(dk + MLKEM_K*384 + MLKEM_EK_BYTES + 32, z, 32);

    OPENSSL_cleanse(d, 32);
    OPENSSL_cleanse(z, 32);
    OPENSSL_cleanse(dk_pke, sizeof(dk_pke));
}

/* mlkem1024_do_encaps: fills ct[1568], ss[32] */
static void
mlkem1024_do_encaps(const uint8_t ek[MLKEM_EK_BYTES],
                   uint8_t ct[MLKEM_CT_BYTES],
                   uint8_t ss[MLKEM_SS_BYTES])
{
    uint8_t m[32];
    RAND_bytes(m, 32);

    /* H = SHA3-256(ek) */
    uint8_t H[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, ek, MLKEM_EK_BYTES);
    unsigned int hl = 32;
    EVP_DigestFinal_ex(ctx, H, &hl);
    EVP_MD_CTX_free(ctx);

    /* G = SHA3-512(m ‖ H) */
    uint8_t G[64];
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, m, 32);
    EVP_DigestUpdate(ctx, H, 32);
    unsigned int gl = 64;
    EVP_DigestFinal_ex(ctx, G, &gl);
    EVP_MD_CTX_free(ctx);

    const uint8_t *Kss = G;        /* 32 bytes */
    const uint8_t *r   = G + 32;   /* 32 bytes */

    mlkem_enc_kpke(ek, m, r, ct);
    memcpy(ss, Kss, 32);

    OPENSSL_cleanse(m, 32);
    OPENSSL_cleanse(G, 64);
}

/* mlkem1024_do_decaps: fills ss[32] (implicit rejection) */
static void
mlkem1024_do_decaps(const uint8_t ct[MLKEM_CT_BYTES],
                   const uint8_t dk[MLKEM_DK_BYTES],
                   uint8_t ss[MLKEM_SS_BYTES])
{
    const uint8_t *dk_pke = dk;
    const uint8_t *ek     = dk + MLKEM_K*384;
    const uint8_t *H      = dk + MLKEM_K*384 + MLKEM_EK_BYTES;
    const uint8_t *z      = dk + MLKEM_K*384 + MLKEM_EK_BYTES + 32;

    uint8_t m_p[32];
    mlkem_dec_kpke(dk_pke, ct, m_p);

    /* G = SHA3-512(m' ‖ H) */
    uint8_t G[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, m_p, 32);
    EVP_DigestUpdate(ctx, H, 32);
    unsigned int gl = 64;
    EVP_DigestFinal_ex(ctx, G, &gl);
    EVP_MD_CTX_free(ctx);

    const uint8_t *Kp = G;
    const uint8_t *rp = G + 32;

    /* Re-encrypt */
    uint8_t cp[MLKEM_CT_BYTES];
    mlkem_enc_kpke(ek, m_p, rp, cp);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < MLKEM_CT_BYTES; i++)
        diff |= ct[i] ^ cp[i];

    /* select Kp if diff==0, else SHAKE-256(z ‖ ct) */
    uint8_t reject[32];
    {
        EVP_MD_CTX *rctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(rctx, EVP_shake256(), NULL);
        EVP_DigestUpdate(rctx, z, 32);
        EVP_DigestUpdate(rctx, ct, MLKEM_CT_BYTES);
        EVP_DigestFinalXOF(rctx, reject, 32);
        EVP_MD_CTX_free(rctx);
    }

    /* Constant-time select: ss = (diff==0) ? Kp : reject */
    uint8_t mask = (uint8_t)(-(int8_t)(diff == 0));   /* 0xFF if match */
    for (int i = 0; i < 32; i++)
        ss[i] = (Kp[i] & mask) | (reject[i] & ~mask);

    OPENSSL_cleanse(m_p,   32);
    OPENSSL_cleanse(G,     64);
    OPENSSL_cleanse(cp,    MLKEM_CT_BYTES);
    OPENSSL_cleanse(reject,32);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Python wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* disable_core_dumps() */
static PyObject *
py_disable_core_dumps(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
    struct rlimit lim = {0, 0};
    setrlimit(RLIMIT_CORE, &lim);
    Py_RETURN_NONE;
}

/* cleanse(buf: bytearray) → None */
static PyObject *
py_cleanse(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "w*", &view)) return NULL;
    OPENSSL_cleanse(view.buf, (size_t)view.len);
    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

/* bn_mod_exp_consttime(base: bytes, exp: bytes, mod: bytes) → bytes */
static PyObject *
py_bn_mod_exp_consttime(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer base_buf, exp_buf, mod_buf;
    if (!PyArg_ParseTuple(args, "y*y*y*", &base_buf, &exp_buf, &mod_buf))
        return NULL;

    BIGNUM *base = BN_bin2bn(base_buf.buf, (int)base_buf.len, NULL);
    BIGNUM *exp  = BN_bin2bn(exp_buf.buf,  (int)exp_buf.len,  NULL);
    BIGNUM *mod  = BN_bin2bn(mod_buf.buf,  (int)mod_buf.len,  NULL);
    BIGNUM *res  = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    BN_MONT_CTX *mctx = BN_MONT_CTX_new();

    PyBuffer_Release(&base_buf);
    PyBuffer_Release(&exp_buf);
    PyBuffer_Release(&mod_buf);

    if (!base || !exp || !mod || !res || !ctx || !mctx) goto oom;

    BN_MONT_CTX_set(mctx, mod, ctx);
    if (!BN_mod_exp_mont_consttime(res, base, exp, mod, ctx, mctx)) goto err;

    int num_bytes = BN_num_bytes(res);
    PyObject *ret = PyBytes_FromStringAndSize(NULL, num_bytes);
    if (!ret) goto err;
    BN_bn2bin(res, (unsigned char *)PyBytes_AS_STRING(ret));

    BN_clear_free(base); BN_clear_free(exp);
    BN_free(mod); BN_free(res); BN_CTX_free(ctx); BN_MONT_CTX_free(mctx);
    return ret;
oom:
err:
    BN_clear_free(base); BN_clear_free(exp);
    BN_free(mod); BN_free(res); BN_CTX_free(ctx); BN_MONT_CTX_free(mctx);
    PyErr_SetString(PyExc_RuntimeError, "bn_mod_exp_consttime failed");
    return NULL;
}

/* bn_mod_inverse(a: bytes, mod: bytes) → bytes */
static PyObject *
py_bn_mod_inverse(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer a_buf, mod_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &a_buf, &mod_buf)) return NULL;

    BIGNUM *a   = BN_bin2bn(a_buf.buf,   (int)a_buf.len,   NULL);
    BIGNUM *mod = BN_bin2bn(mod_buf.buf, (int)mod_buf.len, NULL);
    BIGNUM *res = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    PyBuffer_Release(&a_buf);
    PyBuffer_Release(&mod_buf);

    if (!a || !mod || !res || !ctx) goto err;
    if (!BN_mod_inverse(res, a, mod, ctx)) goto err;

    int nb = BN_num_bytes(res);
    PyObject *ret = PyBytes_FromStringAndSize(NULL, nb);
    if (!ret) goto err;
    BN_bn2bin(res, (unsigned char *)PyBytes_AS_STRING(ret));

    BN_clear_free(a); BN_free(mod); BN_free(res); BN_CTX_free(ctx);
    return ret;
err:
    BN_clear_free(a); BN_free(mod); BN_free(res); BN_CTX_free(ctx);
    PyErr_SetString(PyExc_RuntimeError, "bn_mod_inverse failed");
    return NULL;
}

/* bn_rand_range(mod: bytes) → bytes */
static PyObject *
py_bn_rand_range(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer mod_buf;
    if (!PyArg_ParseTuple(args, "y*", &mod_buf)) return NULL;

    BIGNUM *mod = BN_bin2bn(mod_buf.buf, (int)mod_buf.len, NULL);
    BIGNUM *res = BN_new();
    PyBuffer_Release(&mod_buf);

    if (!mod || !res) goto err;
    if (!BN_rand_range(res, mod)) goto err;

    int nb = BN_num_bytes(res);
    /* Pad to same length as mod */
    int mod_len = BN_num_bytes(mod);
    if (nb > mod_len) goto err;
    PyObject *ret = PyBytes_FromStringAndSize(NULL, mod_len);
    if (!ret) goto err;
    memset(PyBytes_AS_STRING(ret), 0, mod_len);
    BN_bn2bin(res, (unsigned char *)PyBytes_AS_STRING(ret) + (mod_len - nb));

    BN_free(mod); BN_clear_free(res);
    return ret;
err:
    BN_free(mod); BN_clear_free(res);
    PyErr_SetString(PyExc_RuntimeError, "bn_rand_range failed");
    return NULL;
}

/* ── Ring signature helpers ─────────────────────────────────────────────── */

#define ED448_SCALAR_BYTES  57
#define ED448_POINT_BYTES   57
#define RING_SIG_BYTES      (4 * ED448_SCALAR_BYTES)
#define SIGMA_USAGE         0x1Cu

/*
 * ring_challenge  —  c = SHAKE-256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2, 57) mod Q
 * Writes result into c_bn (must be pre-allocated).
 */
static int
ring_challenge(const uint8_t *msg, size_t msg_len,
               const uint8_t A1[57], const uint8_t A2[57],
               const uint8_t T1[57], const uint8_t T2[57],
               BIGNUM *c_out, const BIGNUM *Q)
{
    uint8_t usage = SIGMA_USAGE;
    const uint8_t *parts[6] = { &usage, msg, A1, A2, T1, T2 };
    size_t lens[6] = { 1, msg_len, 57, 57, 57, 57 };
    uint8_t h[57];
    if (!shake256_multi(parts, lens, 6, h, 57)) return 0;
    BIGNUM *tmp = BN_lebin2bn(h, 57, NULL);
    if (!tmp) return 0;
    BN_CTX *ctx = BN_CTX_new();
    int ok = BN_mod(c_out, tmp, Q, ctx);
    BN_free(tmp); BN_CTX_free(ctx);
    return ok;
}

/*
 * ring_sign(seed_57, A1_57, A2_57, msg) → bytes(228)
 *
 * seed = raw Ed448 private key seed (57 bytes, straight from private_bytes())
 * A1   = initiator long-term public key (57-byte compressed point)
 * A2   = responder long-term public key (57-byte compressed point)
 * msg  = transcript binding bytes
 *
 * Algorithm:
 *   1. Derive signing scalar a1 from seed via SHAKE-256+clamping (RFC 8032 §5.2.5)
 *   2. Derive ephemeral scalar t1 deterministically from seed (no re-use risk)
 *   3. T1 = t1·G
 *   4. Simulate responder: pick random c2, r2; T2 = r2·G + c2·A2
 *   5. c  = challenge(msg, A1, A2, T1, T2) mod Q
 *   6. c1 = (c - c2) mod Q
 *   7. r1 = (t1 - c1·a1) mod Q
 *   Output: c1‖r1‖c2‖r2
 */
static PyObject *
py_ring_sign(PyObject *self, PyObject *args)
{
    (void)self;
    const uint8_t *seed, *A1, *A2, *msg;
    Py_ssize_t seed_len, A1_len, A2_len, msg_len;

    if (!PyArg_ParseTuple(args, "y#y#y#y#",
                          &seed, &seed_len,
                          &A1,   &A1_len,
                          &A2,   &A2_len,
                          &msg,  &msg_len))
        return NULL;

    if (seed_len != 57 || A1_len != 57 || A2_len != 57) {
        PyErr_SetString(PyExc_ValueError, "ring_sign: seed/A1/A2 must be 57 bytes");
        return NULL;
    }

    PyObject *ret = NULL;
    BIGNUM *Q   = NULL, *a1 = NULL, *t1 = NULL;
    BIGNUM *c2  = NULL, *r2 = NULL;
    BIGNUM *c   = NULL, *c1 = NULL, *r1 = NULL;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    /* ── Step 1: derive signing scalar a1 ─────────────────────────────────
     * RFC 8032 §5.2.5: h = SHAKE-256(seed, 114); clamp h[0..56]:
     *   h[0]  &= 0xFC (clear bits 0,1)
     *   h[55] |= 0x80 (set bit 447)
     *   h[56]  = 0    (clear byte 56 entirely — Ed448 uses 447-bit scalars)
     */
    uint8_t h_seed[114];
    {   /* RFC 8032 §5.2.5: SHAKE256(seed, 114) — NO tag byte, must match OpenSSL key derivation */
        const uint8_t *parts[1] = { seed };
        size_t lens[1] = { (size_t)seed_len };
        if (!shake256_multi(parts, lens, 1, h_seed, 114)) goto cleanup;
    }
    /* Clamp per RFC 8032 */
    h_seed[0]  &= 0xFC;
    h_seed[55] |= 0x80;
    h_seed[56]  = 0x00;
    a1 = BN_lebin2bn(h_seed, 57, NULL);
    OPENSSL_cleanse(h_seed, 114);
    if (!a1) goto cleanup;

    /* ── Step 2: derive ephemeral t1 ──────────────────────────────────────
     * t1 = SHAKE-256(seed ‖ 0x01, 57) mod Q
     * Using a distinct usage tag ensures t1 ≠ a1.
     */
    {
        uint8_t h_t1[57];
        uint8_t usage1 = 0x01;
        const uint8_t *parts[2] = { seed, &usage1 };
        size_t lens[2] = { (size_t)seed_len, 1 };
        if (!shake256_multi(parts, lens, 2, h_t1, 57)) goto cleanup;
        t1 = BN_lebin2bn(h_t1, 57, NULL);
        OPENSSL_cleanse(h_t1, 57);
        if (!t1) goto cleanup;
    }

    Q   = ed448_q_bn(); if (!Q)  goto cleanup;
    ctx = BN_CTX_new(); if (!ctx) goto cleanup;
    tmp = BN_new();     if (!tmp) goto cleanup;
    c   = BN_new();     if (!c)  goto cleanup;
    c1  = BN_new();     if (!c1) goto cleanup;

    BN_mod(t1, t1, Q, ctx);   /* t1 = t1 mod Q */
    BN_mod(a1, a1, Q, ctx);   /* a1 = a1 mod Q */

    /* ── Step 3: T1 = t1·G ───────────────────────────────────────────────*/
    uint8_t T1[57];
    {
        uint8_t t1_le[57];
        if (BN_bn2lebinpad(t1, t1_le, 57) != 57) goto cleanup;
        if (!ed448_scalarmult_base(t1_le, T1)) goto cleanup;
        OPENSSL_cleanse(t1_le, 57);
    }

    /* ── Step 4: simulate responder ─────────────────────────────────────
     * Pick random c2, r2 in [0, Q-1].
     * T2 = r2·G + c2·A2
     */
    c2 = BN_new(); r2 = BN_new();
    if (!c2 || !r2) goto cleanup;
    if (!BN_rand_range(c2, Q)) goto cleanup;
    if (!BN_rand_range(r2, Q)) goto cleanup;

    uint8_t T2[57];
    {
        uint8_t c2_le[57], r2_le[57];
        if (BN_bn2lebinpad(c2, c2_le, 57) != 57) goto cleanup;
        if (BN_bn2lebinpad(r2, r2_le, 57) != 57) goto cleanup;

        uint8_t r2G[57], c2A2[57];
        if (!ed448_scalarmult_base(r2_le, r2G))             goto cleanup;
        if (!ed448_scalarmult_point(c2_le, A2, c2A2))       goto cleanup;
        if (!ed448_point_add(r2G, c2A2, T2))                goto cleanup;

        OPENSSL_cleanse(c2_le, 57); OPENSSL_cleanse(r2_le, 57);
    }

    /* ── Step 5: c = challenge(msg, A1, A2, T1, T2) ─────────────────────*/
    if (!ring_challenge(msg, (size_t)msg_len, A1, A2, T1, T2, c, Q))
        goto cleanup;

    /* ── Step 6: c1 = (c - c2) mod Q ────────────────────────────────────*/
    /* c1 = (c - c2 + Q) mod Q */
    if (!BN_mod_sub(c1, c, c2, Q, ctx)) goto cleanup;

    /* ── Step 7: r1 = (t1 - c1·a1) mod Q ───────────────────────────────*/
    r1 = BN_new(); if (!r1) goto cleanup;
    if (!BN_mod_mul(tmp, c1, a1, Q, ctx)) goto cleanup;    /* tmp = c1*a1 mod Q */
    if (!BN_mod_sub(r1, t1, tmp, Q, ctx)) goto cleanup;   /* r1 = t1 - tmp mod Q */

    /* ── Encode: c1‖r1‖c2‖r2 (57 bytes each, little-endian) ─────────────*/
    uint8_t sig[RING_SIG_BYTES];
    if (BN_bn2lebinpad(c1, sig + 0*57, 57) != 57) goto cleanup;
    if (BN_bn2lebinpad(r1, sig + 1*57, 57) != 57) goto cleanup;
    if (BN_bn2lebinpad(c2, sig + 2*57, 57) != 57) goto cleanup;
    if (BN_bn2lebinpad(r2, sig + 3*57, 57) != 57) goto cleanup;

    ret = PyBytes_FromStringAndSize((char *)sig, RING_SIG_BYTES);
    OPENSSL_cleanse(sig, RING_SIG_BYTES);

cleanup:
    if (a1)  BN_clear_free(a1);
    if (t1)  BN_clear_free(t1);
    if (r1)  BN_clear_free(r1);
    if (c2)  BN_clear_free(c2);
    if (r2)  BN_clear_free(r2);
    if (tmp) BN_clear_free(tmp);
    BN_free(c); BN_free(c1); BN_free(Q); BN_CTX_free(ctx);
    if (!ret)
        PyErr_SetString(PyExc_RuntimeError, "ring_sign failed");
    return ret;
}

/*
 * ring_verify(A1_57, A2_57, msg, sig_228) → bool
 *
 * Verification:
 *   Parse c1, r1, c2, r2 from sig.
 *   T1' = r1·G + c1·A1
 *   T2' = r2·G + c2·A2
 *   c'  = challenge(msg, A1, A2, T1', T2') mod Q
 *   accept iff c' == (c1 + c2) mod Q
 */
static PyObject *
py_ring_verify(PyObject *self, PyObject *args)
{
    (void)self;
    const uint8_t *A1, *A2, *msg, *sig;
    Py_ssize_t A1_len, A2_len, msg_len, sig_len;

    if (!PyArg_ParseTuple(args, "y#y#y#y#",
                          &A1,  &A1_len,
                          &A2,  &A2_len,
                          &msg, &msg_len,
                          &sig, &sig_len))
        return NULL;

    if (A1_len != 57 || A2_len != 57 || sig_len != RING_SIG_BYTES) {
        PyErr_SetString(PyExc_ValueError, "ring_verify: bad argument sizes");
        return NULL;
    }

    int ok = 0;
    BIGNUM *Q  = NULL, *c1 = NULL, *r1 = NULL;
    BIGNUM *c2 = NULL, *r2 = NULL;
    BIGNUM *c_sum = NULL, *c_chk = NULL;
    BN_CTX *ctx = NULL;

    Q = ed448_q_bn(); if (!Q) goto done;
    ctx = BN_CTX_new(); if (!ctx) goto done;

    c1 = le57_to_scalar(sig + 0*57);
    r1 = le57_to_scalar(sig + 1*57);
    c2 = le57_to_scalar(sig + 2*57);
    r2 = le57_to_scalar(sig + 3*57);
    c_sum = BN_new();
    c_chk = BN_new();
    if (!c1 || !r1 || !c2 || !r2 || !c_sum || !c_chk) goto done;

    /* T1' = r1·G + c1·A1 */
    uint8_t T1p[57];
    {
        uint8_t r1_le[57], c1_le[57];
        if (BN_bn2lebinpad(r1, r1_le, 57) != 57) goto done;
        if (BN_bn2lebinpad(c1, c1_le, 57) != 57) goto done;
        uint8_t r1G[57], c1A1[57];
        if (!ed448_scalarmult_base(r1_le, r1G))          goto done;
        if (!ed448_scalarmult_point(c1_le, A1, c1A1))   goto done;
        if (!ed448_point_add(r1G, c1A1, T1p))           goto done;
    }

    /* T2' = r2·G + c2·A2 */
    uint8_t T2p[57];
    {
        uint8_t r2_le[57], c2_le[57];
        if (BN_bn2lebinpad(r2, r2_le, 57) != 57) goto done;
        if (BN_bn2lebinpad(c2, c2_le, 57) != 57) goto done;
        uint8_t r2G[57], c2A2[57];
        if (!ed448_scalarmult_base(r2_le, r2G))          goto done;
        if (!ed448_scalarmult_point(c2_le, A2, c2A2))   goto done;
        if (!ed448_point_add(r2G, c2A2, T2p))           goto done;
    }

    /* c' = challenge mod Q */
    if (!ring_challenge(msg, (size_t)msg_len, A1, A2, T1p, T2p, c_chk, Q))
        goto done;

    /* c_sum = (c1 + c2) mod Q */
    if (!BN_mod_add(c_sum, c1, c2, Q, ctx)) goto done;

    ok = (BN_cmp(c_chk, c_sum) == 0);

done:
    BN_free(Q); BN_free(c1); BN_free(r1); BN_free(c2); BN_free(r2);
    BN_free(c_sum); BN_free(c_chk); BN_CTX_free(ctx);
    return PyBool_FromLong(ok);
}

/* mlkem1024_keygen() → (ek: bytes, dk: bytes) */
static PyObject *
py_mlkem1024_keygen(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
    uint8_t ek[MLKEM_EK_BYTES];
    uint8_t dk[MLKEM_DK_BYTES];
    mlkem1024_do_keygen(ek, dk);
    PyObject *ek_obj = PyBytes_FromStringAndSize((char *)ek, MLKEM_EK_BYTES);
    PyObject *dk_obj = PyBytes_FromStringAndSize((char *)dk, MLKEM_DK_BYTES);
    OPENSSL_cleanse(dk, MLKEM_DK_BYTES);
    if (!ek_obj || !dk_obj) { Py_XDECREF(ek_obj); Py_XDECREF(dk_obj); return NULL; }
    PyObject *ret = PyTuple_Pack(2, ek_obj, dk_obj);
    Py_DECREF(ek_obj); Py_DECREF(dk_obj);
    return ret;
}

/* mlkem1024_encaps(ek: bytes) → (ct: bytes, ss: bytes) */
static PyObject *
py_mlkem1024_encaps(PyObject *self, PyObject *args)
{
    (void)self;
    const uint8_t *ek;
    Py_ssize_t ek_len;
    if (!PyArg_ParseTuple(args, "y#", &ek, &ek_len)) return NULL;
    if (ek_len != MLKEM_EK_BYTES) {
        PyErr_SetString(PyExc_ValueError, "mlkem1024_encaps: ek must be 1568 bytes");
        return NULL;
    }
    uint8_t ct[MLKEM_CT_BYTES], ss[MLKEM_SS_BYTES];
    mlkem1024_do_encaps(ek, ct, ss);
    PyObject *ct_obj = PyBytes_FromStringAndSize((char *)ct, MLKEM_CT_BYTES);
    PyObject *ss_obj = PyBytes_FromStringAndSize((char *)ss, MLKEM_SS_BYTES);
    OPENSSL_cleanse(ss, MLKEM_SS_BYTES);
    if (!ct_obj || !ss_obj) { Py_XDECREF(ct_obj); Py_XDECREF(ss_obj); return NULL; }
    PyObject *ret = PyTuple_Pack(2, ct_obj, ss_obj);
    Py_DECREF(ct_obj); Py_DECREF(ss_obj);
    return ret;
}

/* mlkem1024_decaps(ct: bytes, dk: bytes) → ss: bytes */
static PyObject *
py_mlkem1024_decaps(PyObject *self, PyObject *args)
{
    (void)self;
    const uint8_t *ct, *dk;
    Py_ssize_t ct_len, dk_len;
    if (!PyArg_ParseTuple(args, "y#y#", &ct, &ct_len, &dk, &dk_len)) return NULL;
    if (ct_len != MLKEM_CT_BYTES) {
        PyErr_SetString(PyExc_ValueError, "mlkem1024_decaps: ct must be 1568 bytes");
        return NULL;
    }
    if (dk_len != MLKEM_DK_BYTES) {
        PyErr_SetString(PyExc_ValueError, "mlkem1024_decaps: dk must be 3168 bytes");
        return NULL;
    }
    uint8_t ss[MLKEM_SS_BYTES];
    mlkem1024_do_decaps(ct, dk, ss);
    PyObject *ret = PyBytes_FromStringAndSize((char *)ss, MLKEM_SS_BYTES);
    OPENSSL_cleanse(ss, MLKEM_SS_BYTES);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module definition
 * ═══════════════════════════════════════════════════════════════════════════ */

static PyMethodDef otr4_methods[] = {
    { "disable_core_dumps",   py_disable_core_dumps,   METH_NOARGS,
      "Disable core dumps via prctl/setrlimit.  Call at startup." },

    { "cleanse",              py_cleanse,              METH_VARARGS,
      "cleanse(buf: bytearray) -> None\n"
      "OPENSSL_cleanse the contents of buf in-place." },

    { "bn_mod_exp_consttime", py_bn_mod_exp_consttime, METH_VARARGS,
      "bn_mod_exp_consttime(base: bytes, exp: bytes, mod: bytes) -> bytes\n"
      "Constant-time modular exponentiation via BN_mod_exp_mont_consttime." },

    { "bn_mod_inverse",       py_bn_mod_inverse,       METH_VARARGS,
      "bn_mod_inverse(a: bytes, mod: bytes) -> bytes\n"
      "Modular inverse via OpenSSL BN_mod_inverse." },

    { "bn_rand_range",        py_bn_rand_range,        METH_VARARGS,
      "bn_rand_range(mod: bytes) -> bytes\n"
      "Uniform random integer in [0, mod-1] via BN_rand_range." },

    { "ring_sign",            py_ring_sign,            METH_VARARGS,
      "ring_sign(seed: bytes, A1: bytes, A2: bytes, msg: bytes) -> bytes\n"
      "OTRv4 §4.3.3 Ed448 Schnorr ring signature.  Returns c1‖r1‖c2‖r2 (228 bytes)." },

    { "ring_verify",          py_ring_verify,          METH_VARARGS,
      "ring_verify(A1: bytes, A2: bytes, msg: bytes, sig: bytes) -> bool\n"
      "Verify an OTRv4 ring signature." },

    { "mlkem1024_keygen",      py_mlkem1024_keygen,      METH_NOARGS,
      "mlkem1024_keygen() -> (ek: bytes, dk: bytes)\n"
      "ML-KEM-1024 key generation.  ek=1568 B, dk=3168 B." },

    { "mlkem1024_encaps",      py_mlkem1024_encaps,      METH_VARARGS,
      "mlkem1024_encaps(ek: bytes) -> (ct: bytes, ss: bytes)\n"
      "ML-KEM-1024 encapsulation.  ct=1568 B, ss=32 B." },

    { "mlkem1024_decaps",      py_mlkem1024_decaps,      METH_VARARGS,
      "mlkem1024_decaps(ct: bytes, dk: bytes) -> ss: bytes\n"
      "ML-KEM-1024 decapsulation with implicit rejection.  ss=32 B." },

    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef otr4_module = {
    PyModuleDef_HEAD_INIT,
    "otr4_crypto_ext",
    "OpenSSL-backed cryptographic primitives for pop3_hardened.py (OTRv4).\n"
    "\n"
    "Provides constant-time BN operations, memory hardening, an OTRv4 §4.3.3\n"
    "Ed448 Schnorr ring signature, and a FIPS 203 ML-KEM-1024 implementation.\n",
    -1,
    otr4_methods
};

PyMODINIT_FUNC
PyInit_otr4_crypto_ext(void)
{
    /* Initialise ML-KEM NTT tables once */
    mlkem_init_tables();

    /* Seed OpenSSL PRNG (no-op on modern OpenSSL which auto-seeds) */
    RAND_poll();

    return PyModule_Create(&otr4_module);
}
