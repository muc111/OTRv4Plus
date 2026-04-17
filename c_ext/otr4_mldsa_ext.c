/*
 * otr4_mldsa_ext.c — ML-DSA-87 (FIPS 204) Python C extension via OpenSSL EVP.
 *
 * Requires OpenSSL ≥ 3.5 with ML-DSA-87 provider enabled.
 * Build:  python setup_otr4.py build_ext --inplace
 *   or:   gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
 *          $(python3-config --includes) -lcrypto
 *
 * Exports:
 *   mldsa87_keygen()                → (pub_bytes, priv_bytearray)
 *   mldsa87_sign(priv_bytes, msg)   → sig_bytes
 *   mldsa87_verify(pub_bytes, msg, sig_bytes) → bool
 *
 * NIST Level 5 (≈AES-256 post-quantum security):
 *   Public key:  2592 bytes
 *   Private key: 4896 bytes
 *   Signature:   4627 bytes
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define MLDSA87_PUB_BYTES   2592
#define MLDSA87_PRIV_BYTES  4896
#define MLDSA87_SIG_BYTES   4627
#define MLDSA87_ALG_NAME    "ML-DSA-87"

/* ── helpers ──────────────────────────────────────────────────────── */

static void _set_openssl_error(const char *prefix)
{
    unsigned long err = ERR_peek_last_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    PyErr_Format(PyExc_RuntimeError, "%s: %s", prefix, buf);
    ERR_clear_error();
}

/* Reconstruct an EVP_PKEY from raw private key bytes. */
static EVP_PKEY *_pkey_from_priv(const unsigned char *priv, size_t priv_len)
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key_ex(
        NULL, MLDSA87_ALG_NAME, NULL, priv, priv_len);
    if (!pkey)
        _set_openssl_error("ML-DSA-87 load private key");
    return pkey;
}

/* Reconstruct an EVP_PKEY from raw public key bytes. */
static EVP_PKEY *_pkey_from_pub(const unsigned char *pub, size_t pub_len)
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(
        NULL, MLDSA87_ALG_NAME, NULL, pub, pub_len);
    if (!pkey)
        _set_openssl_error("ML-DSA-87 load public key");
    return pkey;
}

/* ── mldsa87_keygen ───────────────────────────────────────────────── */

PyDoc_STRVAR(keygen_doc,
    "mldsa87_keygen() -> (pub_bytes, priv_bytearray)\n\n"
    "Generate a fresh ML-DSA-87 keypair.\n"
    "Private key returned as mutable bytearray for OPENSSL_cleanse.");

static PyObject *mldsa87_keygen(PyObject *self, PyObject *args)
{
    (void)self; (void)args;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, MLDSA87_ALG_NAME, NULL);
    if (!ctx) {
        _set_openssl_error("ML-DSA-87 CTX alloc");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        _set_openssl_error("ML-DSA-87 keygen init");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        _set_openssl_error("ML-DSA-87 keygen");
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);

    /* Extract raw public key */
    size_t pub_len = MLDSA87_PUB_BYTES;
    unsigned char pub[MLDSA87_PUB_BYTES];
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        _set_openssl_error("ML-DSA-87 get public key");
        return NULL;
    }

    /* Extract raw private key */
    size_t priv_len = MLDSA87_PRIV_BYTES;
    unsigned char *priv = OPENSSL_malloc(priv_len);
    if (!priv) {
        EVP_PKEY_free(pkey);
        PyErr_NoMemory();
        return NULL;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) <= 0) {
        OPENSSL_free(priv);
        EVP_PKEY_free(pkey);
        _set_openssl_error("ML-DSA-87 get private key");
        return NULL;
    }
    EVP_PKEY_free(pkey);

    /* Build return: (bytes, bytearray) */
    PyObject *pub_obj  = PyBytes_FromStringAndSize((char *)pub, (Py_ssize_t)pub_len);
    PyObject *priv_obj = PyByteArray_FromStringAndSize((char *)priv, (Py_ssize_t)priv_len);

    /* Cleanse the C-side copy immediately */
    OPENSSL_cleanse(priv, priv_len);
    OPENSSL_free(priv);

    if (!pub_obj || !priv_obj) {
        Py_XDECREF(pub_obj);
        Py_XDECREF(priv_obj);
        return NULL;
    }

    return Py_BuildValue("(OO)", pub_obj, priv_obj);
}

/* ── mldsa87_sign ─────────────────────────────────────────────────── */

PyDoc_STRVAR(sign_doc,
    "mldsa87_sign(priv_bytes, msg) -> sig_bytes\n\n"
    "Sign msg with ML-DSA-87 private key.  Returns 4627-byte signature.");

static PyObject *mldsa87_sign(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer priv_buf, msg_buf;

    if (!PyArg_ParseTuple(args, "y*y*", &priv_buf, &msg_buf))
        return NULL;

    if (priv_buf.len != MLDSA87_PRIV_BYTES) {
        PyErr_Format(PyExc_ValueError,
            "ML-DSA-87 private key must be %d bytes, got %zd",
            MLDSA87_PRIV_BYTES, priv_buf.len);
        PyBuffer_Release(&priv_buf);
        PyBuffer_Release(&msg_buf);
        return NULL;
    }

    EVP_PKEY *pkey = _pkey_from_priv(priv_buf.buf, priv_buf.len);
    /* Cleanse the buffer copy in our address space */
    OPENSSL_cleanse(priv_buf.buf, priv_buf.len);
    PyBuffer_Release(&priv_buf);

    if (!pkey) {
        PyBuffer_Release(&msg_buf);
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        PyErr_NoMemory();
        return NULL;
    }

    /* ML-DSA does its own hashing — pass NULL for digest */
    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        _set_openssl_error("ML-DSA-87 sign init");
        return NULL;
    }

    /* Determine signature length */
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, msg_buf.buf, msg_buf.len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        _set_openssl_error("ML-DSA-87 sign length query");
        return NULL;
    }

    unsigned char *sig = OPENSSL_malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        PyErr_NoMemory();
        return NULL;
    }

    if (EVP_DigestSign(mdctx, sig, &sig_len, msg_buf.buf, msg_buf.len) <= 0) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        _set_openssl_error("ML-DSA-87 sign");
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    PyBuffer_Release(&msg_buf);

    PyObject *result = PyBytes_FromStringAndSize((char *)sig, (Py_ssize_t)sig_len);
    OPENSSL_free(sig);
    return result;
}

/* ── mldsa87_verify ───────────────────────────────────────────────── */

PyDoc_STRVAR(verify_doc,
    "mldsa87_verify(pub_bytes, msg, sig_bytes) -> bool\n\n"
    "Verify an ML-DSA-87 signature.  Returns True/False.");

static PyObject *mldsa87_verify(PyObject *self, PyObject *args)
{
    (void)self;
    Py_buffer pub_buf, msg_buf, sig_buf;

    if (!PyArg_ParseTuple(args, "y*y*y*", &pub_buf, &msg_buf, &sig_buf))
        return NULL;

    if (pub_buf.len != MLDSA87_PUB_BYTES) {
        PyErr_Format(PyExc_ValueError,
            "ML-DSA-87 public key must be %d bytes, got %zd",
            MLDSA87_PUB_BYTES, pub_buf.len);
        PyBuffer_Release(&pub_buf);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&sig_buf);
        return NULL;
    }

    EVP_PKEY *pkey = _pkey_from_pub(pub_buf.buf, pub_buf.len);
    PyBuffer_Release(&pub_buf);

    if (!pkey) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&sig_buf);
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&sig_buf);
        PyErr_NoMemory();
        return NULL;
    }

    if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&sig_buf);
        _set_openssl_error("ML-DSA-87 verify init");
        return NULL;
    }

    int rc = EVP_DigestVerify(mdctx, sig_buf.buf, sig_buf.len,
                               msg_buf.buf, msg_buf.len);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    PyBuffer_Release(&msg_buf);
    PyBuffer_Release(&sig_buf);

    /* rc == 1 → valid, 0 → invalid, <0 → error */
    if (rc == 1)
        Py_RETURN_TRUE;
    if (rc == 0)
        Py_RETURN_FALSE;

    /* Unexpected error */
    _set_openssl_error("ML-DSA-87 verify");
    return NULL;
}

/* ── module definition ────────────────────────────────────────────── */

static PyMethodDef methods[] = {
    {"mldsa87_keygen",  mldsa87_keygen,  METH_NOARGS,  keygen_doc},
    {"mldsa87_sign",    mldsa87_sign,    METH_VARARGS, sign_doc},
    {"mldsa87_verify",  mldsa87_verify,  METH_VARARGS, verify_doc},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "otr4_mldsa_ext",
    "ML-DSA-87 (FIPS 204) via OpenSSL EVP — post-quantum digital signatures.\n"
    "Requires OpenSSL >= 3.5 with ML-DSA-87 provider.",
    -1,
    methods
};

PyMODINIT_FUNC PyInit_otr4_mldsa_ext(void)
{
    PyObject *m = PyModule_Create(&module);
    if (!m) return NULL;

    /* Expose size constants for Python-side validation */
    PyModule_AddIntConstant(m, "PUB_BYTES",  MLDSA87_PUB_BYTES);
    PyModule_AddIntConstant(m, "PRIV_BYTES", MLDSA87_PRIV_BYTES);
    PyModule_AddIntConstant(m, "SIG_BYTES",  MLDSA87_SIG_BYTES);

    return m;
}
