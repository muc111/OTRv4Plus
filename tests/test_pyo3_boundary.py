"""Hostile Python input must not get past PyO3 into the Rust core.

`Rust/Cargo.toml` sets `panic = "abort"` for the release profile. That is a
deliberate fail-closed choice for a crypto core -- a wrapped counter is worse
than a crash -- but it means a Rust panic is not a Python exception someone can
catch: it takes the whole client down mid-session, with the peer left waiting.
So every argument arriving from Python has to be rejected as a `PyErr`, never
by panicking.

This file drives the *installed extension module*, not the source tree. A
dependency upgrade that changes how PyO3 converts arguments -- and 0.24 -> 0.29
is exactly that kind of upgrade -- would show up here and nowhere else.

The three shapes it pushes through are the three the boundary actually accepts:

    &[u8]         - bytes-like, fixed-length in almost every case
    u32 / u64     - unsigned, so a negative or oversized int must be refused
    &str          - vault entry names

plus the wrong-type case for each. What must NOT happen is the interpreter
dying: every assertion below is followed, at the end of the module, by a
liveness check that the module still works.

Enforces INV-23, and the "no unnecessary Python copy of key material" half
of INV-08.
"""

import pytest

otrv4_core = pytest.importorskip("otrv4_core")


#: Values Python will happily hand to a `u64` parameter and PyO3 has to
#: refuse. 2**64 is the one that matters: a conversion that truncated instead
#: of raising would silently alias a different, valid length. 2**32 is NOT
#: here -- it is a perfectly good u64 -- and 2**4096 is, because "obviously
#: absurd" and "rejected" are not the same property.
HOSTILE_INTS = (
    -1,
    -(2 ** 63),
    2 ** 64,
    2 ** 64 + 1,
    2 ** 256,
    2 ** 4096,
)

#: Objects that are not bytes-like at all. The near-misses are the point: a
#: list of ints and a tuple of ints are exactly what someone reaches for when
#: `bytes` would have been right, and a list of `bytes` is what a caller who
#: meant to `b"".join(...)` first passes in.
NON_BYTES = (
    None,
    0,
    1.5,
    "not bytes",
    [1, 2, 3],
    (1, 2, 3),
    {1: 2},
    {1, 2},
    object(),
    [b"a", b"b"],
)


def _assert_python_error(fn, *args, **kwargs):
    """Call `fn` and require it to raise something Python can catch.

    A bare `except Exception` is the point: what is being asserted is that
    control returns to Python at all. Which exception type PyO3 chooses for a
    given conversion is its business and has changed between releases.
    """
    with pytest.raises(Exception):
        fn(*args, **kwargs)


class TestIntegerArgumentsAreRefusedNotTruncated:
    """`file_transfer_sizes(plain_len: u64)` is the simplest integer crossing
    in the module, so it is the one to prove the rule on."""

    @pytest.mark.parametrize("value", HOSTILE_INTS)
    def test_out_of_range_integers_raise(self, value):
        _assert_python_error(otrv4_core.file_transfer_sizes, value)

    @pytest.mark.parametrize("value", (None, "8", 1.5, [8], object()))
    def test_non_integers_raise(self, value):
        _assert_python_error(otrv4_core.file_transfer_sizes, value)

    def test_a_lying_int_subclass_cannot_smuggle_a_value_past_the_check(self):
        """An `int` subclass whose `__index__` returns something else does not
        get to choose which value Rust sees.

        This is the safe direction and it is worth pinning: CPython reads the
        underlying integer for an `int` subclass rather than calling the
        overridden hook, so the value Rust range-checks is the value the
        object really is. If a future PyO3 started routing through
        `__index__`, an attacker-controlled object could pass a small value to
        whatever Python-side length check exists and a huge one to Rust."""

        class Liar(int):
            def __index__(self):
                return 2 ** 128

        assert otrv4_core.file_transfer_sizes(Liar(5)) == \
            otrv4_core.file_transfer_sizes(5)

    def test_a_plausible_value_still_works(self):
        sealed, chunk = otrv4_core.file_transfer_sizes(1024)
        assert sealed > 1024      # framing and tag are additive
        assert chunk > 0


class TestBytesArgumentsAreRefusedNotCoerced:
    """Every `&[u8]` parameter in the crate is length-checked in Rust *after*
    PyO3 has established it is bytes-like at all. Both halves are asserted:
    the wrong type, and the right type at the wrong length."""

    @pytest.mark.parametrize("value", NON_BYTES)
    def test_non_bytes_public_key_raises(self, value):
        _assert_python_error(otrv4_core.verify_ed448_sig, value, b"msg", b"\x00" * 114)

    @pytest.mark.parametrize("length", (0, 1, 56, 58, 113, 4096))
    def test_wrong_length_public_key_is_rejected(self, length):
        """Ed448 public keys are 57 bytes. Anything else is either an error or
        a `False` verdict -- never a panic, and never a `True`."""
        try:
            verdict = otrv4_core.verify_ed448_sig(
                b"\x00" * length, b"msg", b"\x00" * 114)
        except Exception:
            return                      # refused outright: also correct
        assert verdict is False

    def test_an_empty_message_is_data_not_an_error(self):
        """Zero-length is a legitimate message, and must not be confused with
        a missing argument. It verifies to False against a zero key rather
        than raising."""
        verdict = otrv4_core.verify_ed448_sig(
            b"\x00" * 57, b"", b"\x00" * 114)
        assert verdict is False

    def test_a_very_large_message_does_not_overflow_anything(self):
        big = b"\x5a" * (4 * 1024 * 1024)
        verdict = otrv4_core.verify_ed448_sig(b"\x00" * 57, big, b"\x00" * 114)
        assert verdict is False

    def test_a_bytearray_is_refused_by_the_plain_slice_parameters(self):
        """`&[u8]` means `bytes` and nothing else.

        PyO3 will not borrow a slice out of a `bytearray`, because the
        bytearray can be resized from Python while Rust holds the pointer.
        That is the right call, and it is why the wipe-after-use paths have
        their own `*_from_bytearray` entry points that take a
        `&Bound<PyByteArray>` instead -- see the next test. Asserting the
        refusal here stops anyone "fixing" a TypeError by loosening the
        signature."""
        _assert_python_error(
            otrv4_core.verify_ed448_sig, bytearray(57), b"msg", b"\x00" * 114)

    def test_the_wipeable_entry_points_do_take_a_bytearray(self):
        """The client hands secrets in as `bytearray` precisely so Rust can
        zero the caller's buffer. If an upgrade removed these, the secret
        would have to arrive as an immutable `bytes` that nothing can wipe."""
        vault = otrv4_core.RustSMPVault()
        buf = bytearray(b"a passphrase-derived secret")
        vault.store_from_bytearray("peer", buf)
        assert vault.has("peer")
        assert bytes(buf) == bytes(len(buf)), (
            "store_from_bytearray left the caller's buffer intact; the whole "
            "reason this entry point takes a bytearray is to wipe it"
        )


class TestStringArgumentsAreBounded:
    """`RustSMPVault.store(name: &str, ...)`. Names come from the local user,
    not the wire, but the conversion is the same one a wire-fed `&str` would
    use and it is the only `&str` crossing in the module."""

    def test_a_lone_surrogate_is_refused(self):
        """A lone surrogate is a `str` Python will build but cannot encode to
        UTF-8. Rust's `&str` cannot represent it either, so the conversion has
        to fail rather than produce mojibake or invalid UTF-8 in Rust."""
        vault = otrv4_core.RustSMPVault()
        _assert_python_error(vault.store, "\ud800", b"secret")

    @pytest.mark.parametrize("value", (None, 1, b"bytes", [], object()))
    def test_non_strings_raise(self, value):
        vault = otrv4_core.RustSMPVault()
        _assert_python_error(vault.store, value, b"secret")

    def test_an_ordinary_name_round_trips(self):
        vault = otrv4_core.RustSMPVault()
        vault.store("alice@example.i2p", b"a secret")
        assert vault.has("alice@example.i2p")
        assert vault.count() == 1


class TestSecretsStayRustOwned:
    """Rule 3: cryptographic material should not cross the boundary unless it
    has to. These are the three handles that exist precisely so it does not,
    and each is asserted by what it *lacks*.

    A getter added to any of them would be a new Python copy of a key, which
    is the thing the boundary is for.
    """

    def test_the_smp_vault_has_no_read_back(self):
        vault = otrv4_core.RustSMPVault()
        vault.store("peer", b"passphrase-derived secret")
        exposed = [n for n in dir(vault)
                   if not n.startswith("_")
                   and any(w in n.lower()
                           for w in ("get", "read", "expose", "value", "secret"))]
        assert not exposed, (
            "RustSMPVault now exposes %r; Python could read a stored SMP "
            "secret back out, which is what the vault exists to prevent"
            % exposed
        )

    def test_the_voice_root_does_not_hand_out_the_root(self):
        names = [n for n in dir(otrv4_core.RustVoiceRoot) if not n.startswith("_")]
        assert not [n for n in names
                    if n in ("root", "get_root", "expose", "raw", "bytes")], (
            "RustVoiceRoot exposes the epoch root; a copy of the root is a "
            "copy of every media key for that epoch"
        )

    def test_the_long_term_key_handles_expose_only_public_material(self):
        for cls in (otrv4_core.Ed448KeyHandle, otrv4_core.X448KeyHandle):
            names = [n for n in dir(cls) if not n.startswith("_")]
            leaky = [n for n in names
                     if any(w in n.lower()
                            for w in ("priv", "secret", "seed", "scalar"))]
            assert not leaky, (
                "%s exposes %r -- the handle exists so the private key stays "
                "in Rust" % (cls.__name__, leaky)
            )


class TestTheModuleSurvivedAllOfThat:
    """The point of the whole file. Every rejection above must have returned
    control to Python; if any of them had aborted the process instead, this
    would never run -- but if one merely corrupted state, this catches it."""

    def test_the_module_still_computes(self):
        handle = otrv4_core.generate_ed448_keypair()
        public = handle.public_bytes()
        assert len(public) == 57
        sig = handle.sign(b"still alive")
        assert otrv4_core.verify_ed448_sig(public, b"still alive", sig) is True
        assert otrv4_core.verify_ed448_sig(public, b"tampered", sig) is False
