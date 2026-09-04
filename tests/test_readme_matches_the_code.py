"""The README's headline claims, checked against the code they describe.

A README is the only thing most readers will read, and this one makes
cryptographic claims. Two of them had gone stale by v10.16.1: the version
badge still said v10.14.0, and an "honest caveat" still described the voice
path as using the Python `cryptography` library, which stopped being true at
v10.13.2 — while two other sections of the same file said it had moved. A
README that overstates a weakness is as wrong as one that hides it, and one
that contradicts itself gives a reader no way to tell which half to believe.

These are the claims cheap enough to check mechanically. They do not make the
README true; they stop the specific things that have already drifted from
drifting again silently.
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

xmpp = pytest.importorskip("otrv4plus_xmpp")


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def readme():
    return _read("README.md")


class TestTheVersionBadge:

    def test_it_matches_the_client(self):
        """The badge is the first line anyone reads; it said v10.14.0 while
        the client reported 10.16.1."""
        badge = _badge(_read("README.md"))
        assert badge.startswith("v" + xmpp.XMPP_VERSION + " "), (
            "README badge says %r, client says %r"
            % (badge.split(" ")[0], "v" + xmpp.XMPP_VERSION))

    def test_it_names_what_encrypts_a_message(self):
        """It listed the AEAD for voice and not for chat, which reads as
        though chat has none -- the question that prompted this file."""
        badge = _badge(_read("README.md"))
        chat = badge.split("·")
        assert any("chat" in seg and "AES-256-GCM" in seg for seg in chat), (
            "the badge does not say what encrypts a chat message")


def _badge(readme):
    m = re.search(r"<code>(v\d+\.\d+\.\d+ .*?)</code>", readme, re.DOTALL)
    assert m, "the README no longer has a version badge"
    return m.group(1)


class TestTheSmpClaims:
    """SMP is where the AES question came from, so the answer is pinned."""

    def test_the_readme_does_not_put_aes_inside_the_smp_primitives(self):
        """`Rust/src/smp.rs` contains no AES.  Listing it among SMP's
        primitives would say the construction uses it."""
        badge = _badge(_read("README.md"))
        smp_segment = [s for s in badge.split("·") if "SMP" in s]
        assert smp_segment, "the badge no longer mentions SMP"
        assert "AES" not in smp_segment[0], (
            "the badge now claims SMP uses AES; smp.rs has none")

    def test_the_engine_really_has_no_aes(self):
        """The claim above is only worth pinning if it stays true."""
        smp_rs = _read(os.path.join("Rust", "src", "smp.rs")).lower()
        for token in ("aes256gcm", "aes_gcm", "aes-256-gcm"):
            assert token not in smp_rs, (
                "smp.rs now uses %s -- the README says it does not" % token)

    def test_the_default_wire_version_is_documented(self, readme):
        """0x03 has been the default since v10.13.0; the README said 0x02."""
        smp_rs = _read(os.path.join("Rust", "src", "smp.rs"))
        assert "version: SMP_VERSION_PQ_ARGON2" in smp_rs, (
            "the default wire version changed; the README needs rereading")
        assert "`0x03`" in readme
        assert "default since v10.13.0" in readme


class TestTheVoiceCaveatIsNotStale:
    """It described the pre-v10.13.2 arrangement for three releases."""

    def test_no_live_python_aes_gcm_remains(self):
        """The caveat used to say there were two AES-256-GCM implementations
        in the tree.  If one comes back, the caveat has to come back too."""
        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in (".attic", ".git", "tests", "target",
                                        "__pycache__", "node_modules")]
            for name in filenames:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        code = line.split("#", 1)[0]
                        if "AESGCM(" in code:
                            offenders.append("%s:%d"
                                             % (os.path.relpath(path, ROOT), n))
        assert offenders == [], (
            "a Python AES-GCM call site is back: %s" % offenders)

    def test_voice_has_no_python_fallback(self, readme):
        """The caveat's replacement claims this; a fallback would restore
        exactly what was removed."""
        voice = _read("otrv4plus_voice.py")
        assert "def _require_rust_voice():" in voice
        assert "RUST_VOICE_AVAILABLE" in voice, (
            "the hard requirement is gone; voice may run without the core")
        flat = " ".join(voice.replace('"', " ").split())
        assert "no Python fallback" in flat, (
            "the error no longer says the requirement is absolute")
        assert "no fallback" in readme

    def test_the_caveat_no_longer_states_the_old_arrangement(self, readme):
        """It must not say, in the present tense, that voice crypto comes
        from the Python library."""
        stale = ("its media AES-256-GCM, HKDF-SHA512 key schedule and X448 "
                 "come from the Python `cryptography` library")
        assert stale not in readme

    def test_the_security_document_agrees(self):
        """README caveat 4 and SECURITY.md's voice table disagreed for three
        releases, each pointing at the other."""
        security = _read("SECURITY.md")
        assert "Voice epoch root (64 B) | Rust `SecretBytes<64>`" in security, (
            "SECURITY.md still lists the epoch root as Python-held")
        # And it still names what genuinely is Python-side.
        assert "ML-KEM decapsulation key" in security
        assert "Python `bytearray`" in security, (
            "the table now claims nothing is Python-side, which is not true")


class TestTheCryptoChainDiagram:
    """The top-of-README chain, checked against the code it draws.

    A diagram is the part of a README people actually retain, so a wrong one
    is worse than none. Two mistakes are easy to make here and both were
    corrected before it was committed: dropping the Ed448 ring signature (the
    thing that makes the authentication deniable, which is what OTR is for),
    and drawing the KEM as a one-time handshake step when it re-runs at every
    DH ratchet step.
    """

    def test_the_diagram_is_there(self, readme):
        assert "What actually encrypts a message" in readme

    def test_it_keeps_the_ring_signature_beside_ml_dsa(self, readme):
        """ML-DSA-87 is added alongside the ring signature, not instead."""
        chain = readme.split("What actually encrypts a message", 1)[1][:900]
        assert "Ed448 ring signature" in chain, (
            "the chain now credits authentication to ML-DSA-87 alone, which "
            "drops deniability")
        assert "ML-DSA-87" in chain

    def test_the_dake_really_uses_a_ring_signature(self):
        dake = _read(os.path.join("Rust", "src", "dake.rs"))
        assert "ring_sig::ring_verify_bytes" in dake, (
            "DAKE3 no longer verifies a ring signature; the diagram lies")

    def test_the_key_schedule_really_is_shake_256(self, readme):
        kdf = _read(os.path.join("Rust", "src", "kdf.rs"))
        assert "Shake256" in kdf
        assert "SHAKE-256 key schedule" in readme

    def test_the_kem_really_re_runs_per_ratchet_step(self, readme):
        """The brace key is rotated by a KEM shared secret at each DH step.
        Lose that and the diagram's central claim is wrong."""
        ratchet = _read(os.path.join("Rust", "src", "ratchet.rs"))
        assert "kdf_brace_rotate" in ratchet, (
            "nothing rotates the brace key any more")
        assert "EVERY DH ratchet step" in readme

    def test_it_does_not_put_aes_in_the_agreement_layer(self, readme):
        """AES-256-GCM is the last step, not part of the key agreement."""
        chain = readme.split("What actually encrypts a message", 1)[1][:600]
        agreement, _, rest = chain.partition("double ratchet")
        assert "AES" not in agreement, (
            "AES appears above the ratchet, where no AES runs")
        assert "AES-256-GCM" in rest
