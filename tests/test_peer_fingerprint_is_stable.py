#!/usr/bin/env python3
"""Is the pinned fingerprint actually stable across restarts?

The claim under test, made after a live mismatch: "the way we generate these
always changes the output, therefore saving is pointless." If that were true,
pinning could never work and the whole TOFU feature should be removed rather
than debugged. So it is worth settling with code rather than with an argument.

The value a peer pins is `EnhancedOTRSession.get_fingerprint()`, which is

    SHA3-512(remote_long_term_pub).hex().upper()

-- a pure function of the peer's LONG-TERM identity public key, with no DAKE
transcript, no ephemeral X448, no ML-KEM material and no timestamp in it. So
the question reduces to whether that long-term key survives a restart, which
is exactly what persistent identity provides and what these tests check by
reloading it.
"""

import hashlib
import inspect
import os
import re
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
xmpp = pytest.importorskip("otrv4plus_xmpp")


def _fp_of(identity_pub: bytes) -> str:
    """What a peer would pin, given these long-term public bytes."""
    return hashlib.sha3_512(bytes(identity_pub)).digest().hex().upper()


class TestWhatTheFingerprintIsMadeOf:

    def test_it_is_only_the_long_term_key(self):
        src = inspect.getsource(otr.EnhancedOTRSession.get_fingerprint)
        assert "sha3_512" in src
        # Anything ephemeral in here would make a pin change every session and
        # the feature impossible, which is precisely the reported suspicion.
        for ephemeral in ("transcript", "session_id", "ssid", "epoch",
                          "mlkem", "brace", "chain", "root_key", "time"):
            assert ephemeral not in src.lower(), (
                "get_fingerprint mixes in %s; a pin could never survive a "
                "session" % ephemeral)
        names = re.findall(r"self\.(\w+)", src)
        assert set(names) <= {"remote_long_term_pub", "_remote_long_term_pub_bytes"}, (
            "get_fingerprint reads %s; it must read only the peer's long-term "
            "key" % sorted(set(names))

        )


class TestItSurvivesRestarts:

    def _bob_identity_pub(self, statedir):
        """One 'launch' of Bob: build the manager, return his long-term key."""
        cfg = otr.OTRConfig(
            test_mode=True,
            persist_identity=True,
            persist_trust=True,
            trust_db_path=os.path.join(statedir, "trust.json"),
            identity_path=os.path.join(statedir, "identity.sealed"),
            identity_dek_path=os.path.join(statedir, ".identity_dek"),
        )
        mgr = otr.EnhancedSessionManager(config=cfg)
        assert mgr.identity_is_persistent
        return bytes(mgr.client_profile.identity_key.public_bytes())

    def test_the_pinned_value_is_identical_across_launches(self):
        with tempfile.TemporaryDirectory() as d:
            first = _fp_of(self._bob_identity_pub(d))
            for _ in range(4):
                assert _fp_of(self._bob_identity_pub(d)) == first, (
                    "the fingerprint a peer pins changed between launches")

    def test_an_ephemeral_build_is_where_it_does_change(self):
        """The claim was true before v10.12.0, and this is why.

        Without persistence every launch mints a new long-term key, so the
        pinned value could not survive and a mismatch on the second session was
        guaranteed. That is the world the report came from.
        """
        with tempfile.TemporaryDirectory() as d:
            seen = set()
            for i in range(3):
                mgr = otr.EnhancedSessionManager(
                    config=otr.OTRConfig(
                        test_mode=True,
                        trust_db_path=os.path.join(d, "t%d.json" % i)))
                assert not mgr.identity_is_persistent
                seen.add(_fp_of(mgr.client_profile.identity_key.public_bytes()))
            assert len(seen) == 3, "an ephemeral build repeated a fingerprint"

    def test_upgrading_from_ephemeral_to_persistent_looks_like_a_change(self):
        """And that is the mismatch actually seen, not a defect.

        A pin taken while the peer was ephemeral cannot match the identity the
        peer settled on afterwards. One /trust-reset clears it; the pin taken
        after that is the one that lasts.
        """
        with tempfile.TemporaryDirectory() as d:
            db = otr.TrustDatabase(os.path.join(d, "trust.json"), persistent=True)
            old_ephemeral = _fp_of(
                otr.EnhancedSessionManager(
                    config=otr.OTRConfig(
                        test_mode=True,
                        trust_db_path=os.path.join(d, "x.json"))
                ).client_profile.identity_key.public_bytes())
            db.add_trust("bob@x", old_ephemeral)

            now_persistent = _fp_of(self._bob_identity_pub(os.path.join(d)))
            with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
                db.check_or_pin("bob@x", now_persistent)

            assert db.remove_trust("bob@x") is True
            assert db.check_or_pin("bob@x", now_persistent) is False
            db.add_trust("bob@x", now_persistent)
            assert db.check_or_pin("bob@x", now_persistent) is True


class TestAMismatchHaltsBeforeSmp:

    def test_smp_setup_does_not_run_while_a_change_is_unresolved(self):
        """Observed live: Bob reached the SMP passphrase step and Alice did not.

        That is this branch, working. Continuing to SMP would mean agreeing a
        shared secret with an identity that has not been accounted for, which
        is the one moment it matters who is on the other end.
        """
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._apply_tofu)
        head, _, tail = src.partition("_fingerprint_changed[peer]")
        assert tail, "the mismatch branch no longer records the change"
        before_return = tail.split("return", 1)[0]
        assert "_prompt_smp_secret" not in before_return, (
            "the mismatch branch continues into SMP setup")
