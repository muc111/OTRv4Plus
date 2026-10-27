# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client's trust pins: sealed, and refused when they will not
open (P1, docs/SECURITY_ISSUES.md).

Before: `~/.otrv4plus/xmpp/trust.json` was plaintext, and one that would
not parse loaded as empty, so every pinned contact became a first contact
-- the failure P1 fixed in the apps, still open in the third client. Now:
  * a plaintext file that will not open is refused, never read as empty;
  * with the XMPP config the pins are sealed on F3's sealing path, under
    their own key file in `trust/`, and the plaintext file is moved in once
    and removed;
  * a sealed record that will not open is refused, and nothing is replaced;
  * if both exist and differ, neither is touched.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
pytest.importorskip("otrv4_core")

PEER = "bob@example.test"
FP = "A1" * 56
OTHER_FP = "B2" * 56
IDENT, MLDSA, OTHER_MLDSA = b"\x01" * 57, b"\x02" * 2592, b"\x03" * 2592


@pytest.fixture
def state(monkeypatch):
    """A terminal XMPP state directory of its own, and HOME inside it."""
    xmpp = pytest.importorskip("otrv4plus_xmpp")
    root = tempfile.mkdtemp(prefix="otrv4plus-term-trust-")
    monkeypatch.setenv("HOME", root)
    statedir = os.path.join(root, ".otrv4plus", "xmpp")
    os.makedirs(statedir, mode=0o700)
    monkeypatch.setattr(xmpp._host, "XMPP_STATE_DIR", statedir)
    return statedir


def _config(xmpp_state):
    import otrv4plus_xmpp as xmpp
    return xmpp._xmpp_otr_config("me@example.test")


def _start(xmpp_state):
    """One start of the terminal client's trust database."""
    return otr._open_trust_db(_config(xmpp_state))


def _plain(xmpp_state):
    return os.path.join(xmpp_state, "trust.json")


def _sealed(xmpp_state):
    return os.path.join(xmpp_state, "trust", "trust.terminal.sealed")


def _write_plain(xmpp_state, data):
    with open(_plain(xmpp_state), "w", encoding="utf-8") as fh:
        fh.write(data if isinstance(data, str) else json.dumps(data))


# -- the plaintext file fails closed ------------------------------------------

@pytest.mark.parametrize("content", ["{not json", "", "[]", '"pins"'])
def test_a_plaintext_trust_file_that_will_not_open_is_refused_not_emptied(content):
    """The gate: this loaded as an empty database before."""
    d = tempfile.mkdtemp(prefix="otrv4plus-plain-trust-")
    path = os.path.join(d, "trust.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    with pytest.raises(otr.TrustDatabase.StoreUnavailable):
        otr.TrustDatabase(path, persistent=True)
    with open(path, encoding="utf-8") as fh:
        assert fh.read() == content, "the file was replaced"


def test_a_missing_plaintext_file_is_a_first_run():
    d = tempfile.mkdtemp(prefix="otrv4plus-plain-trust-")
    assert otr.TrustDatabase(os.path.join(d, "trust.json"), persistent=True).list_trusted() == {}


# -- the terminal seals its pins ----------------------------------------------

def test_the_xmpp_config_seals_the_pins_under_their_own_key(state):
    cfg = _config(state)
    assert cfg.persist_trust is True
    assert cfg.trust_dek_path == os.path.join(state, "trust", "trust.dek")
    assert os.path.dirname(cfg.trust_dek_path) != os.path.dirname(cfg.identity_dek_path)


def test_after_a_restart_the_terminal_refuses_a_changed_key(state):
    db = _start(state)
    db.check_or_pin(PEER, FP)
    db.check_or_pin_pq(PEER, IDENT, MLDSA, True)
    db = _start(state)
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        db.check_or_pin(PEER, OTHER_FP)
    with pytest.raises(otr.TrustDatabase.PqIdentityRefused):
        db.check_or_pin_pq(PEER, IDENT, OTHER_MLDSA, True)
    assert not os.path.exists(_plain(state)), "no plaintext file is written"


def test_the_sealed_record_names_no_contact_and_its_key_file_is_private(state):
    _start(state).check_or_pin(PEER, FP)
    blob = open(_sealed(state), "rb").read()
    assert PEER.encode() not in blob and FP.encode() not in blob
    dek = os.path.join(state, "trust", "trust.dek")
    assert stat.S_IMODE(os.stat(dek).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(dek)).st_mode) == 0o700


def test_plaintext_pins_from_before_are_moved_in_and_the_file_removed(state):
    _write_plain(state, {PEER: {"fingerprint": FP, "trusted": True,
                                "pq": {"identity": "i" * 64, "mldsa": "m" * 64}},
                         "carol@example.test": "C3" * 56})          # the oldest form
    db = _start(state)
    assert not os.path.exists(_plain(state))
    assert db.is_trusted(PEER, FP)
    assert db.is_trusted("carol@example.test", "C3" * 56)
    assert _start(state)._db[PEER]["pq"] == {"identity": "i" * 64, "mldsa": "m" * 64}


def test_a_plaintext_file_that_will_not_open_blocks_the_move_and_stays(state):
    _write_plain(state, "{not json")
    with pytest.raises(Exception) as caught:
        _start(state)
    assert type(caught.value).__name__ == "TrustUnavailable"
    assert open(_plain(state), encoding="utf-8").read() == "{not json"
    assert not os.path.exists(_sealed(state)), "nothing was sealed in its place"


def test_a_sealed_record_that_will_not_open_is_refused_and_not_replaced(state):
    _start(state).check_or_pin(PEER, FP)
    blob = bytearray(open(_sealed(state), "rb").read())
    blob[-1] ^= 0x01
    with open(_sealed(state), "wb") as fh:
        fh.write(blob)
    for _ in range(2):                               # refused, and again
        with pytest.raises(Exception) as caught:
            _start(state)
        assert type(caught.value).__name__ == "TrustUnavailable"
    assert open(_sealed(state), "rb").read() == bytes(blob)
    assert not os.path.exists(_plain(state))


def test_both_files_saying_the_same_thing_is_a_finished_move(state):
    """The move was cut short after sealing: the plaintext goes."""
    _write_plain(state, {PEER: {"fingerprint": FP, "trusted": False}})
    _start(state)
    _write_plain(state, {PEER: {"fingerprint": FP, "trusted": False}})
    assert _start(state).check_or_pin(PEER, FP) is False
    assert not os.path.exists(_plain(state))


def test_both_files_differing_are_refused_and_neither_is_touched(state):
    """An older build wrote trust.json after the upgrade. Taking either side
    would drop pins without saying so."""
    _start(state).check_or_pin(PEER, FP)
    sealed_before = open(_sealed(state), "rb").read()
    _write_plain(state, {PEER: {"fingerprint": OTHER_FP, "trusted": False}})
    with pytest.raises(Exception) as caught:
        _start(state)
    assert type(caught.value).__name__ == "TrustUnavailable"
    assert _plain(state) in str(caught.value) and _sealed(state) in str(caught.value), \
        "both files are named"
    assert open(_sealed(state), "rb").read() == sealed_before
    assert json.load(open(_plain(state)))[PEER]["fingerprint"] == OTHER_FP


# -- what does not change -----------------------------------------------------

def test_irc_still_keeps_its_pins_in_memory_and_writes_nothing():
    d = tempfile.mkdtemp(prefix="otrv4plus-irc-trust-")
    cfg = otr.OTRConfig(trust_db_path=os.path.join(d, "trust.json"),
                        trust_dek_path=os.path.join(d, "trust", "trust.dek"))
    db = otr._open_trust_db(cfg)
    db.add_trust("someone", "AA" * 64)
    assert os.listdir(d) == [], "an IRC run wrote trust state"
    assert db.where() == "IN MEMORY ONLY"


def test_both_session_managers_open_trust_the_same_way():
    import inspect
    for cls in (otr.SessionManager, otr.EnhancedSessionManager):
        src = inspect.getsource(cls.__init__)
        assert "self.trust_db = _open_trust_db(self.config)" in src, cls.__name__


def test_the_trust_listing_says_where_the_pins_are(state):
    assert _start(state).where().startswith("sealed, ")
    d = tempfile.mkdtemp(prefix="otrv4plus-plain-trust-")
    assert otr.TrustDatabase(os.path.join(d, "t.json"), persistent=True).where().endswith("(plaintext)")
    import otrv4plus_xmpp_trust as T
    src = open(T.__file__, encoding="utf-8").read()
    assert "self.otr.trust_db.where()" in src


def test_the_terminal_pins_are_under_what_a_wipe_destroys(state):
    from android_bridge import wipe
    roots = [os.path.realpath(r) for r in wipe.python_state_roots()]
    sealed = os.path.realpath(_sealed(state))
    assert any(sealed.startswith(r + os.sep) for r in roots)


def test_a_terminal_started_from_client_alone_opens_its_sealed_pins():
    """`python otrv4plus_xmpp.py` has only client/ on its path; the engine
    must still reach android_bridge, or the terminal could not start."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    client = os.path.join(root, "client")
    d = tempfile.mkdtemp(prefix="otrv4plus-term-clean-")
    code = ("import sys; sys.path.insert(0, %r)\n" % client
            + "import otrv4plus as otr\n"
            + "cfg = otr.OTRConfig(persist_trust=True, trust_db_path=%r,\n"
              "                    trust_dek_path=%r)\n"
              % (os.path.join(d, "trust.json"), os.path.join(d, "trust", "trust.dek"))
            + "db = otr._open_trust_db(cfg); db.check_or_pin('bob@example.test', 'A1' * 56)\n"
            + "print(db.where())")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run([sys.executable, "-I", "-c", code], cwd="/", env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0 and "sealed, " in done.stdout, done.stderr[-2000:]
