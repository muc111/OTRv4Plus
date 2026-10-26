# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""L1: the process is killed between retire_all and the server's confirmation.

A real child process runs two apps over the wire harness. Alice presses Make
Chat Deniable: retire_all runs, the closing messages are made, and the
server never confirms them. Her transport holds the frames in its send
buffer, as slixmpp's queue would, and the server does not answer the ping.
The app reports the close as unconfirmed, and then the process is killed
with SIGKILL before any re-send. That is the window SECURITY_ISSUES.md L1
names.

What must hold, and what honestly does not:
  * on the next launch no MAC key is held: none in the new process, none on
    disk under the app's home;
  * the next launch re-sends nothing: the closing messages lived in memory
    only. That is deliberate: persisting them would leave a record, on the
    device, of whom you just made a chat deniable with;
  * the transcript of that close is STILL PROVABLE: every line whose key the
    lost closing messages carried stays verifiable from the wire. The
    residual, asserted rather than hidden.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

import pytest

pytest.importorskip("otrv4_core")

import test_deniability_wire_audit as W                         # noqa: E402
from test_deniability_wire_audit import _own_rate_limiter       # noqa: E402,F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import json, os, sys, time
root, out = sys.argv[1], sys.argv[2]
sys.path[:0] = [os.path.join(root, "tests"), os.path.join(root, "client"), root]
import conftest                                    # the test environment's stubs
import test_deniability_wire_audit as W

wire, alice, bob = W._pair()

class Buffering(W.Link):
    """The socket's send buffer: the closing frames are queued, not sent,
    and the server never answers the ping."""
    buffering = False
    queued = []
    def send(self, peer, payload):
        if self.buffering:
            self.queued.append(payload)
            return
        super().send(peer, payload)
    def confirm_received(self, timeout=15.0):
        time.sleep(0.2)
        return False

t = Buffering(wire, W.ALICE)
alice._transport = t
lines = W._talk(wire, alice, bob, W.SCRIPT)
json.dump(lines, open(os.path.join(out, "lines.json"), "w"))
t.buffering = True
result = alice.make_chat_deniable(W.BOB, restart=False)
keys = sorted({bytes(k).hex() for body in t.queued
               for k in (W._data(body).revealed_mac_keys if W._data(body) else [])})
json.dump(keys, open(os.path.join(out, "oracle.json"), "w"))   # test-only knowledge
# Everything that left a device, from the handshake on (the closing frames
# never did: they are in the send buffer).
json.dump(wire.frames, open(os.path.join(out, "wire.json"), "w"))
print("REPORTED", result, len(alice._closings()), flush=True)
time.sleep(600)                                    # idle, before any re-send tick
'''


@pytest.fixture(scope="module")
def killed():
    home, out = tempfile.mkdtemp(), tempfile.mkdtemp()
    env = dict(os.environ, HOME=home, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, "-c", CHILD, ROOT, out], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = ""
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line.startswith("REPORTED") or not line:
            break
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=30)
    if not line.startswith("REPORTED"):
        pytest.fail("child did not reach the close: %s" % proc.stderr.read()[-2000:])
    frames = [tuple(f) for f in json.load(open(os.path.join(out, "wire.json")))]
    return {"home": home, "report": line.split(), "frames": frames,
            "lines": json.load(open(os.path.join(out, "lines.json"))),
            "oracle": [bytes.fromhex(k) for k in json.load(open(os.path.join(out, "oracle.json")))],
            "returncode": proc.returncode}


class TestCrashDuringClose:
    def test_it_was_killed_after_reporting_the_close_unconfirmed(self, killed):
        assert killed["returncode"] == -signal.SIGKILL
        _tag, result, kept = killed["report"]
        assert result == "made_deniable_unconfirmed", "the app said it is not confirmed"
        assert int(kept) > 0, "the closing messages were waiting to be re-sent"
        assert killed["oracle"], "the close had keys to publish"

    def test_no_mac_key_is_on_disk_after_the_kill(self, killed):
        """Raw, hex, or inside a closing frame written as wire text (base64,
        where a key is not findable as a substring; audit 2026-10-26: the
        raw-and-hex check alone let a persisted frame through)."""
        hits = []
        for base, _dirs, files in os.walk(killed["home"]):
            for name in files:
                with open(os.path.join(base, name), "rb") as fh:
                    data = fh.read()
                for k in killed["oracle"]:
                    if k in data or k.hex().encode() in data:
                        hits.append(name)
                for frame in re.findall(rb"\?OTRv4 [A-Za-z0-9_\-=]+\.?", data):
                    msg = W._data(frame.decode("ascii"))
                    keys = [bytes(k) for k in (msg.revealed_mac_keys if msg else [])]
                    if any(k in killed["oracle"] for k in keys):
                        hits.append(name + " (a closing frame)")
        assert hits == [], "a MAC key reached the disk: %r" % hits

    def test_the_next_launch_holds_no_key_and_re_sends_nothing(self, killed, monkeypatch):
        """A new process over the same home: nothing of the old one carried."""
        from android_bridge.app import OtrApp
        monkeypatch.setenv("HOME", killed["home"])
        app = OtrApp(W.E._manager(), W.Link(W.Wire(), W.ALICE))
        assert app._closings() == [], "nothing to re-send: it lived in memory"
        assert app._engine.sessions == {}, "no session, so no ratchet, so no MAC key"

    def test_residual_the_transcript_of_an_unconfirmed_close_is_still_provable(self, killed):
        """Every line whose key the lost closing messages carried stays
        verifiable from the wire: exactly those, no more, no fewer."""
        wire = W.Wire()
        wire.frames = killed["frames"]
        lines = killed["lines"]
        _keys, missing = W._audit(wire, lines)
        assert missing, "provable: the claim does not hold for this close"
        oracle = killed["oracle"]
        would_have_covered = [i for i in lines
                              if W._key_for(W._data(wire.frames[i][2]), oracle)]
        assert missing == would_have_covered, "the gap is exactly the lost closing messages"
