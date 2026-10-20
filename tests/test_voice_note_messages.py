# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A voice note is a message, not a file (owner, 2026-10-20: "voice notes
should be auto accepted" ... "i should be able to play back any voice note
i sent and same as received").

On the wire nothing changes: it is still an encrypted file transfer, behind
the same verification gate. What changes is on each end:

* an offered note is accepted without asking, and a finished one raises
  `VoiceNoteReceived` with the sealed copy's path, 1:1 and in a group;
* only a name the recorder makes (voice-note-*.ogg / .wav), no bigger than a
  note can be, counts; any other file still asks;
* a sent note keeps a sealed copy for playback, and a refused one keeps
  nothing.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ft = pytest.importorskip("otrv4plus_filetransfer")

from android_bridge import files as files_mod                    # noqa: E402
from android_bridge.events import FileTransferChanged, VoiceNoteReceived  # noqa: E402

S = ft.TransferState


class _App:
    def __init__(self):
        self.events = []

    def _emit(self, event):
        self.events.append(event)


def _bridge(monkeypatch):
    monkeypatch.setattr(files_mod, "_later", lambda fn: fn())
    app = _App()
    bridge = files_mod.FileBridge(app)

    class _Mgr:
        outgoing, incoming = {}, {}
    bridge._manager = _Mgr()
    accepted = []
    monkeypatch.setattr(bridge, "accept", lambda key: accepted.append(key) or "started")
    return app, bridge, accepted


def _incoming(name, size, state, final_path=None):
    offer = ft.Offer(transfer_id=b"\x09" * 16, filename=name, plaintext_size=size,
                     encrypted_size=size + 64, chunk_count=1,
                     encrypted_sha256=b"\0" * 32, plaintext_sha256=b"\0" * 32,
                     envelope=b"e")
    t = ft.IncomingTransfer(peer="bob@notes.test", offer=offer)
    t.state, t.reason = state, ""
    t.final_path = final_path
    return t


def test_an_offered_voice_note_is_accepted_without_asking(monkeypatch):
    app, bridge, accepted = _bridge(monkeypatch)
    bridge._on_state(_incoming("voice-note-0a1b2c.ogg", 9000, S.OFFERED), False)
    assert accepted == [("09" * 16)]
    assert [type(e) for e in app.events] == [FileTransferChanged]


def test_a_finished_voice_note_is_a_message_with_its_sealed_copy(monkeypatch):
    app, bridge, _ = _bridge(monkeypatch)
    bridge._on_state(_incoming("voice-note-0a1b2c.ogg", 9000, S.RECEIVED,
                               "/state/voice-note-0a1b2c.ogg.otrv"), False)
    note = [e for e in app.events if isinstance(e, VoiceNoteReceived)]
    assert len(note) == 1
    assert note[0].peer == "bob@notes.test"
    assert note[0].transfer_id == "09" * 16
    assert note[0].path == "/state/voice-note-0a1b2c.ogg.otrv"


@pytest.mark.parametrize("name,size", [
    ("holiday.ogg", 9000),                       # not a name the recorder makes
    ("voice-note-0a1b2c.exe", 9000),             # not audio
    ("voice-note-0a1b2c.ogg", 64 * 1024 * 1024),  # bigger than a note can be
    ("voice-note-0a1b2c.ogg", 0),
])
def test_anything_else_still_asks(monkeypatch, name, size):
    app, bridge, accepted = _bridge(monkeypatch)
    bridge._on_state(_incoming(name, size, S.OFFERED), False)
    bridge._on_state(_incoming(name, size, S.RECEIVED, "/state/x.otrv"), False)
    assert accepted == []
    assert not any(isinstance(e, VoiceNoteReceived) for e in app.events)


def test_our_own_outgoing_note_is_never_accepted_or_announced(monkeypatch):
    app, bridge, accepted = _bridge(monkeypatch)
    t = _incoming("voice-note-0a1b2c.ogg", 9000, S.OFFERED)
    bridge._on_state(t, True)
    assert accepted == []
    assert not any(isinstance(e, VoiceNoteReceived) for e in app.events)


def test_a_group_members_note_is_accepted_and_announced_with_its_sender(monkeypatch):
    from android_bridge import group_files as gf
    monkeypatch.setattr(files_mod, "_later", lambda fn: fn())
    events = []
    class _Groups:
        def set_file_handler(self, fn):
            pass
    g = gf.GroupFiles(groups=_Groups(), emit=events.append)
    accepted = []
    monkeypatch.setattr(g, "accept", lambda tid: accepted.append(tid) or True)
    inc = gf._In(room="team@rooms.test", tid="t1", sender="carol@notes.test",
                 name="voice-note-aa.ogg", size=5000, chunks=1, sha="0" * 64, at=0.0)
    g._changed_in(inc)
    assert accepted == ["t1"]
    inc.state, inc.path = "received", "/state/voice-note-aa.ogg.otrv"
    g._changed_in(inc)
    (note,) = [e for e in events if isinstance(e, VoiceNoteReceived)]
    assert (note.peer, note.sender, note.path) == ("team@rooms.test", "carol@notes.test",
                                                   "/state/voice-note-aa.ogg.otrv")
    other = gf._In(room="team@rooms.test", tid="t2", sender="carol@notes.test",
                   name="report.pdf", size=5000, chunks=1, sha="0" * 64, at=0.0)
    g._changed_in(other)
    assert accepted == ["t1"]


def test_a_sent_note_keeps_a_copy_and_a_refused_one_keeps_nothing(monkeypatch):
    import pathlib
    import tempfile
    from android_bridge.app import OtrApp
    from android_bridge.files import FileOutcome
    # Not pytest's tmp_path: conftest stubs pwd, which tmp_path needs.
    kept = pathlib.Path(tempfile.mkdtemp()) / "voice-note-sent-x.ogg.otrv"

    def keep(path):
        kept.write_bytes(b"sealed")
        return str(kept)
    monkeypatch.setattr(files_mod, "keep_sent_note", keep)
    app = OtrApp.__new__(OtrApp)

    app.send_file = lambda peer, path, strip=False: FileOutcome.STARTED
    assert app.send_voice_note("bob@notes.test", "/cache/voice-note-x.ogg") == {
        "outcome": "started", "path": str(kept)}
    assert kept.exists()

    app.send_file = lambda peer, path, strip=False: FileOutcome.UNVERIFIED
    assert app.send_voice_note("bob@notes.test", "/cache/voice-note-x.ogg") == {
        "outcome": "unverified", "path": ""}
    assert not kept.exists()


def test_keep_sent_note_refuses_anything_but_a_note():
    assert files_mod.keep_sent_note("/etc/passwd") == ""


def test_the_desktop_host_can_send_one():
    from desktop_bridge.host import APP_OPS
    assert APP_OPS["send_voice_note"] == ("peer", "path")
