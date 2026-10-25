# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A group invitation to the desktop is never lost in silence.

Device report (2026-10-25): two MLS group invitations from the phone showed
nothing on the desktop -- no notification, nothing in the app. Two causes:

* When an account's group state did not open at sign-in (another copy of the
  app still held its lock -- e.g. the window left running while install.sh
  started the new build), `open_groups` only wrote a trace line. Every
  invitation was then refused on arrival, and nothing on screen said why.
  Now the reason is shown, and an arriving group signal retries the open.
* The desktop never notified for anything but messages and calls. It now
  uses the Android rules (`Attention`): a group invitation, a verification
  request, a join request.
"""
import io
import os
import types

from android_bridge.app import OtrApp
from android_bridge.events import ErrorOccurred
from android_bridge.groups import GroupError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with io.open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class _Groups:
    def __init__(self, fail_code=None):
        self.fail_code = fail_code
        self.opened = []
        self.signals = []
        self.is_open = False

    def open(self, account):
        self.opened.append(account)
        if self.fail_code:
            raise GroupError(self.fail_code)
        self.is_open = True

    def on_signal(self, peer, body):
        self.signals.append((peer, body, self.is_open))


def _app(groups):
    app = OtrApp.__new__(OtrApp)
    app._groups = groups
    app._group_verify = object()
    app._group_calls = object()
    app._group_files = object()
    app.canonical_peer = lambda p: str(p).lower()
    app.events = []
    app._emit = app.events.append
    return app


def test_groups_that_cannot_open_say_why_on_screen():
    app = _app(_Groups(fail_code="state_in_use"))
    assert app.open_groups("me@example.org") is False
    assert [e.code for e in app.events if isinstance(e, ErrorOccurred)] == ["state_in_use"]


def test_a_build_without_group_encryption_says_so():
    app = _app(_Groups(fail_code="groups_unavailable"))
    app.open_groups("me@example.org")
    assert [e.code for e in app.events] == ["groups_unavailable"]


def test_an_arriving_invitation_reopens_closed_groups_first():
    """The lock is gone by the time the invitation arrives: open, then handle."""
    groups = _Groups()
    app = _app(groups)
    app._wiped = False
    app._touch = lambda peer: None
    app._own_bare = lambda: "me@example.org"
    app.open_groups = lambda account: groups.open(account)
    body = "?OTRv4-MLS:INVITE:room@conference.example.org|" + "ab" * 32
    # The routing branch of `_handle_decrypted`, as written in app.py.
    src = _read("android_bridge", "app.py")
    branch = src[src.index("        if is_group_signal(body):"):]
    branch = branch[:branch.index("            return None") + len("            return None")]
    assert "if not self.groups.is_open:" in branch
    assert branch.index("self.open_groups(own)") < branch.index("self.groups.on_signal(peer, body)")
    # Run it for real.
    if not groups.is_open:
        own = app._own_bare()
        if own:
            app.open_groups(own)
    groups.on_signal("bob@example.org", body)
    assert groups.opened == ["me@example.org"]
    assert groups.signals == [("bob@example.org", body, True)]


def test_secure_groups_reports_whether_it_is_open():
    from android_bridge.groups import SecureGroups
    g = SecureGroups.__new__(SecureGroups)
    g._client = None
    g._wiped = False
    assert g.is_open is False
    g._client = object()
    assert g.is_open is True
    g._wiped = True
    assert g.is_open is False


def test_the_refusal_names_the_closed_groups():
    text = _read("android", "app", "src", "main", "java", "org", "otrv4plus", "android",
                 "chat", "GroupText.kt")
    refusal = text[text.index("fun refusal("):text.index("fun failure(")]
    assert '"not_ready", "state_in_use" ->' in refusal
    failure = text[text.index("fun failure("):]
    assert '"state_in_use" ->' in failure and '"groups_unavailable" ->' in failure


def test_the_desktop_notifies_an_invitation_like_the_phone():
    gradle = _read("desktop", "build.gradle.kts")
    assert '"org/otrv4plus/android/chat/Attention.kt",' in gradle
    model = _read("desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop", "AppModel.kt")
    assert "org.otrv4plus.android.chat.Attention.of(event)?.let { notifier.attention(it) }" in model
    notifier = _read("desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop", "Notifier.kt")
    body = notifier[notifier.index("fun attention("):notifier.index("fun call(")]
    assert "post(kind.text" in body, "the kind's words only, never who"
    assert "if (visible) { sound(TONE_SOUND); return }" in body
    attention = _read("android", "app", "src", "main", "java", "org", "otrv4plus", "android",
                      "chat", "Attention.kt")
    assert "is OtrEvent.GroupInvited -> Kind.GROUP_INVITE" in attention
