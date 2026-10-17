# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A replaced controller can no longer touch the app (owner report,
2026-10-17: typing in the Welcome room, the connection fell over and did not
come back).

Every connect attempt builds a new ConnectionController; the old one was
simply dropped. Its transport's late "disconnected" -- or, now that the
server keeps one session per account, "replaced" -- still reached the SHARED
app and cleared the new connection's rooms and presence, or failed the
connection with signed_in_elsewhere. `retire()` stops that, and closes a
dead transport so its tunnel cannot linger.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile


class App:
    def __init__(self):
        self.presence_lost = 0
        self.rooms_forgotten = 0
        self._transport = None

    def set_event_sink(self, sink):
        pass

    def note_presence_lost(self):
        self.presence_lost += 1

    def forget_rooms(self):
        self.rooms_forgotten += 1


class Transport:
    def __init__(self, connected):
        self.is_connected = connected
        self.closed = False

    def close(self):
        self.closed = True
        self.is_connected = False


def _ctl(app):
    return ConnectionController(
        app, ConnectionProfile(jid="alice@otrv4plus.i2p"),
        transport_factory=lambda *a, **k: None,
        prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))


def test_a_retired_controllers_late_drop_touches_nothing():
    app = App()
    old = _ctl(app)
    old._transport = Transport(connected=False)
    old.retire()
    for state in ("disconnected", "replaced", "failed"):
        old._on_transport_state(state, "otrv4plus.i2p")
    assert app.presence_lost == 0 and app.rooms_forgotten == 0
    assert old.status()["last"].get("code") != "signed_in_elsewhere"


def test_its_dead_transport_is_closed_without_clearing_the_new_one():
    app = App()
    old = _ctl(app)
    dead = Transport(connected=False)
    old._transport = dead
    newer = Transport(connected=True)
    app._transport = newer                   # the new controller's
    old.retire()
    assert dead.closed
    assert app._transport is newer


def test_a_live_transport_is_not_disconnected_by_retiring():
    app = App()
    old = _ctl(app)
    live = Transport(connected=True)
    old._transport = live
    old.retire()
    assert not live.closed


def test_a_controller_that_was_not_retired_still_reports_drops():
    app = App()
    ctl = _ctl(app)
    ctl._on_transport_state("disconnected", "otrv4plus.i2p")
    assert app.rooms_forgotten == 1


def test_kotlin_retires_the_old_controller_before_building_one():
    kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                           "android/bridge/ChaquopyOtrCore.kt")).read()
    body = kt[kt.index("fun prepareConnection("):]
    body = body[:body.index("return connectionStatus()")]
    assert body.index('old.callAttr("retire")') < body.index('"controller_for"')
