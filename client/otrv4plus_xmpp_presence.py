# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's view of other people: presence, receipts, subscriptions.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). Who is online, when a peer
has gone (and their OTR session with them), delivery receipts, contact
requests, and the bounced messages the server returns."""
import asyncio
import time

import otrv4plus_caps as _caps
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)


def _room_presence(client, presence):
    fn = getattr(client, "_is_room_presence", None)
    return bool(fn(presence)) if fn is not None else False


class PresenceMixin:
    """Presence, receipts and subscriptions. Mixed into OTRv4PlusXMPP."""

    def _on_message_error(self, msg):
        peer = msg["from"].bare
        condition = msg["error"]["condition"]
        text = msg["error"]["text"] or condition
        groups = getattr(self, "_groups", None)
        if groups is not None:
            try:
                if groups.on_room_rejected(peer):
                    return
            except Exception:
                pass
        print(f"\n[delivery rejected] to {_sanitise(peer, 128)}: {_sanitise(text)}")
        if condition == "forbidden":
            print(
                "  -> not mutually subscribed; both accounts must accept each "
                "other as contacts.\n"
            )
            return
        # The server telling us it will not route to that domain is a
        # definitive answer about the address, not a transient failure. On a
        # device this was printed once, unexplained, and then the run carried
        # on for several minutes looking like a protocol bug -- while every
        # message to that peer was being dropped at the server.
        blob = ("%s %s" % (condition, msg["error"]["text"] or "")).lower()
        if ("remote-server" in blob or "remote domains" in blob
                or "remote server" in blob):
            print("  -> the server will not route to %s at all."
                  % _sanitise(peer.partition("@")[2] or peer, 128))
            if self.boundjid is not None:
                mine = self.boundjid.bare.partition("@")[2]
                theirs = peer.partition("@")[2]
                if mine and theirs and mine != theirs:
                    print("  -> you are on %s and --peer is on %s."
                          % (_sanitise(mine, 128), _sanitise(theirs, 128)))
                    if mine.startswith(theirs):
                        print("  -> --peer looks truncated. Did you mean %s%s ?"
                              % (_sanitise(peer, 128),
                                 _sanitise(mine[len(theirs):], 64)))
            print("  -> nothing sent to this address will arrive. Restart with "
                  "the corrected --peer.\n")

    def _on_delivery_receipt(self, receipt):
        """XEP-0184: fired when a peer acknowledges delivery of our message."""
        try:
            peer = receipt["from"].bare
            msg_id = receipt.get("id", "?")
            print(f"[receipt] delivered to {_sanitise(peer, 128)} (id {msg_id})")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Presence handling
    # -------------------------------------------------------------------------

    def _on_subscribe(self, presence):
        """Gate subscription requests; never auto-approve."""
        peer = presence["from"].bare
        self._pending_subscriptions[peer] = presence
        print(f"[sub] {_sanitise(peer, 128)} requests subscription.")
        print(f"[sub] Type  /accept {peer}  to approve or  /deny {peer}  to reject.")

    def _on_subscribed(self, presence):
        peer = presence["from"].bare
        print(f"[sub] {_sanitise(peer, 128)} approved our subscription")
        self.send_presence(pto=peer)

    MUC_USER_NS = "http://jabber.org/protocol/muc#user"

    def _is_room_presence(self, presence):
        """A presence from a ROOM occupant (`room@service/nick`), not a
        contact: never "online", never a peer to start OTRv4+ with. A device
        saw the client start a handshake with the room itself, which the
        server refused (service-unavailable). As on Android
        (`XmppTransport._is_room_presence`)."""
        try:
            if presence.xml.find("{%s}x" % self.MUC_USER_NS) is not None:
                return True
        except Exception:
            pass
        groups = getattr(self, "_groups", None)
        try:
            return bool(groups is not None
                        and groups.owns_room(str(presence["from"].bare)))
        except Exception:
            return False

    def _note_own_session(self, presence, online: bool) -> None:
        """Another session of OUR account (owner, 2026-10-16: signed in as
        alice here while alice was signed in on the phone, and nothing said
        so). The server sends us our other resources' presence."""
        resource = str(presence["from"].resource or "")
        if not resource or resource == str(self.boundjid.resource or ""):
            return
        seen = self.__dict__.setdefault("_own_sessions", set())
        if online and resource not in seen:
            seen.add(resource)
            print("[account] WARNING: this account is also signed in on "
                  "another device (resource %s)." % _sanitise(resource, 64))
            print("[account] If that is not you, change the password now. "
                  "A server admin can sign it out with")
            print("[account]   /admin end-user-session   and the full JID "
                  "%s/%s" % (_sanitise(self._own_bare, 128),
                             _sanitise(resource, 64)))
        elif not online and resource in seen:
            seen.discard(resource)
            print("[account] the other session (%s) signed out."
                  % _sanitise(resource, 64))

    def _on_presence_available(self, presence):
        peer = presence["from"].bare
        if peer == self._own_bare:
            try:
                self._note_own_session(presence, True)
            except Exception:
                pass
            return
        if _room_presence(self, presence):
            return
        show = presence["show"] or "available"
        status = presence["status"] or ""
        status_s = f" ({_sanitise(status, 64)})" if status else ""
        print(f"[presence] {_sanitise(peer, 128)} is {show}{status_s}")
        resources = self._peer_resources.setdefault(peer, set())
        if len(resources) < 16:
            resources.add(str(presence["from"].resource or ""))
        self._peer_is_alive(peer)
        try:
            node = str(presence["caps"]["node"] or "")
        except Exception:
            node = ""
        ready = getattr(self, "_presence_ready", None)
        if ready is None or not hasattr(self, "_otr_capable"):
            return                       # a partial client (tests)
        if node == _caps.CAPS_NODE:
            self._otr_capable.add(str(peer))
        ready(str(peer))

    def _on_presence_unavailable(self, presence):
        """One RESOURCE went away; the peer is gone only when none is left.

        Every app launch signs in as a new resource and, over I2P, the server
        times the previous session out minutes later. Treating that late
        `unavailable` as "the peer left" reported a live contact offline and
        armed the abandoned-session teardown on a session in use (device
        report, 2026-09-24).
        """
        peer = presence["from"].bare
        if peer == self._own_bare:
            try:
                self._note_own_session(presence, False)
            except Exception:
                pass
            return
        if _room_presence(self, presence):
            # XEP-0045 §10.9: the owner destroyed the room. For a secure
            # group that is its deletion.
            try:
                gone = presence.xml.find("{%s}x/{%s}destroy" % (
                    self.MUC_USER_NS, self.MUC_USER_NS)) is not None
            except Exception:
                gone = False
            groups = getattr(self, "_groups", None)
            if gone and groups is not None:
                try:
                    groups.groups.on_room_destroyed(str(peer).lower())
                except Exception:
                    pass
            return
        resource = str(presence["from"].resource or "")
        resources = self._peer_resources.get(peer, set())
        if resource:
            resources.discard(resource)
        else:
            resources.clear()
        if resources:
            return                       # another resource is still online
        self._peer_resources.pop(peer, None)
        print(f"[presence] {_sanitise(peer, 128)} went offline")
        self._arm_peer_gone(peer)

    # -------------------------------------------------------------------------
    # Abandoned OTR sessions
    # -------------------------------------------------------------------------
    #
    # A ratchet is shared state. When the peer's client exits, its half is
    # gone; ours is not, so the next /otr found a live session on our side
    # only, and the DAKE it tried to start went nowhere. start_otr already
    # force-resets a stuck session, but only after a failed attempt the user
    # has to notice and interpret.
    #
    # The trigger is a peer that goes offline and stays offline. It is
    # deliberately NOT "the peer went offline", because that fires constantly
    # for reasons that have nothing to do with the peer: our own stream
    # dropping produces the same presence, and this client reconnects often
    # enough over I2P that tearing down a verified session on a blip would be
    # far worse than the problem being fixed. So the timer is cancelled by
    # anything that proves the peer is still there, and by our own reconnects.

    PEER_GONE_SECONDS = 180

    def _peer_is_alive(self, peer: str) -> None:
        """Any sign of life cancels a pending teardown."""
        self._peer_gone_at.pop(peer, None)

    def _arm_peer_gone(self, peer: str) -> None:
        if peer not in self._encrypted:
            return                       # nothing to clear
        self._peer_gone_at[peer] = time.monotonic()
        self._start_peer_gone_sweeper()

    def _clear_peer_gone(self, why: str = "") -> None:
        """Forget every pending teardown.

        Called when OUR transport drops. The peers looked absent because we
        were, and their sessions are fine.
        """
        if self._peer_gone_at:
            self._peer_gone_at.clear()
        # What we knew about their resources went with our stream.
        getattr(self, "_peer_resources", {}).clear()

    def _start_peer_gone_sweeper(self) -> None:
        task = self._peer_gone_task
        if task is not None and not task.done():
            return
        try:
            loop = asyncio.get_event_loop()
            self._peer_gone_task = loop.create_task(self._peer_gone_sweeper())
        except Exception:
            self._peer_gone_task = None

    async def _peer_gone_sweeper(self) -> None:
        try:
            while not self._shutting_down and self._peer_gone_at:
                await asyncio.sleep(15)
                now = time.monotonic()
                for peer, since in list(self._peer_gone_at.items()):
                    if now - since < self.PEER_GONE_SECONDS:
                        continue
                    if self._peer_in_call(peer):
                        # Media does not use XMPP, so a call can be healthy
                        # while presence says otherwise. Ending OTR here would
                        # take the rekey and END signalling with it.
                        self._peer_gone_at[peer] = now
                        continue
                    self._peer_gone_at.pop(peer, None)
                    self._forget_otr(peer, "offline for %ds"
                                     % self.PEER_GONE_SECONDS)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            print("[otr] session sweeper stopped: %s" % _sanitise(str(exc), 80))

    def _peer_in_call(self, peer: str) -> bool:
        manager = self._voice_manager
        if manager is None:
            return False
        try:
            return bool(manager.has_active_call(peer))
        except Exception:
            return False
