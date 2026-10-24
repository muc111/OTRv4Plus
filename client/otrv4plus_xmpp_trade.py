# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's Monero tips and courier trades, inside the OTR session.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). The trade and tip logic is
otrv4plus_trade.py and otrv4plus_tip.py (docs/TRADE.md); this is the
`/trade`, `/tip`, `/tipreply` and `/setxmr` commands and the signals they
send to the peer."""
import otrv4plus_tip as _tip
import otrv4plus_trade as _trade
from otrv4plus_host import _xmpp_state_path
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)

TRADE_PREFIX = _trade.TRADE_PREFIX
TradeError = _trade.TradeError
TipError = _tip.TipError


class TradeMixin:
    """Tips and trades. Mixed into OTRv4PlusXMPP."""

    def _clear_trades(self, reason: str) -> int:
        """Forget every trade. Returns how many there were.

        Trade state is in memory only and never written to disk, so this is
        the whole of it. Called on disconnect, /quit, and by the same
        reasoning as the v10.19.0 scrollback purge (INV-24): what belonged to
        one session must not appear in the next.
        """
        mgr = self._trade_manager
        if mgr is None:
            return 0
        try:
            count = mgr.clear()
        except Exception:
            count = 0
        if count:
            print("[trade] dropped %d open trade(s) — %s" % (count, reason))
        # Peer addresses and unanswered tip requests belong to the session
        # too. Your own configured address is deliberately NOT cleared: it is
        # configuration, and it is on disk.
        if self._tip_manager is not None:
            try:
                self._tip_manager.clear()
            except Exception:
                pass
        return count

    def _peer_fingerprint(self, peer: str):
        """The peer's live fingerprint, or None.

        What binds a trade to a counterparty. Deliberately not the JID and
        deliberately not the I2P destination: destinations are TRANSIENT and
        change every session, and a JID is a name anyone can present.
        """
        try:
            getter = getattr(self.otr, "get_peer_fingerprint", None)
            if getter is None:
                return None
            return getter(peer)
        except Exception:
            return None

    def _send_trade_signal(self, peer: str, verb: str, payload: str) -> bool:
        """One trade control message inside the OTR channel.

        The same shape as `_send_file_signal`, and the same rule: if the
        encrypted channel is unavailable the message is DROPPED, never
        downgraded. A multisig blob sent in the clear would tell the server
        who is coordinating a trade with whom, and would let an off-session
        party inject a blob into someone's wallet.
        """
        body = TRADE_PREFIX + verb + ((":" + payload) if payload else "")
        try:
            frame, should_send = self.otr.handle_outgoing_message(peer, body)
        except Exception as exc:
            print("[trade] could not encrypt: %s" % _sanitise(str(exc), 120))
            return False
        if not (should_send and frame):
            print("[trade] dropped — OTR channel unavailable (trade messages "
                  "are never sent in the clear)")
            return False
        try:
            self.send_otr_fragmented(
                peer, frame if isinstance(frame, str) else frame.decode())
        except Exception as exc:
            print("[trade] send failed: %s" % _sanitise(str(exc), 120))
            return False
        return True

    def _send_tip_tlv(self, peer: str, payload: bytes) -> bool:
        """One TIP TLV inside the OTR channel.

        `send_tlv` is fail-closed: it will not open a session, will not
        queue, and will not fall back to plaintext, so a False here means
        there was no encrypted session and nothing went on the wire.
        """
        try:
            frame = self.otr.send_tlv(peer, _tip.TIP_TLV_TYPE, payload)
        except Exception as exc:
            print("[tip] could not encrypt: %s" % _sanitise(str(exc), 120))
            return False
        if not frame:
            return False
        try:
            self.send_otr_fragmented(
                peer, frame if isinstance(frame, str) else frame.decode())
        except Exception as exc:
            print("[tip] send failed: %s" % _sanitise(str(exc), 120))
            return False
        return True

    def _cmd_setxmr(self, args: str) -> None:
        """/setxmr <address> | clear — your own Monero address, persisted."""
        mgr = self._tip_manager
        if mgr is None:
            print("[tip] the tip subsystem is not ready yet")
            return
        self._tip_disclaim()
        args = (args or "").strip()
        try:
            if args.lower() == "clear":
                mgr.forget_address()
                print("[tip] address cleared — requests will no longer be "
                      "answered automatically")
                return
            saved = mgr.set_address(args)
            print("✅ [tip] XMR address saved: %s" % saved)
            print("[tip] verified peers who /tip you now get it "
                  "automatically. Stored 0600 in %s — your address next to "
                  "your OTR identity links the two for anyone who reads that "
                  "disk." % _xmpp_state_path("xmr.json"))
        except TipError as exc:
            print("[tip] %s" % exc)

    def _cmd_tip(self, peer: str, args: str) -> None:
        """/tip [amount [note]] — ask a verified peer where to send it."""
        mgr = self._tip_manager
        if mgr is None:
            print("[tip] the tip subsystem is not ready yet")
            return
        self._tip_disclaim()
        args = (args or "").strip()
        try:
            if not args:
                for line in mgr.status():
                    print(line)
                return
            if not peer:
                print("[tip] no peer selected — /otr <jid> first")
                return
            amount, _, note = args.partition(" ")
            mgr.request(peer, amount, note)
        except TipError as exc:
            print("[tip] %s" % exc)

    def _cmd_tipreply(self, peer: str) -> None:
        """/tipreply — answer a request that arrived before /setxmr.

        The explicit local action that stands in for the interactive prompt
        a peer must not be able to trigger (INV-06).
        """
        mgr = self._tip_manager
        if mgr is None:
            print("[tip] the tip subsystem is not ready yet")
            return
        if not peer:
            print("[tip] no peer selected — /otr <jid> first")
            return
        try:
            mgr.reply(peer)
        except TipError as exc:
            print("[tip] %s" % exc)

    def _tip_disclaim(self) -> None:
        if not self._tip_disclaimed:
            print(_tip.DISCLAIMER)
            self._tip_disclaimed = True

    def _cmd_trade(self, peer: str, args: str) -> None:
        """/trade [init <terms> | accept | decline | blob <b64> | confirm |
        cancel] — the courier command surface.

        Bare /trade shows status. Everything else needs an SMP-verified peer,
        which the manager enforces on every call rather than here: a check in
        the command handler protects only the commands, and inbound messages
        do not come through here.
        """
        mgr = self._trade_manager
        if mgr is None:
            print("[trade] the trade subsystem is not ready yet")
            return
        if not self._trade_disclaimed:
            print(_trade.DISCLAIMER)
            self._trade_disclaimed = True

        args = (args or "").strip()
        sub, _, rest = args.partition(" ")
        sub = sub.strip().lower()
        rest = rest.strip()

        try:
            if not sub or sub == "status":
                for line in mgr.status():
                    print(line)
                return
            if not peer:
                print("[trade] no peer selected — start a session with /otr "
                      "<jid> first")
                return
            if sub == "init":
                mgr.start(peer, rest)
            elif sub == "accept":
                mgr.accept(peer)
            elif sub == "decline":
                mgr.decline(peer, rest)
            elif sub == "cancel":
                mgr.cancel(peer, rest)
            elif sub == "blob":
                mgr.send_blob(peer, rest)
            elif sub == "confirm":
                mgr.confirm(peer, rest)
            else:
                print("[trade] unknown subcommand %s — try /trade, /trade "
                      "init <terms>, accept, decline, blob <base64>, "
                      "confirm, cancel" % _sanitise(sub, 32))
        except TradeError as exc:
            print("[trade] %s" % exc)
        except Exception as exc:
            print("[trade] failed: %s" % type(exc).__name__)
