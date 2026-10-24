# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's file transfer and voice notes, inside the OTR session.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). The transfer protocol and its
keys are otrv4plus_filetransfer.py; this is the `/sendfile`, `/voice` and
`/transfer` commands, the metadata question asked before a file goes, and
the quick y/n answers files and calls share."""
import asyncio
import os
import time

import otrv4plus_alerts as _alerts
import otrv4plus_filetransfer as _filetransfer
import otrv4plus_host as _host
from otrv4plus_host import _run, _which
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)

FILE_PREFIX = _filetransfer.FILE_PREFIX
TransferError = _filetransfer.TransferError

#: Outbound pacing for file chunks, in fragments per second.
#:
#: Kept well under `_RATE_MAX_BULK / _RATE_WINDOW` (24/s, otrv4plus_xmpp.py)
#: so ordinary chat, SMP and keepalives still fit inside the receiver's
#: budget alongside a running transfer -- a sender that exactly fills the
#: budget starves them.
_FILE_FRAGMENTS_PER_SEC = 8.0


class FilesMixin:
    """Files and voice notes. Mixed into OTRv4PlusXMPP."""

    # -- file transfer ----------------------------------------------------

    def _send_file_signal(self, peer: str, verb: str, payload: str) -> bool:
        """The Phase A byte pump: one control message inside the OTR channel.

        Identical in shape to the voice manager's `_signal`, and for the same
        reason -- an offer or a chunk sent in the clear would tell the server
        who is sending what to whom, and would let an off-session party inject
        a transfer.  If OTR is unavailable the frame is dropped rather than
        downgraded.

        This is the ONLY thing tying the transfer engine to XMPP.  Replacing
        it with a SAM-stream writer is the whole of a future transport swap.
        """
        body = FILE_PREFIX + verb + ((":" + payload) if payload else "")
        try:
            frame, should_send = self.otr.handle_outgoing_message(peer, body)
        except Exception as exc:
            print("[file] could not encrypt: %s" % _sanitise(str(exc), 120))
            return False
        if not (should_send and frame):
            print("[file] dropped — OTR channel unavailable (file transfer is "
                  "never sent in the clear)")
            return False
        try:
            self.send_otr_fragmented(
                peer, frame if isinstance(frame, str) else frame.decode())
        except Exception as exc:
            print("[file] could not send: %s" % _sanitise(str(exc), 120))
            return False
        return True

    def _start_file_pump(self, transfer) -> None:
        """Send an accepted transfer without standing on the event loop.

        `on_accept` is reached from inside the inbound message handler, which
        runs on the loop.  The engine's own pump sends every chunk in one
        unbroken run, so calling it here meant a 340 KB file encrypted and
        pushed a hundred stanzas with nothing else getting a turn: keepalives
        could not run, the stream was declared dead, and the transfer took the
        connection down with it.  A device test showed the disconnect; it read
        like a network problem and was not one.

        So: one chunk per turn, with a real pause between.  The pause is not
        politeness -- it keeps the send rate inside the receiver's budget (see
        `_RATE_MAX_BULK`), which is the other half of why the first real
        transfer failed.  Sends stay on the loop thread rather than moving to
        an executor, because slixmpp's writer is not ours to call from another
        thread.
        """
        async def _run():
            mgr = self._file_manager
            if mgr is None:
                return
            while True:
                self._file_fragments_sent = 0
                try:
                    more = mgr.pump_step(transfer)
                except Exception as exc:
                    print("[file] send failed: %s" % _sanitise(str(exc), 160))
                    return
                if not more:
                    return
                # Pace on what actually went out.  A chunk that fragmented
                # into five stanzas costs five stanzas of budget; one that
                # fitted in a single frame costs one.
                sent = max(1, self._file_fragments_sent)
                await asyncio.sleep(sent / _FILE_FRAGMENTS_PER_SEC)

        asyncio.ensure_future(_run())

    def _file_peer_verified(self, peer: str) -> bool:
        """File transfer requires the same cryptographic gate voice does.

        Reads the voice manager's `_smp_verified`, which consults only the
        engine's published predicates -- not display state, not a trust pin,
        not the blue OTRv4+ marker.  One gate, one definition of verified.
        """
        try:
            if self._voice_manager is None:
                return False
            return bool(self._voice_manager._smp_verified(peer))
        except Exception:
            return False

    def _file_transfer_ratchet(self, peer: str):
        """The peer's live RustDoubleRatchet, or None.

        The transfer key is derived from it inside Rust; Python only passes
        the handle along and never sees anything derived from it.
        """
        try:
            session = self.otr.get_session(peer)
            ratchet = getattr(session, "ratchet", None)
            rust = getattr(ratchet, "_rust", None)
            if rust is None or not rust.supports_file_transfer:
                return None
            return rust
        except Exception:
            return None

    def _cmd_sendfile(self, peer, path: str) -> None:
        """/sendfile [path] — a path, or nothing to open the Android picker.

        To a contact over OTRv4+, or -- while talking to a secure group -- to
        the whole group over MLS (android_bridge.group_files). Either way the
        file is examined first and, if it carries hidden information (where
        and when a photo was taken, the camera), the user answers y/n: remove
        it, or send the original (owner request, 2026-10-11)."""
        groups = getattr(self, "_groups", None)
        group = bool(peer and groups is not None and groups.owns_room(peer))
        if not group and self._file_manager is None:
            print("[file] the transfer subsystem is not ready yet")
            return
        if not peer:
            print("[file] open a chat with a peer first")
            return
        if not group and self._file_transfer_ratchet(peer) is None:
            print("[file] no OTR session with %s that can key a transfer — "
                  "run /otr first" % _sanitise(peer, 128))
            return
        if not path and not _host.IS_TERMUX:
            print("usage: /sendfile <path>")
            return

        def _waiting():
            # termux-storage-get returns the moment it has handed the intent
            # over, so from here the client is watching a directory, not a
            # process.  Say so: the alternative is a silent pause for as long
            # as the gallery is open, which reads as a hang.
            print("[file] waiting for your choice — the picker is open on the "
                  "phone (up to %d s; backing out waits that long)"
                  % int(_filetransfer.PICKER_TIMEOUT_S))

        async def _run():
            loop = asyncio.get_event_loop()
            staged = None
            chosen = os.path.expanduser(path) if path else ""
            if not path:
                print("[file] opening the Android file picker — choose a file "
                      "on the phone")
                # Blocking, and it waits for a human scrolling a gallery:
                # off the event loop.
                try:
                    staged = await loop.run_in_executor(
                        None, lambda: _filetransfer.pick_file(which=_which,
                                                              on_wait=_waiting))
                except TransferError as exc:
                    print("[file] %s" % exc)
                    return
                except Exception as exc:
                    print("[file] could not pick a file: %s"
                          % _sanitise(str(exc), 160))
                    return
                chosen = staged

            def discard():
                # The staged copy is PLAINTEXT.  It goes as soon as it has
                # been sealed, refused, or the user said cancel.
                if staged:
                    try:
                        os.unlink(staged)
                    except OSError:
                        pass

            def go(strip: bool):
                asyncio.ensure_future(self._offer_file(
                    peer, chosen, strip, group=group, picked=not path,
                    discard=discard))

            self.confirm_metadata(chosen, go, on_cancel=discard)

        asyncio.ensure_future(_run())

    def _cmd_voice(self, peer, args: str) -> None:
        """/voice [synthetic|natural] -- record (synthetic by default); /voice again (or
        /voice stop) to finish; then /voice play, /voice send, /voice cancel.

        The recording stays in memory and goes through the voice mask
        (otrv4plus_voicenote) before anything is written; the note is then
        sent as an ordinary encrypted file, with the same gates."""
        import otrv4plus_voicenote as vn
        words = args.split()
        verb = words[0].lower() if words else ""
        rec = getattr(self, "_vn_rec", None)
        note = getattr(self, "_vn_note", None)

        def drop_note():
            if self._vn_note is not None:
                try:
                    os.unlink(self._vn_note["path"])
                except OSError:
                    pass
                self._vn_note = None

        if verb in vn.MODES or verb == "":
            if rec is not None and rec.recording:
                verb = "stop"
            else:
                mode = verb or vn.DEFAULT_MODE
                if not vn.mask_available() and mode != "natural":
                    print("[voice] the voice mask is not in this build; nothing "
                          "was recorded (/voice natural sends your own voice)")
                    return
                self._vn_mode = mode
                self._vn_rec = rec = vn.Recorder()
                self._vn_note = None if note is None else (drop_note() or None)
                try:
                    rec.start()
                except vn.VoiceNoteError as exc:
                    print("[voice] cannot record: %s" % _sanitise(str(exc), 160))
                    return
                print("[voice] recording (%s) — /voice to stop, /voice cancel to "
                      "discard. Max %d s." % (vn.describe_mode(mode), vn.MAX_SECONDS))
                return
        if verb == "stop":
            if rec is None or not rec.recording:
                print("[voice] not recording")
                return
            pcm, rate = rec.stop()
            try:
                self._vn_note = vn.make_note(pcm, rate, getattr(self, "_vn_mode", vn.DEFAULT_MODE),
                                             _filetransfer.staging_dir())
            except vn.VoiceNoteError as exc:
                print("[voice] no note: %s" % {
                    "too_short": "too short", "no_speech": "no speech heard",
                    "unavailable": "the voice mask is not in this build",
                }.get(exc.code, exc.code))
                return
            n = self._vn_note
            print("[voice] note ready: %.1f s, %s. /voice play to hear it, /voice send "
                  "to send, /voice cancel to discard." % (n["seconds"], vn.describe_mode(n["mode"])))
        elif verb == "cancel":
            if rec is not None:
                rec.cancel()
            drop_note()
            print("[voice] discarded")
        elif verb == "play":
            target = " ".join(words[1:]) or (note or {}).get("path", "")
            if not target:
                print("[voice] no note to play")
                return
            try:
                with open(os.path.expanduser(target), "rb") as f:
                    data = f.read(vn.MAX_NOTE_BYTES + 1)
                player = getattr(self, "_vn_player", None) or vn.Player()
                self._vn_player = player
                print("[voice] playing %.1f s" % player.play(data))
            except (OSError, vn.VoiceNoteError) as exc:
                print("[voice] cannot play: %s" % _sanitise(str(exc), 160))
            except Exception as exc:
                print("[voice] no audio output: %s" % _sanitise(str(exc), 160))
        elif verb == "send":
            if note is None:
                print("[voice] record one first: /voice")
                return
            if not peer:
                print("[voice] open a chat with a peer first")
                return
            groups = getattr(self, "_groups", None)
            group = bool(groups is not None and groups.owns_room(peer))
            if not group and self._file_transfer_ratchet(peer) is None:
                print("[voice] no OTR session with %s — run /otr first"
                      % _sanitise(peer, 128))
                return
            path, self._vn_note = note["path"], None

            def discard():
                try:
                    os.unlink(path)
                except OSError:
                    pass

            asyncio.ensure_future(self._offer_file(
                peer, path, False, group=group, picked=False, discard=discard))
        else:
            print("usage: /voice [synthetic|natural] | stop | play | send | cancel")

    async def _offer_file(self, peer, chosen: str, strip: bool, *, group: bool,
                          picked: bool, discard) -> None:
        """Seal and offer, off the event loop (sealing reads the whole file
        through the AEAD; a scrubbed copy is written to the private staging
        directory and removed straight after)."""
        loop = asyncio.get_event_loop()
        if group:
            try:
                await loop.run_in_executor(
                    None, lambda: self._groups.send_file(peer, chosen, strip))
            finally:
                discard()
            return
        ratchet = self._file_transfer_ratchet(peer)
        if ratchet is None:
            print("[file] the OTR session with %s is gone; nothing was sent"
                  % _sanitise(peer, 128))
            discard()
            return

        def seal():
            sent = chosen
            if strip:
                from android_bridge import metadata as _metadata
                sent = _metadata.scrub_file(chosen, _filetransfer.staging_dir())
            try:
                return self._file_manager.offer_file(peer, sent, ratchet)
            finally:
                if sent != chosen:
                    try:
                        os.unlink(sent)
                        os.rmdir(os.path.dirname(sent))
                    except OSError:
                        pass
                discard()

        try:
            transfer = await loop.run_in_executor(None, seal)
        except TransferError as exc:
            print("[file] %s" % exc)
            return
        except Exception as exc:
            print("[file] could not send: %s" % _sanitise(str(exc), 160))
            return
        note = ""
        if picked:
            # The picker cannot report the original name, so say what the
            # peer will actually see rather than letting them find out.
            note = "  (the picker does not report the original name)"
        print("[file] offered %s (%s) to %s%s — waiting for them to accept%s"
              % (transfer.offer.filename, transfer.offer.human_size(),
                 _sanitise(peer, 128),
                 " (hidden information removed)" if strip else "", note))

    #: How long a "remove hidden information?" question stays answerable.
    METADATA_QUESTION_SECONDS = 600.0

    def confirm_metadata(self, path: str, on_choice, on_cancel=None) -> None:
        """Ask whether to remove a file's hidden information, then call
        `on_choice(strip)`. Asked only when there is something to remove --
        the app's rule (MetadataChoice.kt), word for word in effect:

          * nothing found: sent as it is, nothing asked;
          * a kind of file that cannot be checked: sent as it is, and said;
          * metadata found: y = remove it and send, n = keep it and send the
            original (the user may want it kept), c = cancel.

        Armed only by the user's own /sendfile, so a peer can never put this
        question on screen to catch a y meant for something else."""
        from android_bridge import metadata as _metadata
        finding = _metadata.examine_file(path)
        if not finding.can_scrub:
            print("[file] this kind of file cannot be checked for hidden "
                  "information; it is sent exactly as it is")
            on_choice(False)
            return
        if not finding.carries_metadata:
            on_choice(False)
            return
        self._metadata_question = (on_choice, on_cancel, time.monotonic())
        print("[file] %s carries %d bytes of hidden information -- typically "
              "where and when it was taken, and on what device."
              % (_sanitise(os.path.basename(path), 120), finding.metadata_bytes))
        print("[file] Remove it before sending? [y/n/c]   y = remove and send,  "
              "n = keep it and send the original,  c = cancel")

    def _answer_metadata(self, line: str) -> bool:
        """A bare y/n/c answers a pending metadata question. True if it did."""
        pending = getattr(self, "_metadata_question", None)
        if pending is None:
            return False
        on_choice, on_cancel, at = pending
        if time.monotonic() - at > self.METADATA_QUESTION_SECONDS:
            self._metadata_question = None
            if on_cancel is not None:
                on_cancel()
            return False
        word = line.strip().lower()
        if word not in ("y", "yes", "n", "no", "c", "cancel"):
            return False
        self._metadata_question = None
        if word in ("c", "cancel"):
            print("[file] not sent")
            if on_cancel is not None:
                on_cancel()
            return True
        on_choice(word in ("y", "yes"))
        return True

    # -- sounds and y/n answers (otrv4plus_alerts) -------------------------

    def _alerts(self) -> "_alerts.Alerts":
        # Lazy, so the many tests that drive this class from a bare stub
        # without __init__ still work.
        a = getattr(self, "_alerts_obj", None)
        if a is None:
            a = self._alerts_obj = _alerts.Alerts()
        return a

    def _quick_answer(self) -> "_alerts.QuickAnswer":
        q = getattr(self, "_quick_obj", None)
        if q is None:
            q = self._quick_obj = _alerts.QuickAnswer(on_ask=self._drop_group_prompt)
        return q

    def _drop_group_prompt(self) -> None:
        # The newest question wins: a group question still open keeps its
        # /command but no longer takes the bare y/n.
        groups = getattr(self, "_groups", None)
        if groups is not None and hasattr(groups, "_prompt"):
            groups._prompt = None

    def _on_file_state(self, transfer, outgoing: bool) -> None:
        """An incoming 1:1 offer becomes the question a bare y/n answers."""
        if outgoing or getattr(transfer, "state", "") != _filetransfer.TransferState.OFFERED:
            return
        key = transfer.offer.transfer_id.hex()[:8]
        mgr = self._file_manager

        def still_open() -> bool:
            t = mgr.incoming.get(transfer.offer.transfer_id.hex()) if mgr else None
            return t is not None and not t.accepted

        self._quick_answer().ask(
            "file",
            on_yes=lambda: self._cmd_transfer("accept " + key),
            on_no=lambda: self._cmd_transfer("decline " + key),
            still_open=still_open)
        self._alerts().message()

    def ask_answer_call(self, peer: str) -> None:
        """Called by the voice manager when a 1:1 call starts ringing."""
        vm = self._voice_manager

        def still_open() -> bool:
            return vm is not None and vm.ringing_peer() == peer

        self._quick_answer().ask(
            "call",
            on_yes=lambda: (None if self._voice_blocked_by_tofu(peer) else
                            asyncio.ensure_future(vm.answer_call(peer))),
            on_no=lambda: asyncio.ensure_future(vm.reject_call(peer)),
            still_open=still_open)

    def _cmd_transfer(self, rest: str) -> None:
        parts = rest.split(None, 1)
        action = parts[0].lower() if parts else ""
        argument = parts[1].strip() if len(parts) > 1 else ""
        # Group files (android_bridge.group_files) answer to the same verbs.
        group_files = getattr(getattr(self, "_groups", None), "files", None)
        if group_files is not None:
            rows = group_files.transfers()
            if not action and rows:
                self._groups.print_files()
            if action in ("accept", "decline", "cancel") and argument:
                hit = [r["id"] for r in rows if r["id"].startswith(argument.lower())]
                if len(hit) == 1:
                    done = getattr(group_files, action)(hit[0])
                    if not done:
                        print("[file] that group file can no longer be %sed"
                              % action.rstrip("e"))
                    return
        if self._file_manager is None:
            print("[file] the transfer subsystem is not ready yet")
            return
        mgr = self._file_manager

        if not action:
            if not mgr.incoming and not mgr.outgoing:
                if not (group_files is not None and group_files.transfers()):
                    print("[file] no transfers")
                return
            for key, t in mgr.incoming.items():
                state = "receiving" if t.accepted else "offered to you"
                print("  in   %s  %s  %s  %s"
                      % (key[:8], t.offer.filename, t.offer.human_size(),
                         state))
            for key, t in mgr.outgoing.items():
                state = "sending" if t.accepted else "awaiting accept"
                print("  out  %s  %s  %s  %s"
                      % (key[:8], t.offer.filename, t.offer.human_size(),
                         state))
            return

        if action not in ("accept", "decline", "cancel"):
            print("usage: /transfer [accept|decline|cancel <id>]")
            return
        if not argument:
            print("usage: /transfer %s <id>" % action)
            return

        try:
            if action == "accept":
                transfer = mgr.find_incoming(argument)
                ratchet = self._file_transfer_ratchet(transfer.peer)
                if ratchet is None:
                    print("[file] the OTR session with %s is gone; the "
                          "transfer cannot be keyed"
                          % _sanitise(transfer.peer, 128))
                    return
                mgr.accept(transfer.offer.transfer_id, ratchet)
                print("[file] accepting %s" % transfer.offer.filename)
            elif action == "decline":
                mgr.decline(mgr.find_incoming(argument).offer.transfer_id)
            else:
                target = None
                for key in list(mgr.outgoing) + list(mgr.incoming):
                    if key.startswith(argument.lower()):
                        target = key
                        break
                if target is None:
                    print("[file] no such transfer")
                    return
                mgr.cancel(bytes.fromhex(target))
        except TransferError as exc:
            print("[file] %s" % exc)
