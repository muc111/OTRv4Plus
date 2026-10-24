# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's trust: fingerprints pinned on first use, and SMP.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). The cryptography is the
engine's and the Rust core's; this is when the client asks for an SMP
secret, how it reads one without echoing it, what it says about the
result, and what a changed fingerprint blocks.

The engine and the client's SMP tag are handed over by the client once
it has loaded the engine (`bind_engine`): this module does not import the
engine."""
import asyncio
import os
import sys

import otrv4plus_smpflow as _smpflow
import otrv4plus_voice as _voice
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)

# Set by bind_engine().
_otr = None
_SMP = "[smp]"
SMP_MIN_LEN, SMP_MAX_LEN = 8, 512


def bind_engine(otr, smp_tag, smp_min_len, smp_max_len) -> None:
    """Take the engine and the client's SMP tag (see the module doc)."""
    global _otr, _SMP, SMP_MIN_LEN, SMP_MAX_LEN
    _otr, _SMP = otr, smp_tag
    SMP_MIN_LEN, SMP_MAX_LEN = smp_min_len, smp_max_len


def _fmt_fp(fp: str) -> str:
    """Format a fingerprint as space-separated groups of 8 hex chars."""
    if not fp or fp == "unavailable":
        return fp or "unavailable"
    clean = fp.upper().replace(" ", "")
    return " ".join(clean[i : i + 8] for i in range(0, len(clean), 8))


def _smp_query(manager, peer):
    """Ask the OTR engine whether SMP has cryptographically verified a peer.

    Returns (verified, state_name).  The boolean comes only from the engine's
    published predicates; state_name is for display and no decision is taken
    on it.  See otrv4plus_voice._smp_query_default.
    """
    return _voice._smp_query_default(manager, peer)


class TrustMixin:
    """TOFU pinning and the SMP flow. Mixed into OTRv4PlusXMPP."""

    # -------------------------------------------------------------------------
    # TOFU (XMPP only)
    # -------------------------------------------------------------------------

    def _apply_tofu(self, peer, remote_fp):
        """Trust-on-first-use against the pinned fingerprint.

        Three outcomes, and they are genuinely different situations rather than
        three shades of the same prompt:

        first contact   nothing pinned -> show it, ask once, pin on `y`
        same key        pinned and matching -> say so, ask nothing
        changed key     pinned and DIFFERENT -> refuse, keep the old pin

        The third case never auto-repins and never offers `y` as a way through.
        A prompt that can be answered `y` is a prompt that will be answered `y`,
        and the whole point of pinning is that this particular `y` should cost
        the user some deliberate effort somewhere else.

        This is identity *continuity*, not authentication. SMP remains what
        authenticates a peer, and `_smp_verified` remains the only gate on
        voice -- a matching pin authorises nothing by itself.
        """
        if not remote_fp:
            print("[trust] no peer fingerprint available - encrypted only.")
            self._announce_smp_needed(peer)
            return

        try:
            pinned_and_trusted = self.otr.trust_db.check_or_pin(peer, remote_fp)
        except Exception as exc:
            if type(exc).__name__ != "FingerprintMismatchError":
                print("[trust] trust store unusable (%s) - encrypted only."
                      % type(exc).__name__)
                self._announce_smp_needed(peer)
                return
            self._fingerprint_changed[peer] = getattr(exc, "stored", "")
            print("")
            print("!" * 60)
            print("[trust] THE FINGERPRINT FOR THIS JID HAS CHANGED.")
            print("[trust]   pinned : %s" % _fmt_fp(getattr(exc, "stored", "")))
            print("[trust]   now    : %s" % _fmt_fp(remote_fp))
            print("[trust] The pinned fingerprint has NOT been replaced.")
            print("[trust] This is what a machine-in-the-middle looks like. It")
            print("[trust] also looks exactly like your peer reinstalling, so")
            print("[trust] it is a question, not a verdict - but confirm the")
            print("[trust] new fingerprint with them over a channel that is")
            print("[trust] not this one before you accept it.")
            print("[trust] To accept deliberately:  /trust-reset %s" % peer)
            print("[trust] Voice is refused for this peer until you do.")
            print("!" * 60)
            print("")
            return

        self._fingerprint_changed.pop(peer, None)
        if pinned_and_trusted:
            print("[trust] Fingerprint matches the pinned identity for this JID.")
            self._announce_smp_needed(peer)
            return

        # First contact: pin it and say so. No question.
        #
        # The prompt is gone because it never carried the security. Asked to
        # approve a fingerprint you have never seen, there is nothing to check
        # it against -- the only available answer is yes, and a question whose
        # answer is always yes trains the reflex that makes the question that
        # DOES matter useless. Signal, WhatsApp and every other TOFU deployment
        # pin silently for the same reason.
        #
        # What protects you is the second half, and it is untouched: a pinned
        # fingerprint that CHANGES still stops the session, still refuses
        # voice, still cannot be waved through with a keystroke, and still
        # needs a deliberate /trust-reset. That is the branch above, and it is
        # where a machine-in-the-middle actually shows up.
        ok = False
        try:
            ok = self.otr.trust_fingerprint(peer, remote_fp)
        except Exception as exc:
            print("[trust] could not pin the fingerprint: %s" % type(exc).__name__)
        if ok:
            print("[trust] First contact — fingerprint PINNED for this JID.")
            print("[trust] A change will be reported and will block voice.")
        else:
            print("[trust] First contact — the fingerprint could NOT be pinned,")
            print("[trust] so a change cannot be detected. /identity for why.")
        self._announce_smp_needed(peer)

    def show_identity(self):
        """Everything TOFU depends on, in one screen.

        Written because "it still asks me to trust the fingerprint" has three
        very different causes -- an older build at one end, a pin that did not
        stick, or a peer whose identity really is changing -- and telling them
        apart previously meant finding and reading a JSON file on both phones.
        """
        print("-" * 60)
        persistent = bool(getattr(self, "identity_persistent", False))
        print("[identity] local identity : %s"
              % ("PERSISTENT — the same every run" if persistent
                 else "EPHEMERAL — regenerates every run"))
        if not persistent:
            print("[identity]   Peers cannot pin a fingerprint that changes every")
            print("[identity]   launch. XMPP should be persistent; if this says")
            print("[identity]   ephemeral you are on a build older than v10.12.0.")
        print("[identity] your fingerprint: %s" % _fmt_fp(self._local_fp()))
        try:
            cfg = self.otr.config
            print("[identity] identity record: %s" % getattr(cfg, "identity_path", "?"))
            print("[identity] trust store    : %s%s"
                  % (self.otr.trust_db.db_path,
                     "" if self.otr.trust_db.persistent else "  (IN MEMORY ONLY)"))
        except Exception:
            pass

        try:
            entries = self.otr.trust_db.list_trusted()
        except Exception as exc:
            print("[identity] trust store unreadable: %s" % type(exc).__name__)
            entries = {}

        print("-" * 60)
        if not entries:
            print("[identity] No fingerprints pinned yet.")
            print("[identity]   First contact pins silently. If nothing is listed")
            print("[identity]   after a session, the pin did not stick.")
        else:
            print("[identity] Pinned fingerprints (%d):" % len(entries))
            for jid, fp in sorted(entries.items()):
                live = self._remote_fp(jid) if jid in self._encrypted else None
                if live and live != "unavailable":
                    state = "matches now" if live == fp else "!! DIFFERS FROM LIVE !!"
                else:
                    state = "not in session"
                print("[identity]   %-32s %s  [%s]" % (jid, _fmt_fp(fp), state))
        if self._fingerprint_changed:
            print("[identity] UNRESOLVED identity change for: %s"
                  % ", ".join(sorted(self._fingerprint_changed)))
            print("[identity]   Voice is refused for these until /trust-reset <jid>.")
        print("-" * 60)

    def _voice_blocked_by_tofu(self, peer) -> bool:
        """Refuse a call to a peer whose pinned fingerprint changed.

        This is an ADDITIONAL refusal, layered on top of the SMP gate rather
        than replacing any part of it. `_smp_verified` remains the only thing
        that authorises voice; a matching pin has never authorised anything and
        still does not. What this adds is that a *mismatched* pin refuses
        early, so an unresolved identity change cannot be walked past by
        completing SMP against whoever is on the other end.
        """
        if peer not in self._fingerprint_changed:
            return False
        print("[voice] refused: the pinned fingerprint for %s has changed and "
              "the change is unresolved." % peer)
        print("[voice] Confirm the new fingerprint with them out of band, then "
              "/trust-reset %s" % peer)
        return True

    def _report_pq_refusal(self, peer):
        """A2: the engine refused this handshake because the contact's
        post-quantum key was dropped or changed under the same identity."""
        take = getattr(self.otr, "take_pq_refusal", None)
        code = take(peer) if take is not None else None
        if code is None:
            return
        if code == "pq_v2_required":
            print("[trust] HANDSHAKE REFUSED (pq_v2_required): %s runs an older "
                  "protocol without the post-quantum ratchet and authentication "
                  "(A1, A2). Both sides need this version or newer." % peer)
            return
        what = ("did not prove its post-quantum key this time" if code == "pq_downgrade"
                else "now uses a different post-quantum key")
        print("")
        print("!" * 60)
        print("[trust] HANDSHAKE REFUSED (%s): %s %s," % (code, peer, what))
        print("[trust] under the same fingerprint that used one before.")
        print("[trust] That is what an attacker who can forge the classical key")
        print("[trust] looks like. It also looks like your contact reinstalling")
        print("[trust] or going back to an older version: ask them in person.")
        print("[trust] To accept deliberately:  /trust-reset %s" % peer)
        print("!" * 60)
        print("")

    def trust_reset(self, peer):
        """Deliberately drop a pin so the next contact re-pins (`/trust-reset`).

        Separate from the `y` prompt on purpose. Accepting a changed identity
        should cost a distinct, typed, peer-named action rather than the same
        keystroke the user already presses reflexively.
        """
        if not peer:
            print("usage: /trust-reset <jid>")
            return
        try:
            removed = self.otr.trust_db.remove_trust(peer)
        except Exception as exc:
            print("[trust] could not clear the pin: %s" % type(exc).__name__)
            return
        self._fingerprint_changed.pop(peer, None)
        if removed:
            print("[trust] Pin cleared for %s. The next session will treat it as "
                  "first contact." % peer)
            print("[trust] Run /otr again to re-establish and pin.")
        else:
            print("[trust] No pin was stored for %s." % peer)

    # -------------------------------------------------------------------------
    # SMP passphrase prompt
    # -------------------------------------------------------------------------

    def _announce_smp_needed(self, peer):
        """Tell the user SMP is available.  Arm NOTHING.

        This is reached from `_handle_otr_in_async` -> `_check_dake_complete`
        -> `_apply_tofu`, which is to say: a remote peer decides when it runs.
        It therefore may not change what the next line the user types means.

        It used to.  It set `_pending[peer] = "smp_secret"`, and `dispatch_line`
        consumed the pending state before any command parsing, so a peer who
        completed a DAKE could make the user's next keystroke -- a message, a
        command, anything but /quit -- be swallowed and stored as a shared
        secret.  The user's only warning was a prompt they may have scrolled
        past.

        Supplying the secret now requires the user to type `/smp-secret`
        themselves.  See `_request_smp_secret`.
        """
        print("-" * 60)
        print(
            _SMP + " SOCIALIST MILLIONAIRE PROTOCOL is available for this peer "
            "(hybrid PQC: ML-KEM-1024 + ML-DSA-87 + ZKP)."
        )
        print(
            _SMP + f" Passphrase: {SMP_MIN_LEN}-{SMP_MAX_LEN} chars. "
            "Both sides must use the SAME secret, agreed out of band."
        )
        print(_SMP + " To verify:   /smp     (asks for the passphrase if you "
              "have not stored one)")
        print(_SMP + " Until you run that command, what you type is an ordinary "
              "message.")

    # ─── the guided verification flow ────────────────────────────────────────
    #
    # Two entries, and the difference between them is the whole security
    # story.  `/smp` is local: the user typed a command, so the next line may
    # be a passphrase without further ceremony -- the `passwd` shape.  An
    # incoming SMP1 is remote: it may ASK, and the asking stops at a y/n that
    # cannot be a passphrase.  Only the answer to that y/n opens the hidden
    # read.  otrv4plus_smpflow.SmpFlow has no edge that skips it.

    def smp_verify(self, peer):
        """`/smp` -- verify this session, asking for whatever is missing.

        The normal way to verify.  The user never has to know that a secret
        is stored separately from the act of verifying, or that `/smp-secret`
        exists.
        """
        if not self.otr.has_encrypted_session(peer):
            print(_SMP + f" no encrypted session with {peer}. Run /otr first."
                  + self._no_session_hint(peer))
            return
        flow = self._smp_flows.get(peer)
        if flow.state in (_smpflow.AWAITING_LOCAL_CONSENT,
                          _smpflow.AWAITING_SECRET):
            print(_SMP + " already asking you for the passphrase — answer that "
                  "prompt.")
            return

        stored = False
        try:
            stored = self.otr.has_stored_smp_secret(peer)
        except Exception:
            stored = False

        if stored:
            print(_SMP + f" stored passphrase found for {peer} — verifying…")
            flow.running()
            self.smp_start(peer)
            return

        # No passphrase: ask for it, then start.  One command, not two.
        try:
            flow.local_secret_needed()
        except _smpflow.SmpFlowError as e:
            print(_SMP + f" {e}")
            return
        print(_SMP + " Verification requires the passphrase you agreed with "
              "this contact.")
        print(_SMP + f" Both sides must enter the SAME text "
              f"({SMP_MIN_LEN}-{SMP_MAX_LEN} characters).")
        self._arm_secret_prompt(peer, purpose="start")

    def _announce_secret_required(self, peer):
        """A peer asked to verify and we have no passphrase for them.

        Called from the inbound path after the engine parked the SMP1.  It
        prints and sets consent state; it arms NOTHING that could consume a
        line as a secret.  If the user types an ordinary message here it is
        sent as an ordinary message.
        """
        flow = self._smp_flows.get(peer)
        try:
            state = flow.remote_smp1_arrived()
        except _smpflow.SmpFlowError:
            return
        if state != _smpflow.AWAITING_LOCAL_CONSENT:
            return
        if getattr(self, "_smp_consent_shown", None) == peer:
            # A duplicate SMP1 while the prompt is open must not print again.
            return
        self._smp_consent_shown = peer
        print("=" * 60)
        print("🔐 SMP VERIFICATION REQUEST")
        print("")
        print(f"  {_sanitise(peer, 64)} wants to verify this encrypted")
        print("  session using a passphrase you agreed in advance.")
        print("")
        print("  Press  y  to enter that passphrase, or  n  to decline.")
        print("")
        print("  Nothing you type now is sent to them, and typing an")
        print("  ordinary message here just sends an ordinary message.")
        print("=" * 60)

    def _handle_smp_consent(self, peer, answer):
        """y/n from the user.  The only door into the passphrase prompt for a
        request a peer made."""
        flow = self._smp_flows.get(peer)
        agreed = answer in ("y", "yes")
        try:
            flow.local_consent(agreed)
        except _smpflow.SmpFlowError as e:
            print(_SMP + f" {e}")
            return
        self._smp_consent_shown = None
        if not agreed:
            self._decline_smp_request(peer, "declined")
            return
        print(_SMP + " Enter the passphrase you agreed with this contact.")
        self._arm_secret_prompt(peer, purpose="resume")

    def _decline_smp_request(self, peer, why):
        """Tell the peer, drop the held SMP1, keep nothing."""
        flow = self._smp_flows.get(peer)
        flow.reset()
        self._smp_consent_shown = None
        try:
            abort = self.otr.decline_held_smp1(peer)
        except Exception as e:
            self._dbg(_SMP + f" decline error: {e}")
            abort = None
        if abort:
            self.send_otr_fragmented(
                peer, abort if isinstance(abort, str) else abort.decode())
        if why == "declined":
            print(_SMP + " Verification declined.")
        elif why == "timeout":
            print(_SMP + " Verification request expired.")
        else:
            print(_SMP + " Verification cancelled.")
        print(_SMP + " No passphrase was requested, stored or sent.")

    def _expire_stale_smp_consent(self):
        """Drop a consent request the user never answered.

        Called from the inbound path, which is the only clock this client has
        that ticks without user input.  A request left open forever would mean
        a `y` typed much later, meaning something else entirely, opened a
        passphrase prompt.
        """
        shown = getattr(self, "_smp_consent_shown", None)
        if not shown:
            return
        flow = self._smp_flows.get(shown)
        if flow.state != _smpflow.AWAITING_LOCAL_CONSENT:
            if flow.state not in (_smpflow.AWAITING_SECRET,):
                # The flow timed itself out.
                self._decline_smp_request(shown, "timeout")

    def _arm_secret_prompt(self, peer, purpose):
        """Arm the dedicated hidden read.

        `purpose` says what happens after the passphrase is stored, so the
        user never types a second command:
            "store"  -- just save it (the /smp-secret compatibility path)
            "start"  -- save it, then send SMP1
            "resume" -- save it, then answer the SMP1 already held
        """
        hidden = self._mask_next_input(True)
        self._secret_request = peer
        self._secret_purpose = purpose
        if hidden:
            print(_SMP + " Passphrase (hidden), or Enter to cancel:")
        else:
            print(_SMP + " WARNING: this terminal cannot hide input, so the "
                  "passphrase WILL be")
            print(_SMP + " visible here and in any capture of this session.")
            print(_SMP + " Passphrase, or Enter to cancel:")

    def _request_smp_secret(self, peer):
        """Arm the hidden one-line read.  LOCAL COMMAND ONLY.

        The arming is the second half of a command the user just typed, which
        is what makes it safe: `/smp-secret` on one line, the secret on the
        next, the way `passwd` and `sudo` have always worked.  Nothing a peer
        sends reaches this method -- `test_no_remote_input_capture.py` walks
        the inbound call graph and fails if that stops being true.

        Single use.  `dispatch_line` clears the request before doing anything
        with the line, so it cannot survive into a later one, and no code path
        re-arms it except this method.
        """
        if not self.otr.has_encrypted_session(peer):
            print(_SMP + f" no encrypted session with {peer}. Run /otr first."
                  + self._no_session_hint(peer))
            return
        try:
            self._smp_flows.get(peer).local_secret_needed()
        except _smpflow.SmpFlowError as e:
            print(_SMP + f" {e}")
            return
        self._arm_secret_prompt(peer, purpose="store")

    @staticmethod
    def _set_tty_echo(on: bool) -> bool:
        """Turn terminal echo off or on. True if it took effect.

        This is the only thing that works once the reader is already blocked.
        In plain mode the loop sits inside sys.stdin.readline() from BEFORE
        the prompt was raised, and the echo is done by the terminal driver in
        the kernel, not by any code here -- so a flag set afterwards changes
        nothing and the passphrase appears anyway. That is exactly what
        happened: the client printed "what you type is hidden" and then showed
        it.

        The account password sidesteps the same race by discarding the line
        and asking the user to type it again, which is why its prompt says so.
        Clearing ECHO takes effect immediately instead, with TCSANOW, wherever
        the reader happens to be.
        """
        try:
            import termios
            fd = sys.stdin.fileno()
            if not os.isatty(fd):
                return False
            attrs = termios.tcgetattr(fd)
            if on:
                attrs[3] |= termios.ECHO
            else:
                attrs[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            return True
        except Exception:
            return False

    def _mask_next_input(self, on: bool) -> bool:
        """Hide the next typed line. Returns whether hiding actually works.

        The SMP passphrase is a shared secret and was being echoed: into the
        terminal, into scrollback, into the TUI's recallable command history,
        and into any `script` capture of the session. It reached a bug report
        that way, which is how this was noticed.

        Three front ends, three mechanisms, and the return value says whether
        any of them took. The caller must not promise the user that typing is
        hidden unless it is -- the first attempt at this printed exactly that
        promise and then showed the passphrase anyway.
        """
        self._mask_input = bool(on)
        effective = False

        tui = bool(getattr(self, "_tui_enabled", False))

        # Plain mode: the terminal driver does the echoing, so stop it at the
        # driver. This is the only mechanism that works when the reader is
        # already blocked inside readline(), which it always is.
        if not tui:
            if self._set_tty_echo(not on):
                effective = True
            if on and effective and not getattr(self, "_echo_restore_hooked", False):
                # Leaving a shell with echo off is worse than showing a
                # passphrase, so make restoring it unconditional.
                import atexit
                atexit.register(self._set_tty_echo, True)
                self._echo_restore_hooked = True

        # The engine owns the raw-mode input line the TUI draws.
        try:
            setter = getattr(_otr, "set_input_mask", None)
            if setter is not None:
                setter(bool(on))
                if tui:
                    effective = True
        except Exception:
            pass

        # The standalone TUI, when that is the front end instead.
        screen = getattr(self, "_screen", None)
        if screen is not None:
            try:
                screen.mask_input = bool(on)
                effective = True
            except Exception:
                pass

        return effective

    def _handle_smp_secret_answer(self, peer, secret):
        """Consume one hidden line as the SMP passphrase, then do what the
        prompt was opened for.

        `secret` is a Python str and cannot be zeroized; it is handed to the
        engine, which copies it into a Rust-owned zeroizing buffer, and no
        reference is kept here.  See SECURITY.md on the residual limit.

        Every exit path either advances the flow or resets it.  A flow left in
        AWAITING_SECRET would be a prompt the user cannot see and cannot
        answer, and the next line would go to it.
        """
        self._mask_next_input(False)
        purpose = getattr(self, "_secret_purpose_taken", None) or "store"
        flow = self._smp_flows.get(peer)

        if not secret or secret.strip().lower() in ("skip", "cancel"):
            try:
                flow.secret_cancelled()
            except _smpflow.SmpFlowError:
                pass
            if purpose == "resume":
                # A peer is waiting on a held SMP1; tell them and drop it.
                self._decline_smp_request(peer, "cancelled")
            else:
                flow.reset()
                print(_SMP + " Verification cancelled.")
                print(_SMP + " No passphrase was stored.")
            return

        secret = secret.strip()
        err = self._validate_smp_secret(secret)
        if err:
            # Not a cryptographic failure -- nothing has been tried yet.
            print(_SMP + f" {err}")
            print(_SMP + " Nothing was stored. Run  /smp  to try again.")
            if purpose == "resume":
                self._decline_smp_request(peer, "cancelled")
            else:
                flow.reset()
            return

        try:
            ok = self.otr.set_smp_secret(peer, secret)
        except Exception as e:
            # An internal failure, and it must not be reported as a bad
            # passphrase: nothing has been compared yet.
            print(_SMP + " SMP could not continue because of an internal error.")
            print(_SMP + f"   {_sanitise(str(e), 160)}")
            print(_SMP + " No secret was transmitted. Nothing is verified.")
            if purpose == "resume":
                self._decline_smp_request(peer, "cancelled")
            else:
                flow.reset()
            return
        finally:
            del secret

        if not ok:
            print(_SMP + " SMP could not continue because the passphrase could "
                  "not be stored.")
            flow.reset()
            return

        if purpose == "start":
            try:
                flow.secret_supplied()
            except _smpflow.SmpFlowError:
                pass
            print(_SMP + " Passphrase stored — starting verification…")
            self.smp_start(peer)
            return

        if purpose == "resume":
            try:
                flow.secret_supplied()
            except _smpflow.SmpFlowError:
                pass
            print(_SMP + " Passphrase stored — answering your peer…")
            self._resume_held_smp1(peer)
            return

        flow.reset()
        print(_SMP + " passphrase stored for auto-respond.")
        print(_SMP + " Run  /smp  to verify whenever you are ready.")

    def _resume_held_smp1(self, peer):
        """Answer the SMP1 the engine parked, on the OTR executor.

        The ZKP work is the same several hundred milliseconds the rest of SMP
        costs, so it does not run on the event loop.
        """
        def _do_resume():
            return self.otr.resume_held_smp1(peer)

        async def _run():
            loop = asyncio.get_event_loop()
            try:
                smp2 = await loop.run_in_executor(self._otr_executor, _do_resume)
            except Exception as e:
                print(_SMP + " SMP could not continue because of an internal "
                      "error.")
                print(_SMP + f"   {_sanitise(str(e), 160)}")
                print(_SMP + " No secret was transmitted or verified.")
                self._smp_flows.get(peer).failed()
                return
            if smp2:
                self.send_otr_fragmented(
                    peer, smp2 if isinstance(smp2, str) else smp2.decode())
                print(_SMP + " Answered — verification in progress…")
            else:
                print(_SMP + " Nothing to answer; the request may have expired.")
                self._smp_flows.get(peer).reset()

        self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_run()))

    @staticmethod
    def _validate_smp_secret(secret: str):
        """Return an error string if the SMP secret fails validation, else None."""
        if len(secret) < SMP_MIN_LEN:
            return f"secret too short (minimum {SMP_MIN_LEN} characters)"
        if len(secret) > SMP_MAX_LEN:
            return f"secret too long (maximum {SMP_MAX_LEN} characters)"
        return None

    # -------------------------------------------------------------------------
    # SMP result reporting
    # -------------------------------------------------------------------------

    def _show_smp_progress(self, peer, force: bool = False) -> None:
        """A progress line each time a verification moves on (owner,
        2026-10-16: "it should display a loading bar on all clients"). The
        app and the desktop draw a bar; this is the terminal's: one line per
        step, never repeated for the same step."""
        try:
            step, total = self.otr.get_smp_progress(peer)
        except Exception:
            return
        shown = self.__dict__.setdefault("_smp_shown", {})
        if not (0 < step < total):
            shown.pop(peer, None)
            return
        if shown.get(peer) == step and not force:
            return
        shown[peer] = step
        bar = "█" * step + "░" * (total - step)
        print(_SMP + " verifying with %s  [%s] step %d of %d%s"
              % (peer, bar, step, total,
                 " — waiting for them (a minute or two over I2P)" if step == 1 else ""))

    def _report_smp(self, peer):
        # Terminal success state names across Rust engine versions
        _SMP_SUCCESS = {"SUCCEEDED", "VERIFIED", "COMPLETE", "COMPLETED",
                        "SMP_VERIFIED", "STATE_UPDATED"}
        _SMP_FAIL    = {"FAILED", "ERROR", "ABORTED", "SMP_FAILED"}
        try:
            session = self.otr.get_session(peer)
            if not session:
                return
            verified_now, name = _smp_query(self.otr, peer)
            if verified_now:
                # Return whenever the engine confirms, not only the first
                # time. _report_smp fires on several events per session, so
                # returning only on the first call let later ones fall through
                # to the heuristic branch below and print "this is NOT a
                # verification result" immediately after a genuine
                # IDENTITY VERIFIED — contradicting a true statement.
                if (peer, "SUCCEEDED") not in self._smp_reported:
                    self._smp_reported.add((peer, "SUCCEEDED"))
                    print(
                        "\n" + _SMP + f" *** IDENTITY VERIFIED with {peer} - "
                        "shared secret matched (SMP complete). ***\n"
                    )
                    # The secure groups we share with them: verified there
                    # too (group calls need it), keys sent both ways.
                    groups = getattr(self, "_groups", None)
                    if groups is not None and getattr(groups, "_opened", False):
                        try:
                            groups.groups.on_peer_verified(peer)
                        except Exception:
                            pass
                return
            if not name:
                return

            # Normalise to a single "SUCCEEDED" key regardless of engine naming
            key_ok   = (peer, "SUCCEEDED")
            key_fail = (peer, "FAILED")

            # Also check boolean attrs the Rust session may expose directly
            # Substring matching, because the engine's terminal name has
            # varied (SUCCEEDED / VERIFIED / STATE_UPDATED). Failure tokens
            # are checked first so an in-progress or failed phase can never
            # be misread as success.
            is_ok = (name in _SMP_SUCCESS) or (
                not any(t in name for t in
                        ("FAIL", "ABORT", "ERROR", "EXPECT", "PROGRESS"))
                and any(t in name for t in
                        ("SUCCEED", "VERIFI", "COMPLETE", "STATE_UPDATED")))
            if not is_ok:
                for attr in ("smp_verified", "is_verified", "identity_verified",
                             "smp_complete", "is_complete"):
                    if getattr(session, attr, False):
                        is_ok = True
                        break

            is_fail = (name in _SMP_FAIL) or any(
                t in name for t in ("FAIL", "ABORT", "ERROR"))

            # An ABORT is not a mismatch, and saying it is contradicts the
            # line printed immediately above it.  On a real pair of phones
            # this read:
            #
            #   SMP stopped: your peer has not stored the passphrase yet.
            #   ...This is not a wrong-passphrase failure.
            #   *** SMP FAILED - secrets did NOT match. Possible MITM. ***
            #
            # Both from the same abort.  A mismatch is SMP4 returning false;
            # an abort is the run stopping before any comparison happened.
            is_abort = "ABORT" in name and "FAIL" not in name

            # Deliberately NOT announced as verification.  is_ok is a
            # name/attribute heuristic; only _smp_query's boolean, handled
            # above, is the engine saying the shared secret matched.
            if is_ok and key_ok not in self._smp_display_hints:
                self._smp_display_hints.add(key_ok)
                print(
                    "\n" + _SMP + f" SMP reached a terminal state with {peer} "
                    f"(engine reports: {name}). This is NOT a verification "
                    "result — run /smpstate to see what the engine actually "
                    "says.\n"
                )
            elif is_abort and key_fail not in self._smp_reported:
                self._smp_reported.add(key_fail)
                # The reason, when the peer sent one, has already been printed
                # by the session in terms the user can act on.  Do not restate
                # it as a cryptographic result.
                print(
                    "\n" + _SMP + f" SMP with {peer} stopped before verifying. "
                    "Nothing is verified, and no passphrase comparison "
                    "happened — this is not a wrong-passphrase failure.\n"
                )
            elif is_fail and key_fail not in self._smp_reported:
                self._smp_reported.add(key_fail)
                print(
                    "\n" + _SMP + f" *** SMP FAILED with {peer} - secrets did NOT "
                    "match (or protocol error). Possible MITM. ***\n"
                )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Fingerprint helpers
    # -------------------------------------------------------------------------

    def _local_fp(self, peer=None):
        """Return local identity fingerprint.
        After DAKE, tries the session first (returns full hybrid FP length).
        Falls back to client_profile.get_fingerprint() which may return only
        the classical Ed448 portion."""
        if peer:
            try:
                sess = self.otr.get_session(peer)
                if sess:
                    for attr in (
                        "local_fingerprint", "our_fingerprint", "local_fp",
                        "identity_fingerprint", "our_identity_fp",
                    ):
                        val = getattr(sess, attr, None)
                        if val and str(val) not in ("unavailable", "None", ""):
                            return str(val)
                    for mname in (
                        "get_local_fingerprint", "get_our_fingerprint",
                        "get_identity_fingerprint",
                    ):
                        fn = getattr(sess, mname, None)
                        if callable(fn):
                            try:
                                val = fn()
                                if val and str(val) not in ("unavailable", "None", ""):
                                    return str(val)
                            except Exception:
                                pass
            except Exception:
                pass
        try:
            cp = getattr(self.otr, "client_profile", None)
            if cp and hasattr(cp, "get_fingerprint"):
                return cp.get_fingerprint() or "unavailable"
        except Exception:
            pass
        return "unavailable"

    def _remote_fp(self, peer):
        try:
            if hasattr(self.otr, "get_peer_fingerprint"):
                fp = self.otr.get_peer_fingerprint(peer)
                if fp:
                    return fp
            sess = self.otr.get_session(peer)
            if sess and hasattr(sess, "get_fingerprint"):
                fp = sess.get_fingerprint()
                if fp:
                    return fp
        except Exception:
            pass
        return "unavailable"
