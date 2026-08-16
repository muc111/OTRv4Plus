#!/usr/bin/env python3
"""Splice the hardened voice subsystem (v3) into otrv4plus_xmpp.py.

    python3 integrate_voice_v3.py path/to/otrv4plus_xmpp.py

Writes otrv4plus_xmpp.py.bak, then edits in place.  Idempotent: running it
twice is a no-op.  Every anchor is matched on content, not line number, so
it survives unrelated edits to the file.

It refuses to write anything unless every mandatory edit succeeded, and it
prints a report of exactly what it changed.  Anything it could not handle is
listed at the end with a file/line reference for you to finish by hand — it
never silently leaves a half-applied patch.

WHAT IT DOES
------------
1. Deletes the v2 voice block: the design comment header, the VOICE_*
   constants, _pad_opus/_unpad_opus, VoiceKeyExchange, VoiceFrameCrypto,
   VoiceCallSession, VoiceCallManager, and the module-level _smp_query.
   Keeps the SAM timeouts, _ossl_cleanse, _pipe_read_exact, _pipe_write_all,
   _sam_release, SAMProtocolError, _sam_read_line, _sam_parse,
   _sam_handshake and _sam_open, all of which the I2P bridge also uses.

2. Inserts an import of otrv4plus_voice plus a bind_host() call that hands
   it the host's terminal, SAM and audio helpers, and re-exports the voice
   names under their old module-level spellings so nothing else in the file
   has to change.

3. Rewrites VoiceCallSession.<STATE> references to CallState.<STATE>.

4. Stops the TUI from writing to _smp_reported.

   This is the security-critical edit.  _tui_route_output scans every printed
   line for substrings such as "SMP VERIFIED" and "IDENTITY VERIFIED", and on
   a match promotes whichever JID appears in the line to (peer, "SUCCEEDED")
   in _smp_reported.  The v2 voice gate consulted that set BEFORE asking the
   engine, so a rendered log line was sufficient to unlock a voice call with
   no cryptographic verification at all.  Those writes are redirected to a
   display-only set, and the v3 gate never reads either set — it asks the
   engine and nothing else.
"""

import os
import re
import shutil
import sys

SHIM = '''
# =============================================================================
# Voice call: encrypted Opus over a single bidirectional I2P SAM stream
# =============================================================================
#
# The voice subsystem lives in otrv4plus_voice.py (protocol v3: hybrid
# X448 + ML-KEM-1024 media keys, call-ID-bound signalling, two-phase rekey,
# authenticated media headers).  It is a separate module so that the key
# agreement, the rekey state machine and the replay window can be tested
# without importing slixmpp, opuslib or PulseAudio — see
# test_voice_security.py.  Read the module docstring there for the wire
# format and the exact security claims.
#
# Everything below re-exports the voice names under their historical
# module-level spellings so the rest of this file is unchanged.

import otrv4plus_voice as _voice

_voice.bind_host(
    print=print,
    sanitise=_sanitise,
    ossl_cleanse=_ossl_cleanse,
    which=_which,
    load_opus=_load_opus,
    voice_available=voice_available,
    sam_open=_sam_open,
    sam_read_line=_sam_read_line,
    sam_parse=_sam_parse,
    sam_release=_sam_release,
    pipe_read_exact=_pipe_read_exact,
    pipe_write_all=_pipe_write_all,
    opus=_opus,
    termux_prefix=TERMUX_PREFIX,
    is_termux=IS_TERMUX,
)

VoiceKeyExchange = _voice.VoiceKeyExchange
VoiceFrameCrypto = _voice.VoiceFrameCrypto
VoiceKeySchedule = _voice.VoiceKeySchedule
VoiceCallSession = _voice.VoiceCallSession
VoiceCallManager = _voice.VoiceCallManager
CallState = _voice.CallState
KemUnavailable = _voice.KemUnavailable

VOICE_SAMPLE_RATE = _voice.VOICE_SAMPLE_RATE
VOICE_FRAME_MS = _voice.VOICE_FRAME_MS
VOICE_FRAME_SAMPLES = _voice.VOICE_FRAME_SAMPLES
VOICE_CHANNELS = _voice.VOICE_CHANNELS
VOICE_FRAME_BYTES = _voice.VOICE_FRAME_BYTES
VOICE_BITRATE = _voice.VOICE_BITRATE
VOICE_OPUS_SLOT = _voice.VOICE_OPUS_SLOT
VOICE_PACKET_LEN = _voice.VOICE_PACKET_LEN
VOICE_COMPLEXITY = _voice.VOICE_COMPLEXITY
VOICE_LOSS_PCT = _voice.VOICE_LOSS_PCT
VOICE_PLAIN_LEN = _voice.VOICE_PLAIN_LEN
VOICE_SEALED_LEN = _voice.VOICE_SEALED_LEN
VOICE_HDR_LEN = _voice.VOICE_HDR_LEN
VOICE_SYNC = _voice.VOICE_SYNC
VOICE_MIN_FRAME = _voice.VOICE_MIN_FRAME
VOICE_MAX_FRAME = _voice.VOICE_MAX_FRAME
VOICE_JITTER_PREFILL = _voice.VOICE_JITTER_PREFILL
VOICE_JITTER_MAX = _voice.VOICE_JITTER_MAX
VOICE_REKEY_SECONDS = _voice.VOICE_REKEY_SECONDS
VOICE_REKEY_TIMEOUT = _voice.VOICE_REKEY_TIMEOUT
_pad_opus = _voice.pad_opus
_unpad_opus = _voice.unpad_opus

# The _opus module is imported lazily by _load_opus(), so rebind after any
# successful load rather than capturing the None that exists at import time.
_voice_load_opus = _load_opus


def _load_opus_and_bind():
    ok = _voice_load_opus()
    if ok:
        _voice.bind_host(opus=_opus)
    return ok


_voice.bind_host(load_opus=_load_opus_and_bind)


def _smp_query(manager, peer):
    """Ask the OTR engine whether SMP has cryptographically verified a peer.

    Returns (verified, state_name).  The boolean comes only from the engine's
    published predicates; state_name is for display and no decision is taken
    on it.  See otrv4plus_voice._smp_query_default.
    """
    return _voice._smp_query_default(manager, peer)

'''


class Integrator:
    MARKER = "import otrv4plus_voice as _voice"

    def __init__(self, text):
        self.text = text
        # Every anchor this script matches also appears inside the shim
        # it inserts — the banner comment, the VOICE_* names, and
        # _smp_query itself.  Without this flag a second run would cut
        # the shim apart while reporting success, so removal is gated on
        # the shim being absent rather than on each anchor individually.
        self.already_integrated = self.MARKER in text
        self.done = []
        self.skipped = []
        self.failed = []

    # -- helpers ----------------------------------------------------------

    def _cut_between(self, start_marker, end_marker, label, replacement=""):
        """Delete from start_marker up to (not including) end_marker."""
        start = self.text.find(start_marker)
        if start == -1:
            self.skipped.append("%s: start anchor already gone" % label)
            return
        end = self.text.find(end_marker, start)
        if end == -1:
            self.failed.append("%s: end anchor %r not found after the start "
                               "anchor" % (label, end_marker[:60]))
            return
        removed = self.text.count("\n", start, end)
        self.text = self.text[:start] + replacement + self.text[end:]
        self.done.append("%s: removed %d lines" % (label, removed))

    # -- edits ------------------------------------------------------------

    def remove_v2_voice_block(self):
        if self.already_integrated:
            self.skipped.append("v2 voice block: already replaced")
            return
        # Design comment + VOICE_* constants + padding helpers, stopping just
        # before the SAM timeouts, which the I2P bridge also uses.
        self._cut_between(
            "# =============================================================================\n"
            "# Voice call: encrypted Opus over a single bidirectional I2P SAM stream",
            "# SAM timeouts (seconds).",
            "voice constants block")

        # The four v2 classes, stopping at the XMPP client banner.
        self._cut_between(
            "class VoiceKeyExchange:",
            "# =============================================================================\n"
            "# XMPP client",
            "v2 voice classes")

        # The old module-level _smp_query, replaced by the shim's.
        self._cut_between(
            "def _smp_query(manager, peer):",
            "class OTRv4PlusXMPP(",
            "v2 _smp_query")

    def insert_shim(self):
        if "import otrv4plus_voice as _voice" in self.text:
            self.skipped.append("shim: already present")
            return
        anchor = "# =============================================================================\n# XMPP client"
        idx = self.text.find(anchor)
        if idx == -1:
            self.failed.append("shim: could not find the XMPP client banner")
            return
        self.text = self.text[:idx] + SHIM + "\n" + self.text[idx:]
        self.done.append("shim: inserted %d lines" % SHIM.count("\n"))

    def rewrite_state_constants(self):
        pattern = re.compile(r"VoiceCallSession\.([A-Z_]+)\b")
        states = {"IDLE", "INVITING", "RINGING", "CONNECTING",
                  "KEY_CONFIRMING", "MEDIA_CONNECTING", "ACTIVE",
                  "ENDING", "ENDED"}
        unknown = set()
        count = [0]

        def repl(m):
            name = m.group(1)
            if name in states:
                count[0] += 1
                return "CallState.%s" % name
            if name in ("ROLE_CALLER", "ROLE_CALLEE"):
                count[0] += 1
                return {"ROLE_CALLER": "VoiceCallSession.ROLE_INITIATOR",
                        "ROLE_CALLEE": "VoiceCallSession.ROLE_RESPONDER"}[name]
            unknown.add(name)
            return m.group(0)

        # Only rewrite outside the shim, which defines the aliases.
        head, sep, tail = self.text.partition(SHIM)
        if sep:
            head = pattern.sub(repl, head)
            tail = pattern.sub(repl, tail)
            self.text = head + sep + tail
        else:
            self.text = pattern.sub(repl, self.text)

        if count[0]:
            self.done.append("state constants: rewrote %d reference(s) to "
                             "CallState.*" % count[0])
        else:
            self.skipped.append("state constants: nothing to rewrite")
        for name in sorted(unknown):
            self.failed.append("state constants: VoiceCallSession.%s has no "
                               "v3 equivalent — resolve by hand" % name)

    def defang_tui_smp_sniffer(self):
        """Redirect the TUI's string-sniffed SMP writes to a display-only set.

        This is the edit that closes the log-string-unlocks-a-call hole.  The
        badge still updates from the sniffed line, which is what it is for;
        the set the security path used to read no longer gains entries from
        printed text.
        """
        old = ('if check_peer and (check_peer, "SUCCEEDED") not in '
               'self._smp_reported:\n')
        new = ('if check_peer and (check_peer, "SUCCEEDED") not in '
               'self._smp_display_hints:\n')
        n = self.text.count(old)
        if n == 0 and "_smp_display_hints" in self.text:
            self.skipped.append("TUI SMP sniffer: already defanged")
        elif n == 0:
            self.failed.append(
                "TUI SMP sniffer: could not find the writes in "
                "_tui_route_output — check by hand that no code path adds to "
                "_smp_reported on the strength of a printed string")
        else:
            self.text = self.text.replace(old, new)
            self.text = self.text.replace(
                '                    self._smp_reported.add((check_peer, "SUCCEEDED"))\n',
                '                    self._smp_display_hints.add((check_peer, "SUCCEEDED"))\n')
            self.text = self.text.replace(
                '                self._smp_reported.add((check_peer, "SUCCEEDED"))\n',
                '                self._smp_display_hints.add((check_peer, "SUCCEEDED"))\n')
            self.done.append("TUI SMP sniffer: redirected %d write site(s) to "
                             "a display-only set" % n)

        init_old = "        self._smp_reported = set() # (peer, state) already announced\n"
        init_new = (
            "        self._smp_reported = set() # (peer, state) already announced\n"
            "        # Display only.  Populated by _tui_route_output matching\n"
            "        # substrings such as \"SMP VERIFIED\" in printed lines, which\n"
            "        # peer-influenced text can reach.  NOTHING may take a\n"
            "        # security decision on this set: the voice gate asks the\n"
            "        # engine's cryptographic predicate and nothing else.\n"
            "        self._smp_display_hints = set()\n")
        if "self._smp_display_hints = set()" in self.text:
            self.skipped.append("_smp_display_hints: already initialised")
        elif init_old in self.text:
            self.text = self.text.replace(init_old, init_new, 1)
            self.done.append("_smp_display_hints: initialised in __init__")
        else:
            self.failed.append("_smp_display_hints: could not find the "
                               "_smp_reported initialiser — add "
                               "self._smp_display_hints = set() to "
                               "OTRv4PlusXMPP.__init__ by hand")

        # The badge lookup should read both sets so the UI is unchanged.
        badge_old = "reported = (peer, \"SUCCEEDED\") in self._smp_reported\n"
        if badge_old in self.text:
            self.text = self.text.replace(
                badge_old,
                "reported = ((peer, \"SUCCEEDED\") in self._smp_reported\n"
                "                            or (peer, \"SUCCEEDED\") in "
                "self._smp_display_hints)\n", 1)
            self.done.append("badge lookup: now reads both sets")

    def harden_report_smp(self):
        """Stop _report_smp announcing verification on a heuristic.

        The voice gate no longer reads _smp_reported, so this is not an
        authentication bypass any more.  It is still a false statement to the
        user: the banner says "IDENTITY VERIFIED ... shared secret matched"
        on the strength of a state name containing "STATE_UPDATED" or
        "COMPLETE", or a session attribute called smp_complete.  SMP completes
        on failure as readily as on success, and STATE_UPDATED is a generic
        notification, so the user can be told their peer is verified when the
        engine never said so — and they will speak freely on the strength of
        it.  The banner is restricted to the engine's own predicate; the
        heuristic path now reports a state change without claiming anything.
        """
        old = '''            if is_ok and key_ok not in self._smp_reported:
                self._smp_reported.add(key_ok)
                print(
                    f"\\n[smp] *** IDENTITY VERIFIED with {peer} - "
                    "shared secret matched (SMP complete). ***\\n"
                )
            elif is_fail and key_fail not in self._smp_reported:'''
        new = '''            # Deliberately NOT announced as verification.  is_ok is a
            # name/attribute heuristic; only _smp_query's boolean, handled
            # above, is the engine saying the shared secret matched.
            if is_ok and key_ok not in self._smp_display_hints:
                self._smp_display_hints.add(key_ok)
                print(
                    f"\\n[smp] SMP reached a terminal state with {peer} "
                    f"(engine reports: {name}). This is NOT a verification "
                    "result — run /smpstate to see what the engine actually "
                    "says.\\n"
                )
            elif is_fail and key_fail not in self._smp_reported:'''
        if new in self.text:
            self.skipped.append("_report_smp: already hardened")
            return
        if old not in self.text:
            self.failed.append(
                "_report_smp: could not find the heuristic success branch — "
                "check by hand that nothing prints IDENTITY VERIFIED without "
                "the engine's predicate returning True")
            return
        self.text = self.text.replace(old, new, 1)
        self.done.append("_report_smp: verification banner restricted to the "
                         "engine's predicate")

    def check_leftovers(self):
        """Flag v2-only names that survived and have no v3 equivalent.

        VOICE_GEN_MASK is the important one: it is the 8-bit wrapping
        generation that v3 replaces with a monotonic 64-bit epoch, so any
        surviving reference is code that still believes generations wrap.
        """
        defined = set(re.findall(r"^(VOICE_[A-Z0-9_]+) = _voice\.", SHIM,
                                 re.M))
        for m in re.finditer(r"\bVOICE_[A-Z0-9_]+\b", self.text):
            name = m.group(0)
            if name in defined:
                continue
            line = self.text.count("\n", 0, m.start()) + 1
            self.failed.append(
                "leftover reference to %s at line %d — v2-only constant with "
                "no v3 equivalent; rework that code by hand" % (name, line))
            break


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = argv[1]
    if not os.path.isfile(path):
        print("no such file: %s" % path)
        return 2

    original = open(path, encoding="utf-8").read()
    it = Integrator(original)
    it.remove_v2_voice_block()
    it.insert_shim()
    it.rewrite_state_constants()
    it.defang_tui_smp_sniffer()
    it.harden_report_smp()
    it.check_leftovers()

    print("=" * 70)
    for line in it.done:
        print("  applied  %s" % line)
    for line in it.skipped:
        print("  skipped  %s" % line)
    for line in it.failed:
        print("  MANUAL   %s" % line)
    print("=" * 70)

    if it.failed:
        print("\nRefusing to write: %d item(s) need a decision.  Nothing has "
              "been changed on disk." % len(it.failed))
        return 1

    try:
        compile(it.text, path, "exec")
    except SyntaxError as exc:
        print("\nRefusing to write: the result does not parse (%s at line %s)."
              % (exc.msg, exc.lineno))
        return 1

    if it.text == original:
        print("\nNothing to do — already integrated.")
        return 0

    shutil.copy2(path, path + ".bak")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(it.text)
    print("\nWrote %s (backup at %s.bak)." % (path, path))
    print("Next: put otrv4plus_voice.py beside it, then run")
    print("      python3 -m unittest test_voice_security -v")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
