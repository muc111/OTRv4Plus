# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The session's side of SMP (the Socialist Millionaires' Protocol).

`EnhancedOTRSession` (otrv4+.py) is built from this mixin. All of SMP's
cryptography -- the hybrid ML-KEM / ML-DSA / zero-knowledge exchange, the
secret, its binding to the session and both identities -- runs in the Rust
core (`otrv4_core.RustSMP`, `RustSMPVault`). What is here is what Python
still decides: which SMP message is answered, refused or held, what the user
is told, and the session's verified flag once Rust says so.

Moved out of otrv4+.py (2026-11-11, so a reviewer can read the SMP flow on
its own); the inbound handler was split into one method per message.
"""
import struct
import time
from typing import Any, Dict, Optional, Tuple

from otrv4plus_states import SessionState, StateMachineError, UIConstants, colorize
from otrv4plus_tlv import OTRv4TLV


SMP_VERSION_MISMATCH_HELP = (
    "⚠ SMP stopped: version mismatch. The two devices are running different "
    "OTRv4+ builds, so they derive different secrets from the same "
    "passphrase.\n"
    "   This is NOT a wrong passphrase. Update both devices to the same "
    "version (git pull, then rebuild the Rust core) and run  /smp start  "
    "again."
)


def _is_smp_version_mismatch(exc: BaseException) -> bool:
    """Recognise the Rust core's SMP version-mismatch abort.

    Matched on the error text because PyO3 raises it as a plain ValueError.
    Kept deliberately narrow: this only changes which local help line is
    printed, never whether anything is trusted or verified.
    """
    return "version mismatch" in str(exc).lower()


class SessionSmpMixin:
    """SMP for one OTR session. Mixed into EnhancedOTRSession, which owns
    the state it reads (`rust_smp`, `smp_vault`, `peer`, `tracer`, ...)."""

    def transition_smp(self, new_state: UIConstants.SMPState, reason: str = ""):
        """Transition SMP state with validation"""
        if not self._acquire_lock():
            raise StateMachineError("Failed to acquire lock for SMP transition")

        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError("SMP requires encrypted session")

            old_state = self.smp_state

            self.smp_state = new_state
            self.tracer.trace(self.peer, "SMP", old_state.name, new_state.name, reason)

            if new_state == UIConstants.SMPState.SUCCEEDED:
                self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                self.tracer.trace(
                    self.peer, "SECURITY", "ENCRYPTED", "SMP_VERIFIED", "SMP succeeded"
                )

        finally:
            self._release_lock()

    def initialize_smp(self):
        """Initialize the Rust SMP engine and secret vault (lazy, idempotent)."""
        if self.rust_smp is None:
            try:
                from otrv4_core import RustSMP, RustSMPVault

                self.rust_smp = RustSMP(self.is_initiator)
                self.smp_vault = RustSMPVault()
                self.tracer.trace(self.peer, "SMP", None, "READY", "Rust SMP engine initialized")
            except Exception as e:
                self.logger.debug("initialize_smp FAILED")
                raise RuntimeError(f"Failed to initialize Rust SMP engine: {e }") from e

    # ─── inbound SMP messages ───────────────────────────────────────────────
    #
    # One method per message. Each returns the reply to send, as
    # (TLV type, bytes), or None when nothing is sent or the reply is already
    # queued (an abort). Every exception, from Rust or from here, ends the run
    # in `_smp_on_error`: SMP aborted, nothing verified.

    def _enh_handle_smp_tlv(self, tlv: "OTRv4TLV") -> None:
        """Process an incoming SMP TLV and queue the encrypted response.

        Fully Rust-backed: all exponents and the shared secret reside in
        Rust memory with ZeroizeOnDrop.  Python only handles the TLV framing.
        """
        self.initialize_smp()
        if self._ping_refresh_cb is not None:
            try:
                self._ping_refresh_cb()
            except Exception:
                pass

        handlers = {
            OTRv4TLV.SMP_MSG_1: self._smp_on_msg1,
            OTRv4TLV.SMP_MSG_1Q: self._smp_on_msg1,
            OTRv4TLV.SMP_MSG_2: self._smp_on_msg2,
            OTRv4TLV.SMP_MSG_3: self._smp_on_msg3,
            OTRv4TLV.SMP_MSG_4: self._smp_on_msg4,
            OTRv4TLV.SMP_ABORT: self._smp_on_abort,
        }
        handler = handlers.get(tlv.type)
        if handler is None:
            return
        try:
            reply = handler(tlv)
        except Exception as e:
            self._smp_on_error(tlv, e)
            return
        if reply is None:
            return
        out_type, resp_bytes = reply
        try:
            self._queued_smp_response = self.encrypt_with_tlvs(
                "", [OTRv4TLV(out_type, bytes(resp_bytes))]
            )
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "SMP_RESP", "ENCRYPT", str(e)[:80])

    def _smp_queue_abort(self, reason: bytes = b"") -> None:
        """Queue an SMP abort for the peer, with an optional reason code."""
        self._queued_smp_response = self.encrypt_with_tlvs(
            "", [OTRv4TLV(OTRv4TLV.SMP_ABORT, reason)]
        )

    def _smp_on_msg1(self, tlv: "OTRv4TLV") -> Optional[Tuple[int, bytes]]:
        """SMP1: the peer starts a run. Refused, held, or answered with SMP2."""
        phase = self.rust_smp.get_phase()
        # A FAILED run is over, not in progress. Treating it as a race
        # made every retry after one wrong passphrase either refused
        # ("SMP not Idle for SMP1") or, on the side with the lower
        # fingerprint, silently ignored -- the peer then waited out
        # its timeout. Rust leaves Failed for Idle and keeps the
        # attempt count and cooldown, which its guard still enforces.
        if phase in ("FAILED", "ABORTED"):
            try:
                self.rust_smp.restart_after_failure()
            except Exception:
                # The attempt limit is spent: this engine stays shut.
                self.tracer.trace(self.peer, "SMP", "SMP1_RECEIVED",
                                  f"phase={phase }", "attempt limit reached - refused")
                self._smp_queue_abort()
                return None
            phase = self.rust_smp.get_phase()
        # Already verified this session: a second run is not started
        # by the peer. Refuse it with an abort and keep the result;
        # the old race path either ignored it or threw the
        # verification away, depending on whose fingerprint was lower.
        if phase == "VERIFIED":
            self.tracer.trace(self.peer, "SMP", "SMP1_RECEIVED",
                              "phase=VERIFIED", "already verified - refused")
            self._smp_queue_abort()
            return None
        if phase != "IDLE" and not self._smp_resolve_race(phase):
            return None
        if not self.rust_smp.check_secret_set():
            self._smp_without_secret(tlv)
            return None
        self._smp_progress_notify(
            1,
            4,
            "Challenge received - computing response (ML-KEM encaps + ML-DSA-87 + ZKP)…",
            color="yellow",
        )
        resp_bytes = self.rust_smp.process_smp1_generate_smp2(tlv.value)
        self.smp_step = 2
        self._smp_progress_notify(2, 4, "Response computed - sending…", role="responder")
        return OTRv4TLV.SMP_MSG_2, resp_bytes

    def _smp_local_fingerprint(self) -> bytes:
        """This side's long-term public key, for the race tie-break."""
        try:
            if self.dake_engine and self.dake_engine.client_profile:
                cp = self.dake_engine.client_profile
                if cp.identity_pub_bytes:
                    return cp.identity_pub_bytes
                if cp.identity_key:
                    return bytes(cp.identity_key.public_bytes())
        except Exception:
            pass
        return b""

    def _smp_resolve_race(self, phase: str) -> bool:
        """Both sides started SMP at once. The lower fingerprint keeps the
        initiator role; the other yields and answers the peer's SMP1.
        Returns True when this side yields (go on to answer), False when the
        SMP1 is ignored or the run was aborted."""
        local_fp = self._smp_local_fingerprint()
        remote_fp = self._remote_long_term_pub_bytes or b""

        if not local_fp or not remote_fp:
            self.tracer.trace(
                self.peer,
                "SMP",
                "SMP1_RECEIVED",
                f"phase={phase }",
                "race detected, no fingerprints to tie-break - aborting",
            )
            try:
                self.rust_smp.abort()
            except Exception:
                pass
            self._smp_queue_abort()
            return False

        if local_fp < remote_fp:
            self.tracer.trace(
                self.peer,
                "SMP",
                "SMP1_RECEIVED",
                f"phase={phase }",
                "race detected, local_fp < remote_fp - keeping our role as initiator",
            )
            return False

        self.tracer.trace(
            self.peer,
            "SMP",
            "SMP1_RECEIVED",
            f"phase={phase }",
            "race detected, local_fp > remote_fp - yielding initiator role",
        )
        try:
            self.rust_smp.abort()
        except Exception:
            pass

        # Keep the vault across the rebuild.
        #
        # initialize_smp() constructs a NEW RustSMPVault whenever
        # rust_smp is None, so clearing rust_smp threw away the
        # "smp_secret" entry this path is about to read back --
        # and the rebind below therefore failed every single time.
        # It surfaced on two real phones as
        #
        #     SMP race-recovery: vault rebind failed
        #
        # whenever both sides ran /smp at once, which over I2P is
        # not rare: it is what happens when two people are told to
        # verify and both do.  The vault is a separate Rust object
        # holding a secret this session already owns; there is no
        # reason for a new engine to mean a new vault.
        preserved_vault = self.smp_vault
        self.rust_smp = None
        self.initialize_smp()
        if preserved_vault is not None:
            self.smp_vault = preserved_vault
        if self.rust_smp is None or self.smp_vault is None:
            raise RuntimeError("SMP race-recovery: re-init failed")
        sid_recover = self.session_id or b""
        ok = self.rust_smp.set_secret_from_vault(
            self.smp_vault, "smp_secret", sid_recover, local_fp, remote_fp
        )
        if not ok:
            # No secret to rebind: this side has not been given a
            # passphrase at all, so yielding the initiator role
            # leaves nothing to answer with.  Fall through to the
            # no-secret handling rather than raising, which
            # would report a setup problem as an internal error.
            self.tracer.trace(
                self.peer, "SMP", "SMP1_RECEIVED", "RACE_NO_SECRET",
                "yielded initiator role but no stored passphrase "
                "to rebind",
            )
        return True

    def _smp_without_secret(self, tlv: "OTRv4TLV") -> None:
        """An SMP1 arrived and this side has no passphrase.

        HOLD the SMP1 rather than abort.

        Aborting made a setup problem look like a protocol failure: the peer
        was told "SMP aborted" when the truth was that this side had never
        been given the passphrase. The engine parks the message in
        SECRET_REQUIRED instead, so once the user supplies the passphrase the
        SMP1 that already arrived can be answered -- no restart, no second
        round trip over I2P.

        What this does NOT do, and must never do, is arm input capture.
        Holding a message is a state in the SMP engine; it does not decide
        what the user's next keystroke means. The front end asks for consent
        first and only a local answer opens the passphrase prompt -- see
        otrv4plus_smpflow.py and docs/SECURITY_INVARIANTS.md INV-06.
        """
        held = False
        try:
            if self.smp_guided_prompt:
                self.rust_smp.hold_smp1(bytes(tlv.value))
                held = True
        except Exception:
            # An older core without hold_smp1, or a message it
            # would not park.  Fall back to the previous
            # behaviour rather than losing the run silently.
            self.logger.debug("hold_smp1 unavailable or refused")

        self.tracer.trace(
            self.peer,
            "SMP",
            "SMP1_RECEIVED",
            "SECRET_REQUIRED" if held else "NO_SECRET",
            "SMP1 held pending local passphrase" if held
            else "SMP1 received but no secret set - aborting",
        )

        if held:
            # No response goes out yet.  The peer waits while the
            # user is asked; if they decline or the request times
            # out, decline_held_smp1() sends the abort.
            self._smp_secret_required = True
            self._smp_progress_notify(
                0, 4,
                "Your peer asked to verify this session. A shared "
                "passphrase is needed to answer.",
                role=None, color="yellow",
            )
            return

        self._smp_progress_notify(
            0, 4,
            "SMP requested by peer, but no passphrase is stored "
            "for them. Run  /smp  to enter the passphrase you "
            "both agreed.",
            role=None, color="yellow",
        )
        self._smp_queue_abort(OTRv4TLV.SMP_ABORT_NO_SECRET)

    def _smp_on_msg2(self, tlv: "OTRv4TLV") -> Tuple[int, bytes]:
        """SMP2 (we started the run): check it, answer with SMP3."""
        self.smp_step = 2
        self._smp_progress_notify(
            2, 4, "Response received - verifying ML-DSA-87 + ZKP…", role="initiator"
        )
        resp_bytes = self.rust_smp.process_smp2_generate_smp3(tlv.value)
        self.smp_step = 3
        self._smp_progress_notify(
            3,
            4,
            "PQ proof verified - sending confirmation (ML-DSA-87 + ZKP)…",
            role="initiator",
        )
        return OTRv4TLV.SMP_MSG_3, resp_bytes

    def _smp_on_msg3(self, tlv: "OTRv4TLV") -> Tuple[int, bytes]:
        """SMP3 (the peer started the run): Rust decides; answer with SMP4."""
        resp_bytes = self.rust_smp.process_smp3_generate_smp4(tlv.value)
        self.smp_step = 4
        self._smp_progress_notify(4, 4, "Final step - sending verdict…", role="responder")

        if self.rust_smp.is_verified():
            self._smp_verified("role=responder")
        elif self.rust_smp.is_failed():
            self._smp_failed("secrets did not match (responder)")
        return OTRv4TLV.SMP_MSG_4, resp_bytes

    def _smp_on_msg4(self, tlv: "OTRv4TLV") -> None:
        """SMP4 (we started the run): Rust's verdict ends it. Nothing is sent."""
        verified = self.rust_smp.process_smp4(tlv.value)
        self.smp_step = 4
        if verified:
            self._smp_verified(
                f"role={'initiator'if self .is_initiator else 'responder'}")
        else:
            self._smp_failed("secrets did not match")
        return None

    def _smp_verified(self, detail: str) -> None:
        """Rust reported the run verified: mark the session and say so."""
        self.auto_smp_completed = True
        self.auto_smp_started = False
        self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
        self.tracer.trace(self.peer, "SMP", "VERIFIED", "STATE_UPDATED", detail)
        self._smp_progress_notify(
            4,
            4,
            "🔵✅ SMP VERIFIED - identity confirmed! (ML-KEM-1024 + ML-DSA-87 + ZKP)",
            role=None,
            color="blue",
            final=True,
        )

    def _smp_failed(self, detail: str) -> None:
        """Rust reported the secrets differ: nothing is verified."""
        self.auto_smp_started = False
        self.auto_smp_completed = False
        self.smp_step = 0
        self.tracer.trace(self.peer, "SMP", "FAILED", "STATE_UPDATED", detail)
        self._smp_progress_notify(
            0,
            4,
            "🔴❌ SMP FAILED - secrets did not match",
            role=None,
            color="red",
            final=True,
        )

    def _smp_on_abort(self, tlv: "OTRv4TLV") -> None:
        """The peer aborted. Ends the run, except a finished one."""
        if self.rust_smp.get_phase() == "VERIFIED":
            # A finished run cannot be aborted. A stale or refused-run
            # abort must not throw away a verification both sides reached.
            self.tracer.trace(self.peer, "SMP", "ABORTED", "IGNORED",
                              "abort after verification ignored")
            return None
        self.rust_smp.abort()
        self.auto_smp_started = False
        self.auto_smp_completed = False
        self.smp_step = 0
        # The reason, if the peer sent one, only chooses the wording of
        # a local line. It is peer-controlled text and is never trusted
        # as a security predicate: either way the SMP session is over
        # and nothing is verified.
        reason_bytes = bytes(getattr(tlv, "value", b"") or b"")
        no_secret = reason_bytes == OTRv4TLV.SMP_ABORT_NO_SECRET
        declined = reason_bytes == OTRv4TLV.SMP_ABORT_DECLINED
        self.tracer.trace(
            self.peer, "SMP", "ABORTED",
            "PEER_DECLINED" if declined
            else "PEER_NO_SECRET" if no_secret else "PEER_ABORT",
            "Remote peer declined the verification request" if declined
            else "Remote peer has no SMP secret configured" if no_secret
            else "Remote peer aborted SMP",
        )
        if declined:
            self._smp_progress_notify(
                0, 4,
                "SMP stopped: your peer declined the verification "
                "request. Nothing is verified, and this is not a "
                "wrong-passphrase failure.",
                role=None, color="yellow",
            )
        elif no_secret:
            self._smp_progress_notify(
                0, 4,
                "SMP stopped: your peer has not stored the passphrase "
                "yet. Ask them to run  /smp-secret <secret>  and try "
                "again. This is not a wrong-passphrase failure.",
                role=None, color="yellow",
            )
        else:
            self._smp_progress_notify(
                0, 4, "⚠ SMP aborted by remote peer", role=None, color="red"
            )
        return None

    def _smp_on_error(self, tlv: "OTRv4TLV", e: Exception) -> None:
        """Any failure while handling an SMP message: abort, verify nothing."""
        self.tracer.trace(self.peer, "ERROR", "SMP", f"0x{tlv .type :04x}", str(e)[:120])
        if self.rust_smp:
            self.rust_smp.abort()
        self.auto_smp_started = False
        self.auto_smp_completed = False
        self.smp_step = 0
        # A version mismatch is the one SMP failure that is NOT about the
        # passphrase, and it is the whole reason SMP carries a version
        # byte.  The generic handler truncates to 60 characters, which
        # would cut the message off before it says what to do about it.
        if _is_smp_version_mismatch(e):
            self._smp_progress_notify(
                0, 4, SMP_VERSION_MISMATCH_HELP,
                role=None, color="yellow", final=True,
            )
        else:
            self._smp_progress_notify(
                0, 4, f"❌ SMP error: {str (e )[:60 ]}", role=None, color="red"
            )

    _SMP_STEP_LABELS = {
        1: "Sending challenge",
        2: "Challenge sent → awaiting response",
        3: "Response received → sending verification",
        4: "Finalising",
    }

    def _smp_progress_notify(
        self,
        step: int,
        total: int,
        detail: str,
        role: Optional[str] = None,
        color: str = "yellow",
        final: bool = False,
    ) -> None:
        """Emit a visible SMP progress line with dynamic ETA and block bar.

        Each call produces one timestamped line like:

            🔐 SMP [████████░░] 2/4 · 50% · ⏱ 0:02 elapsed · ETA ~0:03

        Timing is derived from smp_start_time and per-step wall-clock
        measurements accumulated in _smp_step_times.
        """
        now = time.time()

        if not hasattr(self, "_smp_step_times"):
            self._smp_step_times: list = []
        if step > 0 and (not self._smp_step_times or self._smp_step_times[-1][0] != step):
            self._smp_step_times.append((step, now))

        t0 = getattr(self, "smp_start_time", 0) or now
        elapsed = max(0.0, now - t0)

        def _fmt(s: float) -> str:
            return f"{int (s //60 )}:{int (s %60 ):02d}"

        elapsed_str = _fmt(elapsed)
        eta_str = ""
        if step > 0 and elapsed > 0 and not final:
            avg_per_step = elapsed / step
            remaining = (total - step) * avg_per_step
            if remaining > 0:
                eta_str = f" · ETA ~{_fmt (remaining )}"

        SEGS = total if total > 0 else 4
        if step > 0 and total > 0:
            seg_w = 3
            filled = "█" * seg_w
            empty_s = "░" * seg_w
            partial = "▒" * seg_w
            bar_segs = []
            for i in range(SEGS):
                if i < step - 1:
                    bar_segs.append(filled)
                elif i == step - 1:
                    bar_segs.append(filled)
                else:
                    bar_segs.append(empty_s)
            bar_body = " ".join(bar_segs)
            pct = int((step / total) * 100)
            bar = f"[{bar_body }]"
            step_str = f"step {step }/{total }"
            if final:
                time_str = f" · ✓ {elapsed_str }"
            elif elapsed > 5:
                time_str = f" · {elapsed_str } elapsed{eta_str }"
            else:
                time_str = ""
            label = f"🔐 SMP {bar } {step_str }{time_str } · {detail }"
        else:
            label = f"🔐 SMP · {detail }"

        colored = colorize(label, color)

        if self._smp_notify_cb is not None:
            try:
                self._smp_notify_cb(colored)
            except Exception:
                pass
        elif self.tracer and self.tracer._emit_cb:
            self.tracer._emit_cb(colored)

        if final or step == 0:
            self._smp_step_times = []

    def start_smp(self, secret: str, question: Optional[str] = None) -> Optional[str]:
        """Start SMP verification using the Rust SMP engine.

        Generates SMP1, encrypts it, and returns the OTR message ready to send.
        The secret is bound to the session (session_id + fingerprints) inside Rust.
        """
        if not self._acquire_lock():
            raise RuntimeError("start_smp: could not acquire session lock (timeout)")
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise RuntimeError(
                    f"start_smp: session not encrypted (state={self .session_state !r })"
                )
            self.initialize_smp()
            if self.rust_smp is None:
                raise RuntimeError("start_smp: RustSMP is None after initialize_smp")
            phase = self.rust_smp.get_phase()
            if phase == "VERIFIED":
                raise RuntimeError("start_smp: this session is already verified")
            if phase not in ("IDLE", "FAILED", "ABORTED"):
                raise RuntimeError(f"start_smp: SMP already in progress (phase={phase })")
            if phase in ("FAILED", "ABORTED"):
                # A new run after a failed or cancelled one. Rust keeps the
                # cooldown and refuses once the attempt limit is spent.
                self.rust_smp.restart_after_failure()

            if secret:
                self.set_smp_secret(secret)

            if not self.rust_smp.check_secret_set():
                raise RuntimeError(
                    "start_smp: secret not set in Rust SMP engine - "
                    "call set_smp_secret() first or pass secret explicitly"
                )

            smp1_bytes = self.rust_smp.generate_smp1(question)
            self.smp_step = 1
            self._smp_progress_notify(
                1, 4, "Challenge sent - awaiting response (Rust ZKP)…", color="yellow"
            )
            return self.encrypt_with_tlvs("", [OTRv4TLV(OTRv4TLV.SMP_MSG_1, bytes(smp1_bytes))])
        except Exception as e:
            import traceback as _tb

            msg = f"start_smp: Error: {e }"
            self.logger.debug("start_smp FAILED")

            raise RuntimeError(f"SMP start failed: {e }") from e
        finally:
            self._release_lock()

    # ─── held SMP1: the responder-with-no-passphrase path ────────────────────
    #
    # Three methods, and the split between them is the security boundary.
    # `smp_secret_required` is set by a REMOTE message arriving.  The other two
    # are called only after the local user has answered a prompt.  Nothing here
    # reads input; the front end owns that and hands down a result.

    def smp_secret_required(self) -> bool:
        """True while an SMP1 from the peer is parked awaiting a passphrase."""
        if self.rust_smp is None:
            return False
        try:
            return self.rust_smp.get_phase() == "SECRET_REQUIRED"
        except Exception:
            return False

    def resume_held_smp1(self) -> Optional[str]:
        """Answer the parked SMP1 now that a passphrase has been stored.

        Returns the encrypted SMP2 to send, or raises.  The caller must have
        called set_smp_secret() first -- the engine refuses otherwise, which is
        the fail-closed half of "only local input can supply the secret".
        """
        if not self._acquire_lock():
            raise RuntimeError("resume_held_smp1: could not acquire session lock")
        try:
            if self.rust_smp is None:
                raise RuntimeError("no SMP engine")
            # The engine is the authority on whether the message is still
            # held; ask it before consuming so a resume that cannot succeed
            # says so plainly rather than as a generic engine error.
            if not self.rust_smp.has_held_smp1():
                raise RuntimeError(
                    "no SMP1 is being held for this session")
            smp2 = self.rust_smp.resume_held_smp1_generate_smp2()
            # Cleared only now.  Setting it before the call meant a failed
            # resume left the session claiming no request was outstanding
            # while the engine was still holding one.
            self._smp_secret_required = False
            self.smp_step = 2
            self._smp_progress_notify(
                2, 4, "Passphrase accepted - answering the challenge…",
                role="responder",
            )
            return self.encrypt_with_tlvs(
                "", [OTRv4TLV(OTRv4TLV.SMP_MSG_2, bytes(smp2))])
        finally:
            self._release_lock()

    def abort_smp(self) -> Optional[str]:
        """Cancel an SMP run in either direction, at any stage, and tell the peer.

        The local user pressed Cancel. The Rust run is aborted, any parked
        SMP1 is discarded, the bound passphrase is dropped from the vault, and
        the returned OTR message carries SMP_ABORT so the peer stops waiting.
        None when there is nothing to abort. An aborted run proves nothing,
        so it leaves the session unverified.
        """
        if not self._acquire_lock():
            return None
        try:
            if self.rust_smp is None:
                return None
            try:
                self.rust_smp.abort()
            except Exception:
                self.logger.debug("rust_smp.abort failed")
            try:
                self.rust_smp.discard_held_smp1()
            except Exception:
                pass
            if self.smp_vault is not None:
                try:
                    self.smp_vault.remove("smp_secret")
                except Exception:
                    pass
            self._smp_secret_required = False
            self.smp_step = 0
            return self.encrypt_with_tlvs("", [OTRv4TLV(OTRv4TLV.SMP_ABORT, b"")])
        finally:
            self._release_lock()

    def decline_held_smp1(self, reason: bytes = b"") -> Optional[str]:
        """Drop the parked SMP1 and tell the peer.

        Used for an explicit decline, for a consent request that timed out, and
        for teardown while one was open.  Storing nothing is the point: a
        declined request must leave no passphrase and no state behind.
        """
        if not self._acquire_lock():
            return None
        try:
            if self.rust_smp is None:
                return None
            self._smp_secret_required = False
            try:
                self.rust_smp.discard_held_smp1()
            except Exception:
                self.logger.debug("discard_held_smp1 failed")
            self.smp_step = 0
            return self.encrypt_with_tlvs(
                "", [OTRv4TLV(OTRv4TLV.SMP_ABORT,
                              reason or OTRv4TLV.SMP_ABORT_DECLINED)])
        finally:
            self._release_lock()

    def process_smp_message(self, data: bytes) -> Optional[str]:
        """Process a raw SMP TLV (type+len+value) using the Rust engine.

        Used by the SessionManager-level dispatch path.  For the session-level
        TLV handler see _enh_handle_smp_tlv.
        """
        if not self._acquire_lock():
            return None
        try:
            if len(data) < 4:
                return None
            self.initialize_smp()
            tlv_type = struct.unpack_from("!H", data, 0)[0]
            tlv_len = struct.unpack_from("!H", data, 2)[0]
            tlv_val = data[4 : 4 + tlv_len]
            out_type = None
            resp = None
            if tlv_type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                if self.rust_smp.get_phase() in ("FAILED", "ABORTED"):
                    self.rust_smp.restart_after_failure()
                resp = self.rust_smp.process_smp1_generate_smp2(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_2
            elif tlv_type == OTRv4TLV.SMP_MSG_2:
                resp = self.rust_smp.process_smp2_generate_smp3(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_3
            elif tlv_type == OTRv4TLV.SMP_MSG_3:
                resp = self.rust_smp.process_smp3_generate_smp4(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_4

                if self.rust_smp.is_verified():
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                elif self.rust_smp.is_failed():
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
            elif tlv_type == OTRv4TLV.SMP_MSG_4:
                verified = self.rust_smp.process_smp4(tlv_val)
                if verified:
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(
                        self.peer, "SMP", "VERIFIED", "STATE_UPDATED", "role=initiator"
                    )
                    self._smp_progress_notify(
                        4,
                        4,
                        "🔵✅ SMP VERIFIED - identity confirmed!",
                        role=None,
                        color="blue",
                        final=True,
                    )
                else:
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "FAILED",
                        "STATE_UPDATED",
                        "secrets did not match (initiator)",
                    )
                    self._smp_progress_notify(
                        0,
                        4,
                        "🔴❌ SMP FAILED - secrets did not match",
                        role=None,
                        color="red",
                        final=True,
                    )
                return None
            elif tlv_type == OTRv4TLV.SMP_ABORT:
                if self.rust_smp.get_phase() != "VERIFIED":
                    self.rust_smp.abort()
                return None
            if resp is not None and out_type is not None:
                return self.encrypt_with_tlvs("", [OTRv4TLV(out_type, bytes(resp))])
            return None
        except Exception as e:
            import traceback as _tb

            self.logger.debug("process_smp_message FAILED")
            return None
        finally:
            self._release_lock()

    def get_smp_status(self) -> Dict[str, Any]:
        """Return SMP status from the Rust engine."""
        if not self._acquire_lock():
            return {
                "state": "NONE",
                "verified": False,
                "failed": False,
                "progress": "0/4",
                "can_start_smp": False,
                "secret_set": False,
            }
        try:
            if self.rust_smp is None:
                return {
                    "state": "NONE",
                    "verified": False,
                    "failed": False,
                    "progress": "0/4",
                    "has_question": False,
                    "question": "",
                    "can_start_smp": self.session_state == SessionState.ENCRYPTED,
                    "can_retry": False,
                    "retry_count": 0,
                    "expired": False,
                    "secret_set": False,
                }
            phase = self.rust_smp.get_phase()
            verified = self.rust_smp.is_verified()
            failed = phase == "FAILED"
            step_map = {
                "IDLE": 0,
                "AWAITING_MSG2": 1,
                "AWAITING_MSG3": 2,
                "AWAITING_MSG4": 3,
                "VERIFIED": 4,
                "FAILED": 0,
            }
            step = step_map.get(phase, 0)
            return {
                "state": phase,
                "verified": verified or self.auto_smp_completed,
                "failed": failed,
                "failure_reason": "" if not failed else "secrets did not match",
                "progress": f"{step }/4",
                "has_question": False,
                "question": "",
                "can_start_smp": phase in ("IDLE", "FAILED")
                and self.session_state == SessionState.ENCRYPTED,
                "can_retry": failed,
                "retry_count": 0,
                "expired": False,
                "secret_set": self.rust_smp.check_secret_set(),
            }
        except Exception as e:
            self.logger.debug("get_smp_status FAILED")
            return {
                "state": "NONE",
                "verified": False,
                "failed": False,
                "progress": "0/4",
                "can_start_smp": self.session_state == SessionState.ENCRYPTED,
            }
        finally:
            self._release_lock()

    def get_smp_progress(self) -> Tuple[int, int]:
        """Get SMP progress as (step, total_steps)."""
        if self.rust_smp is None:
            return (0, 4)
        phase = self.rust_smp.get_phase()
        step_map = {
            "IDLE": 0,
            "AWAITING_MSG2": 1,
            "AWAITING_MSG3": 2,
            "AWAITING_MSG4": 3,
            "VERIFIED": 4,
            "FAILED": 0,
        }
        return (step_map.get(phase, 0), 4)

    def set_smp_secret(self, secret: str):
        """Bind the SMP secret to the current session via the Rust vault.

        Flow:
          1. Encode secret to a bytearray (mutable, can be wiped).
          2. Store bytes in RustSMPVault (Rust-owned, ZeroizeOnDrop).
          3. Call rust_smp.set_secret_from_vault() - bytes never leave Rust
             as a Python object on the SHAKE-256/HMAC path.
          4. Overwrite the bytearray and delete it.
          5. Set auto_smp_secret = True (flag only - plaintext is NOT stored).

        Raises:
            ValueError:   secret shorter than 8 characters.
            RuntimeError: SMP protocol run already active (never rebind mid-run).
        """
        _MIN_LEN = 8
        if len(secret) < _MIN_LEN:
            raise ValueError(f"SMP secret must be at least {_MIN_LEN } characters.")

        def _fill(vault):
            raw = bytearray(secret.encode("utf-8"))
            try:
                # store_from_bytearray, not store(bytes(raw)).
                #
                # The bytearray exists so it can be wiped -- but `bytes(raw)`
                # would make an immutable copy that nothing can overwrite.
                # Handing the bytearray straight down means Rust copies it into
                # a ZeroizeOnDrop entry and zeroes our buffer before returning.
                vault.store_from_bytearray("smp_secret", raw)
            finally:
                # Belt and braces: store_from_bytearray already zeroed it, and
                # this still runs if the call raised before reaching Rust.
                for i in range(len(raw)):
                    raw[i] = 0
                del raw

        self._bind_smp_secret(_fill)

    def set_smp_secret_from_store(self, store, peer: str) -> bool:
        """Bind `peer`'s passphrase from a Rust `SmpSecretStore`.

        The auto-respond path. The passphrase goes store -> this session's
        `RustSMPVault` -> `RustSMP` without becoming a Python object; there is
        no way for this method to see it. Returns False when none is stored.
        """
        if not store.has(peer):
            return False

        def _fill(vault):
            if not store.bind_into(peer, vault, "smp_secret"):
                raise RuntimeError("the stored passphrase disappeared while binding")

        self._bind_smp_secret(_fill)
        return True

    def _bind_smp_secret(self, fill) -> None:
        """Phase checks, then `fill(vault)`, then bind the vault entry into SMP
        with this session's id and both fingerprints. Shared by both setters."""
        if not self._acquire_lock():
            return
        try:

            if self.rust_smp is not None:
                phase = self.rust_smp.get_phase()
                # SECRET_REQUIRED is included deliberately: it means a peer's
                # SMP1 is parked waiting for exactly this call.  The others are
                # states with no run in flight.  AWAITING_MSG2/3/4 are not, and
                # rebinding under those would change the secret mid-proof.
                if phase not in ("IDLE", "FAILED", "VERIFIED", "ABORTED",
                                 "SECRET_REQUIRED"):
                    raise RuntimeError(
                        f"Cannot rebind SMP secret while SMP is active "
                        f"(current phase: {phase }). Abort the current run first."
                    )
            self.initialize_smp()
            if self.rust_smp is None or self.smp_vault is None:
                raise RuntimeError("Rust SMP engine not initialized")

            sid = self.session_id or b""
            local_fp = b""
            try:
                if self.dake_engine and self.dake_engine.client_profile:
                    cp = self.dake_engine.client_profile

                    if cp.identity_pub_bytes:
                        local_fp = cp.identity_pub_bytes
                    elif cp.identity_key:
                        local_fp = bytes(cp.identity_key.public_bytes())
            except Exception:
                pass
            remote_fp = self._remote_long_term_pub_bytes or b""

            fill(self.smp_vault)
            ok = self.rust_smp.set_secret_from_vault(
                self.smp_vault, "smp_secret", sid, local_fp, remote_fp
            )
            if not ok:
                raise RuntimeError("Vault key not found after store - internal error")

            if not self.rust_smp.check_secret_set():
                raise RuntimeError("Rust SMP secret not stored after set_secret_from_vault")

            self.auto_smp_secret = True
        finally:
            self._release_lock()

    def can_start_smp(self) -> bool:
        """Check if SMP can be started."""
        if not self._acquire_lock():
            return False
        try:
            if self.session_state != SessionState.ENCRYPTED:
                return False
            if self.rust_smp is None:
                return True
            phase = self.rust_smp.get_phase()
            return phase in ("IDLE", "FAILED")
        finally:
            self._release_lock()
