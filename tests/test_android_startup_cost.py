#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Startup does its work ONCE, and repeating it is not merely slow.

WHAT WAS MEASURED
=================
`ChaquopyOtrCore.initialize()` on a developer machine, warm bytecode:

    ensure_runtime            0.1 ms
    load_orchestration       47   ms
    collect(selftest=True)  173   ms   <- 58% of the path
    EnhancedSessionManager   77   ms
    TOTAL                   298   ms

Inside `collect`, `_otrv4plus_info` was ~106ms of that, spent constructing an
`EnhancedSessionManager` purely to ask "does one come up, and what is its
fingerprint prefix" -- then dropping it, while `initialize()` went on to build
the engine it actually uses. Two identities generated per launch, one thrown
away. A handset is slower than the machine those numbers came from.

THE PART THAT IS NOT ABOUT SPEED
================================
`initialize()` had no idempotence guard and two callers: the service (guarded
by its own flag) and `ConnectionViewModel.onServiceConnected`, guarded by
nothing -- so it ran on every service bind, which is every Activity creation:
launch, rotation, return to the app.

It is not a query. It builds an engine and REPLACES `app` with a new `OtrApp`
over it. Measured over a live session:

    after first initialize + DAKE : security=ENCRYPTED  OTR asked=True
    after a second initialize()   : security=PLAINTEXT  OTR asked=False

A fresh engine has no sessions, so rotating the phone dropped an established
one. And a fresh `OtrApp` has a fresh `OtrMode`, so a conversation the user
had explicitly asked to encrypt became willing to send plaintext again --
which is the downgrade `OtrMode` exists to refuse.

So these tests pin a security property and a cost together, because in this
case they were the same defect.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from android_bridge import diagnostics                     # noqa: E402
from android_bridge.app import OtrApp                       # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_KT = os.path.join(
    ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
    "android", "bridge", "ChaquopyOtrCore.kt")
VIEWMODEL_KT = os.path.join(
    ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
    "android", "ConnectionViewModel.kt")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# ── the diagnostic probe reuses the engine it is given ───────────────────────

class TestDiagnosticsDoesNotBuildASecondEngine:
    """The probe's own engine was ~106ms of a ~298ms startup, discarded."""

    def test_a_supplied_engine_is_reused(self):
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        info = diagnostics._otrv4plus_info(engine)
        assert info["engine_reused"] is True
        assert info["initialized"] is True

    def test_a_supplied_engine_is_not_replaced(self):
        """Not merely "an engine was used" -- THE one that was passed. A probe
        that quietly built its own would report an identity the app is not
        actually running under."""
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        info = diagnostics._otrv4plus_info(engine)
        assert info["fingerprint_prefix"] == (engine.get_fingerprint() or "")[:16]

    def test_collect_passes_the_engine_through(self):
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        report = diagnostics.collect(False, {"note": "test"}, engine)
        assert report["otrv4plus"]["engine_reused"] is True

    def test_no_engine_still_produces_a_full_report(self):
        """THE FAILURE PATH, and the reason the fallback stays. When the
        caller has no engine because construction failed, this probe is what
        finds out why -- and the report matters most exactly then."""
        report = diagnostics.collect(False, {"note": "test"}, None)
        assert report["otrv4plus"]["engine_reused"] is False
        assert "initialized" in report["otrv4plus"]
        for section in ("python", "abi", "rust_core", "otrv4plus",
                        "at_rest_kdf", "transport_deps", "native_libraries"):
            assert section in report, "%s vanished from the report" % section

    def test_the_old_two_argument_call_still_works(self):
        """`collect` is called from Kotlin and from the Debug screen. Adding a
        parameter must not break a caller that does not pass it."""
        report = diagnostics.collect(False, {"note": "test"})
        assert report["otrv4plus"]["engine_reused"] is False
        assert "ok" in report

    def test_the_report_still_says_whether_the_engine_came_up(self):
        """`initialized` feeds `InitResult.engineInitialized` and the `ok`
        flag that gates the connect screen. Reusing an engine must not make
        that claim weaker or absent."""
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        assert diagnostics.collect(False, {}, engine)["otrv4plus"]["initialized"]

    def test_a_broken_engine_is_reported_not_hidden(self):
        """Reuse must not turn a dead engine into a clean report."""
        class Broken:
            def get_fingerprint(self):
                raise RuntimeError("no identity")

        info = diagnostics._otrv4plus_info(Broken())
        assert info["initialized"] is False
        assert "error" in info

    def test_the_probe_leaks_no_key_material(self):
        """Unchanged rule, re-asserted because this path now touches the REAL
        engine rather than a throwaway: only a truncated PUBLIC fingerprint
        may appear."""
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        info = diagnostics._otrv4plus_info(engine)
        assert len(info["fingerprint_prefix"]) <= 16
        rendered = diagnostics.as_text(
            diagnostics.collect(False, {}, engine)).lower()
        for banned in ("private", "secret", "seed", "-----begin"):
            assert banned not in rendered


# ── initialisation happens once ──────────────────────────────────────────────

class TestInitialiseOnce:
    """The Kotlin guard, and the Python invariant it protects.

    Compose cannot run here, so the guard itself is asserted structurally --
    but the CONSEQUENCE of not having one is driven against the real facade,
    which is the half that actually matters.
    """

    def test_initialize_returns_early_when_already_initialised(self):
        source = _read(CORE_KT)
        body = source[source.index("override fun initialize()"):]
        body = body[:body.index("\n    ", body.index("catch (t: Throwable)"))]
        assert "initResult?.let { if (app != null) return it }" in body, (
            "initialize() has no idempotence guard; it rebuilds the engine "
            "and replaces the live OtrApp on every caller")

    def test_a_failed_initialisation_is_not_cached(self):
        """The guard is on `app`, which stays null when the work threw, so a
        retry is still a retry. Caching a failure forever would be worse than
        repeating the work."""
        source = _read(CORE_KT)
        assert "if (app != null) return it" in source, (
            "the guard no longer checks `app`, so a failed initialisation "
            "could be cached and never retried")

    def test_the_result_is_cached_only_on_success(self):
        source = _read(CORE_KT)
        success = source[source.index("InitResult("):source.index("catch (t: Throwable)")]
        assert ".also { initResult = it }" in success
        failure = source[source.index("catch (t: Throwable)"):]
        failure = failure[:failure.index("override fun")]
        assert "initResult =" not in failure, (
            "the failure path caches a result, so a transient failure would "
            "become permanent")

    def test_shutdown_clears_the_cache(self):
        """Otherwise a sign-out would leave a stale report and the guard would
        refuse to rebuild an engine that no longer exists."""
        source = _read(CORE_KT)
        shutdown = source[source.index("override fun shutdown"):]
        shutdown = shutdown[:shutdown.index("override fun localFingerprint")]
        assert "initResult = null" in shutdown, (
            "shutdown does not clear initResult, so the cached report "
            "outlives the engine it describes")

    def test_the_view_model_still_asks(self):
        """The guard must not be implemented by deleting the caller. The
        connect screen needs a report to show, and now gets the cached one
        rather than paying for a second initialisation."""
        assert "core?.initialize()" in _read(VIEWMODEL_KT), (
            "the ViewModel no longer asks for the report, so the connect "
            "screen has nothing to show while the service starts")

    def test_a_second_facade_over_a_new_engine_loses_the_session(self):
        """WHY THE GUARD EXISTS, driven rather than described.

        This is what the second `initialize()` did. If this ever stops being
        true the guard could be relaxed -- and until then it must not be.
        """
        otr = pytest.importorskip("otrv4_")
        pytest.importorskip("otrv4_core")
        first = OtrApp(otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True)))
        first._mode.request("bob@example.test")
        assert first._mode.may_send_plaintext("bob@example.test", False) is False

        second = OtrApp(otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True)))
        assert second._mode.may_send_plaintext("bob@example.test", False) is True, (
            "a fresh OtrApp no longer forgets that OTR was requested; if that "
            "is genuinely true now, re-read whether the guard is still needed")

    def test_the_mode_reset_is_a_downgrade_not_a_detail(self):
        """Naming the consequence so the guard is not removed as an
        optimisation. Forgetting that OTR was asked for makes a conversation
        willing to send plaintext again."""
        otr = pytest.importorskip("otrv4_")
        app = OtrApp(otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True)))
        peer = "bob@example.test"
        assert app._mode.may_send_plaintext(peer, False) is True
        app._mode.request(peer)
        assert app._mode.may_send_plaintext(peer, False) is False


# ── the startup path stays lean ──────────────────────────────────────────────

class TestTheStartupPathDoesNotRegrow:

    def test_initialize_builds_exactly_one_engine(self):
        source = _read(CORE_KT)
        body = source[source.index("override fun initialize()"):]
        body = body[:body.index("catch (t: Throwable)")]
        built = body.count('callAttr("EnhancedSessionManager"')
        assert built == 1, (
            "initialize() constructs %d engines; each is identity-key work "
            "and only one is used" % built)

    def test_initialize_builds_exactly_one_facade(self):
        source = _read(CORE_KT)
        body = source[source.index("override fun initialize()"):]
        body = body[:body.index("catch (t: Throwable)")]
        # Matched on the argument, not the call spelling: the
        # construction is wrapped across lines and the rule is
        # "one facade", not "one particular formatting".
        assert body.count('"OtrApp"') == 1

    def test_the_engine_is_built_before_diagnostics(self):
        """Order matters: diagnostics can only reuse an engine that exists."""
        source = _read(CORE_KT)
        body = source[source.index("override fun initialize()"):]
        body = body[:body.index("catch (t: Throwable)")]
        assert body.index('callAttr("EnhancedSessionManager"') < \
            body.index('callAttr(\n                "collect"'), (
            "diagnostics runs before the engine exists, so it must build its "
            "own and the duplicate is back")

    def test_the_diagnostic_call_passes_the_engine(self):
        source = _read(CORE_KT)
        assert '"collect", true, androidBuildInfo(py), engine' in source
