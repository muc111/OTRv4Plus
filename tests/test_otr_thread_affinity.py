"""OTR crypto must run on exactly one thread.

A live handshake crashed the process:

    thread '<unnamed>' panicked at pyo3-0.24.2/src/impl_/pyclass.rs:1105:
    assertion `left == right` failed:
    otrv4_core::dake::DakeOutput is unsendable, but sent to another thread
      left: ThreadId(3)   right: ThreadId(2)

`otrv4_core::dake::DakeOutput` is `#[pyclass(unsendable)]`. PyO3 records the
thread that created such an object and panics on access from any other. The
handle is created while one inbound message is processed (generate_dake2 /
process_dake2), stored on the session, and consumed while a LATER inbound
message is (building the ratchet from it) -- so it must not move threads
between those two points.

The OTR executor was configured `max_workers=2` while its own comment called
it a "single-thread executor". A ThreadPoolExecutor only spawns its second
worker when a task is submitted while the first is busy, so over I2P -- where
DAKE messages normally arrive far apart -- one thread handled everything and
nothing went wrong for months. The crash came when a fragmented DAKE and
DAKE3 arrived back to back.

Serialising is independently correct: OTR is a stateful ratchet, and
processing two messages for one peer concurrently races the ratchet, the
skipped-key handling and the SMP state machine.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("slixmpp")
import otrv4plus_xmpp as xmpp


def _threads_used(executor, submissions=6, gap=0.0, work=0.05):
    """Distinct OS threads a pool uses for back-to-back submissions."""
    seen = []
    lock = threading.Lock()

    def _work():
        with lock:
            seen.append(threading.get_ident())
        time.sleep(work)

    futures = []
    for _ in range(submissions):
        futures.append(executor.submit(_work))
        if gap:
            time.sleep(gap)
    for future in futures:
        future.result()
    return len(set(seen))


class TestTheExecutorIsSingleThreaded:

    def test_the_pool_is_configured_for_one_worker(self):
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            assert pool._max_workers == 1
        finally:
            pool.shutdown()

    def test_the_client_builds_a_one_worker_pool(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.__init__)
        assert 'max_workers=1, thread_name_prefix="otr-crypto"' in src, (
            "the OTR executor is not single-threaded; an unsendable "
            "DakeOutput can move threads mid-handshake and panic")

    def test_one_worker_never_crosses_threads_under_load(self):
        # The condition that actually crashed: messages arriving together.
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="otr-crypto")
        try:
            assert _threads_used(pool) == 1
        finally:
            pool.shutdown()

    def test_two_workers_would_cross_threads(self):
        # Documents why the old value was unsafe rather than merely untidy.
        pool = ThreadPoolExecutor(max_workers=2)
        try:
            assert _threads_used(pool) > 1, (
                "a 2-worker pool no longer spreads work, so the premise of "
                "this whole file needs rechecking")
        finally:
            pool.shutdown()

    def test_slow_arrivals_hid_the_bug(self):
        # Why it "never happened before": spaced-out submissions reuse the
        # first worker even with two available.
        pool = ThreadPoolExecutor(max_workers=2)
        try:
            assert _threads_used(pool, submissions=4, gap=0.10, work=0.01) == 1
        finally:
            pool.shutdown()


class TestEveryOtrEntryPointUsesThatExecutor:
    """One serialising queue is only a guarantee if nothing bypasses it."""

    def test_inbound_otr_goes_through_the_executor(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._handle_otr_in_async)
        assert "self._otr_executor, self.otr.handle_incoming_message" in src

    def test_smp_start_goes_through_the_executor(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert "run_in_executor(self._otr_executor, _do_start)" in src

    def test_there_is_no_synchronous_otr_engine_fallback(self):
        """The sync fallback is deleted, not merely uncalled.

        `_handle_otr_in` called the engine directly on the event loop while
        every live path ran it on the executor. Dead code is the wrong shape
        of safe here: it reads as a legitimate entry point, so the next person
        to wire it up reintroduces the thread-affinity crash without ever
        touching the executor. Asserting on callers would still pass with the
        trap sitting in the file; asserting on existence does not.
        """
        assert not hasattr(xmpp.OTRv4PlusXMPP, "_handle_otr_in"), (
            "the synchronous OTR fallback is back; it runs the engine on the "
            "event loop and can move an unsendable DakeOutput across threads")

    def test_the_engine_is_never_called_straight_from_the_event_loop(self):
        # Any inbound handling must go through run_in_executor. A bare
        # `self.otr.handle_incoming_message(...)` call is the shape that
        # bypasses it.
        import inspect
        source = inspect.getsource(xmpp)
        direct = [line.strip() for line in source.split("\n")
                  if "otr.handle_incoming_message(" in line
                  and "run_in_executor" not in line
                  and "_otr_executor" not in line]
        assert direct == [], (
            "the OTR engine is called synchronously on the event loop: %r"
            % direct)

    def test_the_default_executor_is_not_used_for_otr(self):
        # run_in_executor(None, ...) would use the shared default pool, whose
        # worker count is unbounded in practice.
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._handle_otr_in_async)
        assert "run_in_executor(\n" in src or "run_in_executor(" in src
        assert "None, self.otr" not in src


class TestOnlyDakeOutputIsUnsendable:
    """If another unsendable class appears, this analysis needs redoing."""

    def test_the_rust_core_declares_one_unsendable_pyclass(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "Rust" / "src"
        if not root.is_dir():
            pytest.skip("Rust sources not present")
        found = []
        for path in root.glob("*.rs"):
            for number, line in enumerate(
                    path.read_text(encoding="utf-8").split("\n"), 1):
                if "unsendable" in line and "pyclass" in line:
                    found.append("%s:%d" % (path.name, number))
        assert found == ["dake.rs:183"], (
            "the set of unsendable pyclasses changed: %r. Each one is pinned "
            "to its creating thread, so any new one has to be checked against "
            "the executor boundary." % found)


class TestTheDakeOutputLifecycleStaysInbound:
    """One worker only helps if the whole lifecycle runs on that worker.

    Serialising inbound processing is not enough on its own: if a DakeOutput
    were created while an inbound message was handled (on the executor) and
    consumed from an outbound path (on the event loop), it would still cross
    threads and still panic. So the lifecycle has to be inbound-only:

        created   generate_dake2 / process_dake2
        stored    session._dake_output
        consumed  _initialize_ratchet  <- _establish_session
                                       <- _handle_dake2 / _handle_dake3

    All of which hang off handle_incoming_message, whose single call site is
    the executor. This test walks the real engine's call graph so the closure
    is checked rather than asserted.
    """

    @staticmethod
    def _call_graph():
        import ast
        import pathlib
        path = pathlib.Path(__file__).resolve().parent.parent / "otrv4+.py"
        if not path.is_file():
            pytest.skip("engine source not present")
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        bodies = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bodies.setdefault(node.name, []).append(
                    ast.get_source_segment(source, node) or "")
        return bodies

    def _reaches(self, bodies, start, target, seen=None, depth=0):
        seen = seen or set()
        if start in seen or depth > 8:
            return False
        seen = seen | {start}
        for segment in bodies.get(start, []):
            if ("%s(" % target) in segment:
                return True
            for name in bodies:
                if name != start and ("%s(" % name) in segment:
                    if self._reaches(bodies, name, target, seen, depth + 1):
                        return True
        return False

    def test_the_handle_is_created_only_while_handling_inbound(self):
        bodies = self._call_graph()
        for maker in ("generate_dake2", "process_dake2"):
            assert self._reaches(bodies, "handle_incoming_message", maker)
            assert not self._reaches(bodies, "handle_outgoing_message", maker), (
                "%s is reachable from the outbound path, which runs on the "
                "event loop rather than the OTR executor" % maker)

    def test_the_handle_is_consumed_only_while_handling_inbound(self):
        bodies = self._call_graph()
        assert self._reaches(bodies, "handle_incoming_message",
                             "_establish_session")
        assert not self._reaches(bodies, "handle_outgoing_message",
                                 "_establish_session"), (
            "the ratchet is built from the outbound path; a DakeOutput "
            "created on the executor would be consumed on the event loop")

    def test_the_outbound_path_cannot_initialise_a_ratchet(self):
        """The one route that looks reachable, and why it is not.

        `handle_outgoing_message` does reach `transition_dake`, whose body
        mentions `_initialize_ratchet` -- so a textual reachability check
        flags it. The call is guarded by `if new_state ==
        DAKEState.ESTABLISHED`, and the only site that calls transition_dake
        from outside passes SENT_DAKE1, so the branch is never taken from the
        event loop.

        That guard is the invariant, so the guard is what is asserted. If
        anyone later transitions to ESTABLISHED from an outbound path, this
        fails and the thread affinity of _dake_output has to be rechecked.
        """
        import pathlib
        import re
        path = pathlib.Path(__file__).resolve().parent.parent / "otrv4+.py"
        if not path.is_file():
            pytest.skip("engine source not present")
        source = path.read_text(encoding="utf-8")
        sites = [line.strip() for line in source.split("\n")
                 if "transition_dake(" in line
                 and not line.strip().startswith("def ")]
        assert sites, "transition_dake is never called; the graph has moved"
        for site in sites:
            assert "ESTABLISHED" not in site, (
                "transition_dake(ESTABLISHED) runs _initialize_ratchet, which "
                "consumes _dake_output. Reached from the event loop that "
                "crosses threads: %s" % site)
        # And the guard itself is still what stands between the two.
        assert re.search(r"if new_state == DAKEState\.ESTABLISHED:\s*\n"
                         r"(\s+.*\n)*?\s+self\._initialize_ratchet\(\)",
                         source), (
            "_initialize_ratchet is no longer guarded by the ESTABLISHED "
            "transition inside transition_dake")
