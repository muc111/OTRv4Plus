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

    def test_no_live_inbound_path_bypasses_it(self):
        # _handle_otr_in is a retained sync fallback that calls the engine
        # directly on the event loop. It is dead code, and it must stay dead:
        # wiring it up would reintroduce exactly this crash.
        import inspect
        source = inspect.getsource(xmpp)
        calls = [line for line in source.split("\n")
                 if "_handle_otr_in(" in line and "def " not in line]
        assert calls == [], (
            "the sync OTR fallback is live again; it runs the engine on the "
            "event loop while inbound messages run on the executor: %r" % calls)

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
