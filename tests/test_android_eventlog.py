"""Events crossing to Kotlin: bounded, ordered, and delivered once.

Three properties, each with a failure that shows up as a user-visible bug
rather than a crash, which is why they are worth pinning.

**Once.** An event handed over twice puts a message on screen twice, and the UI
cannot tell a duplicate from a peer who really did send the same text again.

**In order.** Chat is a sequence. Out-of-order delivery reads as a garbled
conversation, and the reader blames the sender.

**Bounded.** A screen that stops draining -- backgrounded, wedged -- must cost
a fixed amount of memory rather than growing until Android kills the process.
And a gap must be *reported*: silently losing messages is the bug report
nobody can reproduce.
"""

import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.eventlog import DEFAULT_CAPACITY, EventQueue


class Fake:
    """Not a dataclass: exercises the non-dataclass branch of _describe."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def message(peer="bob@x.i2p", body="hello", ts=1.0):
    from android_bridge.events import MessageReceived
    return MessageReceived(peer=peer, body=body, timestamp=ts)


class TestDeliveredOnce:

    def test_drain_removes_what_it_returns(self):
        q = EventQueue()
        q.on_event(message())
        assert len(q.drain()) == 1
        assert q.drain() == []

    def test_a_second_drain_does_not_repeat_a_message(self):
        q = EventQueue()
        q.on_event(message(body="only once"))
        first = q.drain()
        second = q.drain()
        assert [e["body"] for e in first] == ["only once"]
        assert second == []

    def test_a_partial_drain_leaves_the_rest(self):
        q = EventQueue()
        for i in range(5):
            q.on_event(message(body=str(i)))
        got = q.drain(limit=2)
        assert [e["body"] for e in got] == ["0", "1"]
        assert q.pending() == 3
        assert [e["body"] for e in q.drain()] == ["2", "3", "4"]


class TestInOrder:

    def test_oldest_first(self):
        q = EventQueue()
        for i in range(10):
            q.on_event(message(body=str(i)))
        assert [e["body"] for e in q.drain()] == [str(i) for i in range(10)]

    def test_every_event_carries_a_rising_sequence(self):
        """So the UI can detect a gap rather than infer one."""
        q = EventQueue()
        for i in range(5):
            q.on_event(message(body=str(i)))
        seqs = [e["seq"] for e in q.drain()]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 5

    def test_sequence_keeps_rising_across_drains(self):
        q = EventQueue()
        q.on_event(message())
        first = q.drain()[0]["seq"]
        q.on_event(message())
        assert q.drain()[0]["seq"] > first


class TestBounded:

    def test_it_does_not_grow_without_limit(self):
        q = EventQueue(capacity=10)
        for i in range(1000):
            q.on_event(message(body=str(i)))
        assert q.pending() == 10

    def test_the_oldest_go_first(self):
        """Keeping the newest is the right choice for a chat backlog: the
        recent end is what the user is about to read."""
        q = EventQueue(capacity=3)
        for i in range(6):
            q.on_event(message(body=str(i)))
        assert [e["body"] for e in q.drain()] == ["3", "4", "5"]

    def test_a_gap_is_counted_rather_than_hidden(self):
        q = EventQueue(capacity=3)
        for i in range(10):
            q.on_event(message(body=str(i)))
        assert q.dropped() == 7, (
            "silently losing events is the bug report nobody can reproduce")

    def test_nothing_dropped_means_zero(self):
        q = EventQueue(capacity=10)
        q.on_event(message())
        assert q.dropped() == 0

    def test_a_capacity_of_zero_is_not_accepted(self):
        q = EventQueue(capacity=0)
        q.on_event(message())
        assert q.pending() == 1


class TestItNeverRaises:
    """OtrApp._emit treats a sink that throws as a UI bug it must not die of.
    A sink relying on that forbearance is borrowing someone else's safety net."""

    def test_an_object_it_cannot_describe_is_swallowed(self):
        class Hostile:
            def __getattribute__(self, name):
                raise RuntimeError("no")

        q = EventQueue()
        q.on_event(Hostile())          # must not raise

    def test_a_non_dataclass_event_still_records_its_type(self):
        q = EventQueue()
        q.on_event(Fake(peer="a@b.i2p"))
        got = q.drain()
        assert got and got[0]["type"] == "Fake"


class TestItCrossesTheBoundaryAsPrimitives:

    def test_every_value_is_a_primitive(self):
        q = EventQueue()
        q.on_event(message())
        for key, value in q.drain()[0].items():
            assert isinstance(value, (str, int, float, bool)) or value is None, (
                "%s=%r would be a PyObject tree for Kotlin to walk"
                % (key, value))

    def test_the_type_name_is_carried(self):
        q = EventQueue()
        q.on_event(message())
        assert q.drain()[0]["type"] == "MessageReceived"

    def test_an_enum_becomes_its_name(self):
        from android_bridge.events import (
            ConnectionState, ConnectionStateChanged,
        )
        q = EventQueue()
        q.on_event(ConnectionStateChanged(state=ConnectionState.CONNECTED))
        got = q.drain()[0]
        assert got["state"] == "CONNECTED"

    def test_a_security_level_carries_its_number_too(self):
        """Kotlin's SecurityState.fromLevel maps from the engine's integer."""
        from android_bridge.events import SecurityState, SessionStateChanged
        q = EventQueue()
        q.on_event(SessionStateChanged(peer="b@x.i2p",
                                       security=SecurityState.ENCRYPTED))
        got = q.drain()[0]
        assert got["security"] == "ENCRYPTED"
        assert isinstance(got["security_level"], int)


class TestThePlaintextRule:
    """This queue is the one structure in the bridge that legitimately holds
    plaintext -- MessageReceived.body is the decrypted message the user is
    about to read. That makes where it must NOT go worth asserting."""

    def test_the_body_survives_to_the_ui(self):
        q = EventQueue()
        q.on_event(message(body="the actual message"))
        assert q.drain()[0]["body"] == "the actual message"

    def test_the_module_does_not_log(self):
        """A logger here would put plaintext in logcat."""
        import inspect
        import android_bridge.eventlog as mod
        src = inspect.getsource(mod)
        for banned in ("logging.", "_log.", "print("):
            assert banned not in src, (
                "%r in a module that holds decrypted message bodies" % banned)

    def test_it_is_not_collected_by_diagnostics(self):
        import inspect
        import android_bridge.diagnostics as diag
        assert "eventlog" not in inspect.getsource(diag)


class TestThreadSafety:
    """Events are appended from the transport's loop thread and drained from
    whatever thread the UI polls on. That is two threads by construction."""

    def test_concurrent_writers_lose_nothing(self):
        q = EventQueue(capacity=10000)
        def writer(n):
            for i in range(200):
                q.on_event(message(body="%d-%d" % (n, i)))
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert q.pending() == 1600

    def test_draining_while_writing_does_not_corrupt(self):
        q = EventQueue(capacity=10000)
        seen = []
        stop = threading.Event()

        def drainer():
            while not stop.is_set():
                seen.extend(q.drain())
            seen.extend(q.drain())

        d = threading.Thread(target=drainer)
        d.start()
        for i in range(500):
            q.on_event(message(body=str(i)))
        stop.set()
        d.join()
        bodies = [e["body"] for e in seen]
        assert len(bodies) == 500
        assert len(set(bodies)) == 500, "an event was delivered twice"


class TestItIsTheSinkOtrAppExpects:

    def test_it_satisfies_the_sink_protocol(self):
        q = EventQueue()
        assert callable(q.on_event)

    def test_otrapp_accepts_it(self):
        from android_bridge.app import OtrApp

        class Engine:
            pass

        app = OtrApp(Engine())
        q = EventQueue()
        app.set_event_sink(q)
        app._emit(message(body="through the facade"))
        assert q.drain()[0]["body"] == "through the facade"
