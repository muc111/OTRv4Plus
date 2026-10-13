# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice counters, each checked against its definition.

The definitions are otrv4plus_mediapath.COUNTER_DEFINITIONS. Every scenario
drives the real JitterBuffer deterministically (non-adaptive, fixed prefill)
and checks two things: the named counter moved as defined, and every
accepted frame is accounted for exactly once:

    accepted (queued) = played + shed(drift) + overflow + cleared + buffered

A handset baseline (590 s, 8573 "played", 256 shed, 0 dropped) was measured
with the OLD definition, where "played" was frames accepted and so included
the shed ones. It is history, not re-derived here.
"""
import pytest

V = pytest.importorskip("otrv4plus_voice")
import otrv4plus_mediapath as MP                                # noqa: E402

JB = V.JitterBuffer


def buf(prefill=1, maxlen=64, shed_margin=1000):
    return JB(prefill=prefill, maxlen=maxlen, adaptive=False,
              shed_margin=shed_margin)


def frame(tag=0):
    return bytearray([tag & 0xFF] * 4)


def drain(b):
    out = []
    while True:
        item = b.pop()
        if item is None:
            return out
        out.append(item[1])


def conserved(b):
    s = b.stats
    return s["queued"] == (s["played"] + s["drift"] + s["overflow"]
                           + s["cleared"] + b.depth())


def test_every_counter_has_a_definition():
    for name in ("sent", "received", "played", "missing", "reordered", "late",
                 "duplicate", "underrun", "shed", "dropped"):
        assert name in MP.COUNTER_DEFINITIONS and MP.COUNTER_DEFINITIONS[name]
    assert "not loss in transit" in MP.COUNTER_DEFINITIONS["dropped"].lower()


def test_normal_delivery():
    b = buf()
    for i in range(10):
        assert b.push(0, i, frame(i))
    gaps = drain(b)
    assert b.stats["played"] == 10 and sum(gaps) == 0
    assert b.stats["gaps"] == 0 and b.stats["reordered"] == 0
    assert conserved(b)


def test_loss_is_missing_and_nothing_else():
    b = buf()
    for i in (0, 1, 4, 5):                      # 2 and 3 never arrive
        b.push(0, i, frame(i))
    drain(b)
    assert b.stats["played"] == 4
    assert b.stats["gaps"] == 2
    assert b.stats["late"] == 0 and b.stats["drift"] == 0
    assert conserved(b)


def test_reordering_in_time_is_counted_and_played_in_order():
    b = buf(prefill=4)
    for i in (0, 2, 1, 3):
        assert b.push(0, i, frame(i))
    assert b.stats["reordered"] == 1
    played = []
    while True:
        item = b.pop()
        if item is None:
            break
        played.append(item[0][0])
    assert played == [0, 1, 2, 3]
    assert b.stats["gaps"] == 0 and b.stats["played"] == 4
    assert conserved(b)


def test_duplicates_are_refused_and_counted_once():
    b = buf(prefill=3)
    b.push(0, 0, frame())
    assert not b.push(0, 0, frame())
    assert b.stats["duplicate"] == 1 and b.stats["queued"] == 1
    assert conserved(b)


def test_a_frame_after_its_slot_is_late_not_missing_twice():
    b = buf()
    b.push(0, 0, frame())
    b.push(0, 2, frame())
    drain(b)                                    # 1 is now missing
    assert b.stats["gaps"] == 1
    assert not b.push(0, 1, frame())            # arrives after its slot
    assert b.stats["late"] == 1
    assert b.stats["gaps"] == 1, "a late frame must not be counted missing again"
    assert conserved(b)


def test_a_rekey_is_not_counted_as_missing():
    b = buf()
    for i in range(3):
        b.push(0, 1000 + i, frame())
    for i in range(3):                          # new epoch, counter restarts
        b.push(1, i, frame())
    drain(b)
    assert b.stats["gaps"] == 0, b.stats
    assert b.stats["played"] == 6
    assert conserved(b)


def test_an_old_epoch_frame_after_the_new_one_played_is_late():
    b = buf()
    b.push(1, 0, frame())
    drain(b)
    assert not b.push(0, 999, frame())
    assert b.stats["late"] == 1


def test_the_counter_is_masked_to_its_field_not_carried_into_the_epoch():
    top = (1 << JB.EPOCH_SHIFT) - 1
    seq = JB.sequence(3, top + 5)               # overflowing counter
    assert JB.epoch_of(seq) == 3, "a huge counter bled into the epoch"
    assert JB.sequence(3, top) < JB.sequence(4, 0)


def test_shed_frames_are_shed_not_played_and_not_missing():
    b = buf(prefill=1, shed_margin=1)
    for i in range(40):
        b.push(0, i, frame())
    drain(b)
    s = b.stats
    assert s["drift"] > 0
    assert s["played"] + s["drift"] == 40
    assert s["gaps"] == 0, "shedding must not look like transit loss"
    assert conserved(b)


def test_overflow_evicts_the_oldest_and_counts_it():
    b = buf(prefill=100, maxlen=5)
    for i in range(8):
        b.push(0, i, frame())
    assert b.stats["overflow"] == 3 and b.depth() == 5
    assert conserved(b)


def test_teardown_clears_and_counts_what_was_never_played():
    b = buf(prefill=100)
    for i in range(6):
        b.push(0, i, frame())
    b.clear()
    assert b.stats["cleared"] == 6 and b.stats["played"] == 0
    assert conserved(b)


def test_underrun_is_a_wait_not_a_loss():
    b = buf()
    b.push(0, 0, frame())
    drain(b)
    assert b.pop() is None
    assert b.stats["underrun"] >= 1 and b.stats["gaps"] == 0


class _Session:
    def __init__(self, jitter, stats):
        self.jitter, self.stats = jitter, stats


def test_counters_from_a_session_follow_the_definitions():
    b = buf(prefill=1, shed_margin=1)
    for i in (0, 1, 2, 4, 3):
        b.push(0, i, frame())
    b.push(0, 1, frame())                       # duplicate
    for i in range(5, 40):
        b.push(0, i, frame())
    drain(b)
    c = MP.counters_from(_Session(b, {"sent": 50, "tx_dropped": 2,
                                      "rx_dropped": 3, "dropped": 5}))
    assert c.played == b.stats["played"]
    assert c.shed == b.stats["drift"] + b.stats["overflow"]
    assert c.received == b.stats["queued"] + b.stats["late"] + b.stats["duplicate"]
    assert c.reordered == 1 and c.duplicate == 1
    assert (c.dropped_tx, c.dropped_rx) == (2, 3)
    line = MP.delivery_line(c)
    assert "%d played" % c.played in line and "2/3 dropped locally" in line


def test_a_buffer_without_played_is_read_without_double_counting():
    class Old:
        stats = {"queued": 100, "drift": 20, "overflow": 5, "gaps": 3}
    c = MP.counters_from(_Session(Old(), {}))
    assert c.played == 75


def test_zero_dropped_with_loss_is_reported_as_loss():
    """The misleading case: dropped 0, and still audio was lost."""
    c = MP.MediaCounters(played=900, gaps=40, shed=25)
    line = MP.delivery_line(c)
    assert "40 missing" in line and "25 shed" in line
    assert "dropped" not in line
