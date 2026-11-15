# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""When the app refuses a server, it can say which check failed, and says
nothing by which the exchange could be recognised.

"The server did not prove it knows this account" is the right thing to do
and, by itself, a useless thing to read: on a device it gave no way to tell a
hostile server from a misconfigured one, or which of a dozen checks had
fired. `android_bridge.server_proof` keeps a record of each refusal. These
hold it to three things:

1. every way the exchange can go wrong ends the attempt at once, with one
   named reason (several used to escape slixmpp as exceptions and leave the
   sign-in to time out);
2. the record, the screen line, the log, the trace and both reports carry
   names, lengths and counts, and never a value from the exchange;
3. the person reading it is told only what is known: what had been sent by
   then, and, for the one refusal a server's own setting causes, what to
   change.

The failures are driven through slixmpp's own handlers, as patched, against
the small honest server in test_sasl_hardening.py. What a REAL server sends
is tests/test_real_prosody.py.
"""
import base64
import logging
import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "client"))
sys.path.insert(0, os.path.join(HERE, "tests"))

pytest.importorskip("slixmpp")

import test_sasl_hardening as scram  # noqa: E402
import test_stream_guard as streams  # noqa: E402

from android_bridge import report as report_mod  # noqa: E402
from android_bridge import sasl_hardening  # noqa: E402
from android_bridge import server_proof as proof  # noqa: E402
from android_bridge import transport_base  # noqa: E402
from android_bridge import xmlguard  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402


@pytest.fixture(autouse=True)
def fresh():
    sasl_hardening.apply()
    proof.clear()
    SENT.clear()
    yield
    proof.clear()


class Route:
    """What the transport knows and the guards do not."""
    kind = "i2p_sam"
    verify_certificate = False


# ── a server that misbehaves, one way at a time ─────────────────────────────

#: The client's final message of each honest exchange below: it carries the
#: proof, which must never be written anywhere.
SENT = []


def _honest_challenge(plugin, server):
    """An honest server's challenge; returns the client's answer to it."""
    final = scram.challenge(plugin, server.first(plugin.mech.process()))
    SENT.append(bytes(final))
    return final


def _before_challenge(plugin, server):
    """`<success/>` straight after the first message, carrying text shaped
    like a challenge: the bypass sasl_hardening was written for."""
    plugin.mech.process()
    forged = (b"r=" + plugin.mech.cnonce + b"x,s="
              + base64.b64encode(b"saltsalt") + b",i=4096")
    plugin._handle_success({"value": forged})


def _empty_success(plugin, server):
    _honest_challenge(plugin, server)
    plugin._handle_success({"value": b""})


def _no_signature(plugin, server):
    _honest_challenge(plugin, server)
    plugin._handle_success({"value": b"x=nothing-of-use"})


def _error_instead_of_signature(plugin, server):
    _honest_challenge(plugin, server)
    plugin._handle_success({"value": b"e=other-error"})


def _wrong_signature(plugin, server):
    _honest_challenge(plugin, server)
    plugin._handle_success({"value": b"v=" + base64.b64encode(b"\0" * 20)})


def _unreadable_success(plugin, server):
    _honest_challenge(plugin, server)
    plugin._handle_success({"value": b"\xff\xfe not attributes at all"})


def _with_count(count):
    def misbehave(plugin, server):
        first = server.first(plugin.mech.process())
        scram.challenge(plugin, first.rsplit(b",i=", 1)[0] + b",i=" + count)
    return misbehave


def _foreign_nonce(plugin, server):
    first = server.first(plugin.mech.process())
    scram.challenge(plugin, b"r=" + b"Z" * 40 + first[first.index(b",s="):])


def _reserved(plugin, server):
    scram.challenge(plugin, b"m=ext," + server.first(plugin.mech.process()))


def _no_salt(plugin, server):
    first = server.first(plugin.mech.process())
    scram.challenge(plugin, first[:first.index(b",s=")] + b",i=4096")


def _count_not_a_number(plugin, server):
    _with_count(b"lots")(plugin, server)


#: Whether the app's proof (which is not the password, but can be guessed
#: against) had left by the time of each refusal.
PROOF_SENT = {
    "success_before_challenge": "no",
    "success_without_signature": "yes",
    "signature_mismatch": "yes",
    "success_malformed": "yes",
    "iteration_count": "no",
    "nonce_mismatch": "no",
    "reserved_attribute": "no",
    "challenge_malformed": "no",
}

# name, what the server does, the reason recorded, the step, the shape of
# the message that was refused.
CASES = [
    ("success straight after the first message", _before_challenge,
     "success_before_challenge", 1, r"r:\d+ s:\d+ i:4"),
    ("success with nothing in it", _empty_success,
     "success_without_signature", 2, r"empty"),
    ("success with no signature among its attributes", _no_signature,
     "success_without_signature", 2, r"x:\d+"),
    ("an error where the signature belongs", _error_instead_of_signature,
     "success_without_signature", 2, r"e:\d+"),
    ("a signature that does not verify", _wrong_signature,
     "signature_mismatch", 2, r"v:28"),
    ("a success that is not attributes", _unreadable_success,
     "success_malformed", 2, r"unreadable:\d+"),
    ("an iteration count of one", _with_count(b"1"),
     "iteration_count", 2, r"r:\d+ s:\d+ i:1"),
    ("an iteration count in the billions", _with_count(b"9999999999"),
     "iteration_count", 2, r"r:\d+ s:\d+ i:10"),
    ("a nonce that is not ours", _foreign_nonce,
     "nonce_mismatch", 2, r"r:40 s:\d+ i:\d+"),
    ("the reserved attribute", _reserved,
     "reserved_attribute", 2, r"m:3 r:\d+ s:\d+ i:\d+"),
    ("a challenge with no salt", _no_salt,
     "challenge_malformed", 2, r"r:\d+ i:4"),
    ("a count that is not a number", _count_not_a_number,
     "challenge_malformed", 2, r"r:\d+ s:\d+ i:4"),
]
IDS = [case[0] for case in CASES]


@pytest.mark.parametrize("name,misbehave,reason,step,fields", CASES, ids=IDS)
def test_each_failure_ends_the_attempt_and_says_which(name, misbehave, reason,
                                                      step, fields):
    plugin = scram.plugin_for()
    misbehave(plugin, scram.Server())
    client = plugin.xmpp
    assert client.authenticated is False
    assert "auth_success" not in client.names()
    assert client.restarted == 0
    # Ended at once: not left to a timeout, and not a second mechanism tried.
    assert client.closed and client.closed[-1] == "abort", client.closed
    assert (xmlguard.REFUSED_EVENT, reason) in client.events

    record = proof.last()
    assert record["check"] == "sasl" and record["reason"] == reason
    facts = record["facts"]
    assert facts["mechanism"] == "SCRAM-SHA-1"
    assert facts["step"] == step
    assert facts["proof_sent"] == PROOF_SENT[reason]
    assert facts["channel_binding"] == "no"
    assert re.fullmatch(fields, facts["server_fields"]), facts["server_fields"]
    assert len(proof.recent()) == 1, "one refusal, recorded once"


def test_every_reason_the_guards_can_give_is_explained():
    """A reason with no entry would be reported as "(reason)" and nothing
    more. Every reason a case above produces, and every reason xmlguard
    sets, has its sentence."""
    produced = {case[2] for case in CASES} | {"declaration", "nul_byte",
                                              "stanza_too_large"}
    assert produced == set(proof.REASONS)
    for reason, (check, meaning) in proof.REASONS.items():
        assert check in ("sasl", "xml") and len(meaning) > 40, reason
    assert set(PROOF_SENT) == {reason for reason, (check, _) in
                               proof.REASONS.items() if check == "sasl"}


def test_the_iteration_count_is_recorded_as_the_number_it_was():
    for count, said in ((b"1", "1"), (b"4095", "4095"),
                        (b"2000001", "2000001"),
                        (b"9" * 13, "over 12 digits"),
                        (b"lots", "not a number")):
        proof.clear()
        plugin = scram.plugin_for()
        _with_count(count)(plugin, scram.Server())
        assert proof.last()["facts"]["iterations"] == said


def test_a_foreign_nonce_is_recorded_as_a_fact_not_a_value():
    plugin = scram.plugin_for()
    _foreign_nonce(plugin, scram.Server())
    facts = proof.last()["facts"]
    assert facts["nonce_continues_ours"] == "no"
    assert facts["salt_bytes"] == 16
    proof.clear()
    plugin = scram.plugin_for()
    _with_count(b"1")(plugin, scram.Server())
    assert proof.last()["facts"]["nonce_continues_ours"] == "yes"


def test_an_honest_server_signs_in_and_is_counted_not_recorded():
    plugin = scram.plugin_for()
    server = scram.Server()
    final = _honest_challenge(plugin, server)
    plugin._handle_success({"value": server.final(bytes(final))})
    assert plugin.xmpp.authenticated is True
    assert plugin.xmpp.closed == []
    assert proof.recent() == []
    line = proof.guards_line()
    assert "server proofs verified 1" in line
    assert "3 of 3 fixes active" in line
    assert "iterations accepted 4096..2000000" in line


def test_a_mechanism_that_is_not_scram_is_left_to_slixmpp():
    """PLAIN over a verified certificate (clearnet) has no server proof to
    check. The hardening must neither refuse it nor count it."""
    plugin = scram.plugin_for()
    plugin.mech = scram.M.PLAIN(
        "PLAIN",
        {"username": scram.M.bytes("alice"), "password": scram.M.bytes("pw"),
         "authzid": scram.M.bytes("")},
        {"encrypted": True, "encrypted_plain": True,
         "unencrypted_plain": False})
    plugin._handle_success({"value": b""})
    assert plugin.xmpp.authenticated is True
    assert proof.recent() == []
    assert "server proofs verified 0" in proof.guards_line()


# ── nothing from the exchange is written, anywhere ──────────────────────────

def _everything_written(caplog):
    """Every place a refusal is written: the record, the report section, the
    screen sentence, the log, the trace, and both reports."""
    detail = transport_base.server_not_proven_detail(Route(), "sign-in")
    return "\n".join([
        repr(proof.recent()),
        proof.render(),
        proof.summary_line(proof.last()),
        detail,
        caplog.text,
        TRACE.render(0),
        report_mod.build(status={"stage": "failed",
                                 "last": {"code": "server_not_proven",
                                          "detail": detail}}),
        report_mod.summary(status={"stage": "failed",
                                   "last": {"code": "server_not_proven",
                                            "detail": detail}}),
    ])


@pytest.mark.parametrize("name,misbehave,reason,step,fields", CASES, ids=IDS)
def test_no_value_from_the_exchange_is_written_anywhere(
        name, misbehave, reason, step, fields, caplog):
    caplog.set_level(logging.DEBUG)
    plugin = scram.plugin_for()
    server = scram.Server()
    misbehave(plugin, server)
    assert proof.last()["reason"] == reason
    written = _everything_written(caplog)

    mech = plugin.mech
    secrets = {
        "the password": scram.PASSWORD,
        "the account name": b"alice",
        "the client nonce": bytes(mech.cnonce),
        "the salt": server.salt,
        "the salt as sent": base64.b64encode(server.salt),
        "the server's nonce": b"SERVERNONCE",
        "the injected nonce": b"Z" * 40,
        "the forged salt": base64.b64encode(b"saltsalt"),
        "the zero signature": base64.b64encode(b"\0" * 20),
    }
    signature = getattr(mech, "server_signature", None)
    if signature:
        secrets["the server signature"] = base64.b64encode(bytes(signature))
    for final in SENT:
        secrets["the client's proof"] = final.rsplit(b",p=", 1)[1]
        secrets["the client's final message"] = final
    for what, value in secrets.items():
        text = value.decode("ascii", "replace")
        assert text not in written, "%s is in the output" % what
    # And what it does say is there: the reason, in every one of them.
    assert written.count(reason) >= 6


def test_a_secret_handed_to_the_record_by_mistake_is_not_kept():
    """The callers are careful. This is for the day one is not: a fact with
    no validator is dropped, and a value its validator does not accept
    becomes a question mark."""
    proof.note("sasl", "signature_mismatch",
               password="hunter2", nonce="hunter2", proof="hunter2",
               mechanism="hunter2", offered="hunter2", progress="Hunter2!",
               server_fields="p=aHVudGVyMg==", iterations="hunter2",
               tls="hunter2", step="hunter2", salt_bytes="hunter2",
               phase="hunter2", route="hunter2", stream="hunter2",
               proof_sent="hunter2", since_stream_s="hunter2")
    record = proof.last()
    assert "password" not in record["facts"]
    assert "nonce" not in record["facts"] and "proof" not in record["facts"]
    kept = set(record["facts"].values())
    assert kept == {proof.UNKNOWN}, record["facts"]
    everything = repr(record) + proof.render() + proof.summary_line(record)
    assert "hunter2" not in everything.lower()
    assert "aHVudGVyMg" not in everything
    # A reason or a check that is not a plain name is not kept either.
    proof.note("hunter2 check", "a reason with spaces and = signs")
    assert proof.last()["check"] == proof.UNKNOWN
    assert proof.last()["reason"] == proof.UNKNOWN


@pytest.mark.parametrize("fact,good,bad", [
    ("phase", "registration", "sign in"),
    ("route", "i2p_sam", "i2p"),
    ("certificate_checked", "no", "maybe"),
    ("progress", "authenticating", "Authenticating now"),
    ("mechanism", "SCRAM-SHA-256", "SCRAM-SHA-999"),
    ("step", 2, 4),
    ("step", 0, True),
    ("proof_sent", "yes", "sent"),
    ("server_fields", "r:59 s:24 i:5", "r=abc,s=def"),
    ("server_fields", "unreadable:31", "unreadable"),
    ("server_fields", "empty", ""),
    ("iterations", "4096", "4096 rounds"),
    ("iterations", "over 12 digits", "1234567890123"),
    ("salt_bytes", 16, -1),
    ("nonce_continues_ours", "no", "0"),
    ("tls", "TLSv1.3", "TLSv1.3 (AES)"),
    ("tls", "none", "off"),
    ("stream", 3, 3.5),
    ("stream_bytes", 0, "0"),
    ("parser_state", "cdata", "CDATA"),
    ("since_stream_s", 0.25, -0.25),
])
def test_each_fact_has_one_narrow_form(fact, good, bad):
    assert proof.FACTS[fact](good) == good
    assert proof.FACTS[fact](bad) == proof.UNKNOWN


def test_booleans_become_yes_and_no_and_times_are_rounded():
    assert proof.FACTS["proof_sent"](True) == "yes"
    assert proof.FACTS["certificate_checked"](False) == "no"
    assert proof.FACTS["since_connect_s"](1.23456789) == 1.235


def test_a_server_cannot_write_its_own_text_into_the_report():
    """The mechanism list is the server's. Names this app knows are listed;
    anything else is counted, never quoted."""
    offered = ["SCRAM-SHA-1", "PLAIN", "X-READ-THIS-OPERATOR-IS-EVIL",
               "<script>", 7]
    assert proof.FACTS["offered"](offered) == "PLAIN, SCRAM-SHA-1 +3 other"
    assert proof.FACTS["offered"](set()) == "none"
    assert proof.FACTS["offered"]("SCRAM-SHA-1") == proof.UNKNOWN
    assert proof.FACTS["mechanism"]("X-READ-THIS") == proof.UNKNOWN


def _refusal_like(reason, proof_sent, tls):
    facts = {"mechanism": "SCRAM-SHA-1", "step": 2, "proof_sent": proof_sent,
             "server_fields": "r:59 s:24 i:5", "iterations": "3000000",
             "phase": "sign-in", "route": "i2p_sam", "stream": 2}
    if tls is not None:
        facts["tls"] = tls
    check = proof.REASONS[reason][0]
    return proof.note(check, reason, **facts)


def test_the_scrubber_leaves_the_section_as_written():
    """The report is scrubbed line by line for anything that looks like a
    secret being reported: a line whose first word is "password" loses the
    rest of itself. The section's sentences mention passwords (that is what
    they are about), so every one of them, as wrapped, must pass through
    unchanged; a rewording that wraps badly fails here and not in a report
    someone needed."""
    for reason in proof.REASONS:
        for proof_sent in (True, False):
            for tls in ("none", "TLSv1.3", None):
                proof.clear()
                _refusal_like(reason, proof_sent, tls)
                section = proof.render()
                assert report_mod._scrub(section) == section, (
                    reason, proof_sent, tls)
                for phase in ("sign-in", "registration", "probe"):
                    said = transport_base.server_not_proven_detail(
                        Route(), phase)
                    assert report_mod._scrub(said) == said, (reason, phase)
                    line = "last    server_not_proven: " + said
                    assert report_mod._scrub(line) == line


# ── a refused XML stream ────────────────────────────────────────────────────

class PlainTransport:
    """A connection with no TLS on it yet."""

    def get_extra_info(self, _name, default=None):
        return default


def test_a_refused_stream_records_where_it_was():
    client, loop = streams._client()
    try:
        client.transport = PlainTransport()
        opening = streams.HEADER + streams.STANZAS
        client.data_received(opening)
        client.data_received(b"<!DOCTYPE s [<!ENTITY a 'AAAA'>]>")
        streams._spin(loop)
        assert client.refusals == ["declaration"]
        record = proof.last()
        assert record["check"] == "xml" and record["reason"] == "declaration"
        facts = record["facts"]
        assert facts["stream"] == 1
        assert facts["tls"] == "none"
        assert facts["stream_bytes"] == len(opening)
        assert facts["stream_stanzas"] == 3
        assert facts["parser_state"] == "text"
        assert 0 <= facts["since_stream_s"] <= facts["since_connect_s"] + 0.01
        section = proof.render()
        assert "before TLS" in section
        assert "ENTITY a" not in section and "AAAA" not in section
    finally:
        streams._close(client, loop)


def test_a_stanza_cut_off_records_how_far_it_got(monkeypatch):
    monkeypatch.setattr(xmlguard, "MAX_OPEN_STANZA_BYTES", 64 * 1024)
    client, loop = streams._client()
    try:
        client.data_received(streams.HEADER + b"<message><body>")
        for _ in range(70):
            client.data_received(b"x" * 1024)
        streams._spin(loop)
        assert client.refusals == ["stanza_too_large"]
        facts = proof.last()["facts"]
        assert 64 * 1024 < facts["open_stanza_bytes"] <= 66 * 1024
        assert facts["stream_stanzas"] == 0
        assert "tls" not in facts            # no transport: not known, not guessed
    finally:
        streams._close(client, loop)


def test_a_second_refusal_on_a_new_stream_is_not_swallowed():
    """`_stream_refused` used to outlive the stream it was set on: a client
    object used again met the same refusal with no event and no close."""
    client, loop = streams._client()
    try:
        client.data_received(b"<!DOCTYPE s>")
        client.init_parser()
        client.data_received(b"<!DOCTYPE s>")
        streams._spin(loop)
        assert client.refusals == ["declaration", "declaration"]
        assert client.aborted == [True, True]
        assert [r["facts"]["stream"] for r in proof.recent()] == [1, 2]
    finally:
        streams._close(client, loop)


def test_streams_are_counted_from_one_again_after_the_connection_ends():
    class Base:
        def init_parser(self):
            return None

        def connection_lost(self, exception):
            self.lost = exception

    class Guarded(xmlguard.GuardedStream, Base):
        pass

    client = Guarded()
    for expected in (1, 2, 3):
        client.init_parser()
        assert xmlguard.stream_position(client)["stream"] == expected
    client.connection_lost(None)
    assert client.lost is None
    client.init_parser()
    assert xmlguard.stream_position(client)["stream"] == 1
    assert "streams guarded 4" in proof.guards_line()


# ── where the user and the report see it ────────────────────────────────────

def test_the_screen_line_says_which_check_and_where():
    plugin = scram.plugin_for()
    _before_challenge(plugin, scram.Server())
    detail = transport_base.server_not_proven_detail(
        Route(), "registration", "authenticating")
    assert detail.startswith(transport_base.SERVER_NOT_PROVEN_TEXT)
    line = detail[detail.index("[") + 1:detail.rindex("]")]
    said = dict(part.split("=", 1) for part in line.split(" "))
    assert said["check"] == "success_before_challenge"
    assert said["phase"] == "registration"
    assert said["mechanism"] == "SCRAM-SHA-1"
    assert said["step"] == "1"
    assert said["proof_sent"] == "no"
    assert said["route"] == "i2p_sam"
    facts = proof.last()["facts"]
    assert facts["certificate_checked"] == "no"
    assert facts["progress"] == "authenticating"


def test_the_sentence_claims_only_what_is_known_to_have_been_sent():
    """rc.204 said "nothing that reveals the password was sent" for every
    refusal. During registration that is false: the request that creates the
    account carries the new password to the server, before SCRAM starts."""
    base = transport_base.SERVER_NOT_PROVEN_TEXT
    assert "password" not in base

    # Signing in, refused before the app answered a challenge.
    plugin = scram.plugin_for()
    _with_count(b"1")(plugin, scram.Server())
    said = transport_base.server_not_proven_detail(Route(), "sign-in")
    assert "The password itself was not sent." in said
    assert "sign-in proof was" not in said

    # Signing in, the server failed after the app's proof went out.
    proof.clear()
    plugin = scram.plugin_for()
    _wrong_signature(plugin, scram.Server())
    said = transport_base.server_not_proven_detail(Route(), "sign-in")
    assert "The password itself was not sent." in said
    assert "sign-in proof was" in said and "change the password" in said

    # Registering: the new password went with the registration request.
    proof.clear()
    plugin = scram.plugin_for()
    _wrong_signature(plugin, scram.Server())
    said = transport_base.server_not_proven_detail(Route(), "registration")
    assert "was not sent" not in said
    assert "had already sent this server the password" in said
    assert "do not use that password anywhere else" in said

    # A refused XML stream: when it happened decides, so nothing is claimed.
    proof.clear()
    proof.note("xml", "declaration", stream=1, tls="none")
    for phase in ("sign-in", "registration"):
        said = transport_base.server_not_proven_detail(Route(), phase)
        assert "password" not in said, said


def test_a_servers_own_setting_is_named_with_what_to_change():
    """Against a real Prosody (tests/test_real_prosody.py) one setting, and
    only one, produces this refusal from an honest server: its SCRAM
    iteration count. Then the screen says the number, the range, and that
    it is the operator's to change; the report says the same."""
    plugin = scram.plugin_for()
    _with_count(b"3000000")(plugin, scram.Server())
    said = transport_base.server_not_proven_detail(Route(), "sign-in")
    assert ("The server asked for 3000000 rounds of password hashing; this "
            "app accepts 4096 to 2000000.") in said
    assert "default_iteration_count" in said
    assert "set this account's password again" in said
    # What was and was not sent still comes first, and the line still ends it.
    assert said.index("The password itself was not sent.") < said.index(
        "The server asked for")
    assert said.rstrip().endswith("]") and "check=iteration_count" in said
    section = proof.render()
    assert "default_iteration_count" in section
    assert "set this account's password again" in " ".join(
        section.replace("| ", "").split())
    assert "accepted" in section and "4096..2000000" in section

    # A count too long to be quoted is not quoted.
    proof.clear()
    plugin = scram.plugin_for()
    _with_count(b"9" * 13)(plugin, scram.Server())
    said = transport_base.server_not_proven_detail(Route(), "sign-in")
    assert "a number of password-hashing rounds this app does not accept" in said
    assert "9999" not in said

    # No other refusal is put down to a setting.
    for misbehave in (_wrong_signature, _before_challenge, _foreign_nonce,
                      _reserved, _no_salt, _count_not_a_number):
        proof.clear()
        plugin = scram.plugin_for()
        misbehave(plugin, scram.Server())
        said = transport_base.server_not_proven_detail(Route(), "sign-in")
        assert "operator" not in said and "default_iteration_count" not in said
        assert "default_iteration_count" not in proof.render()
    proof.clear()
    proof.note("xml", "declaration", stream=1, tls="none")
    assert "operator" not in transport_base.server_not_proven_detail(
        Route(), "sign-in")


def test_with_nothing_recorded_the_sentence_stands_alone():
    assert transport_base.server_not_proven_detail(
        Route(), "sign-in") == transport_base.SERVER_NOT_PROVEN_TEXT


def test_an_old_refusal_is_not_taken_for_this_attempt(monkeypatch):
    """The transport adds the route and the phase to the NEWEST record, if
    it is recent. A refusal from an hour ago is not this attempt's."""
    proof.note("sasl", "signature_mismatch", mechanism="SCRAM-SHA-1")
    real = proof.time.monotonic
    monkeypatch.setattr(proof.time, "monotonic", lambda: real() + 3600)
    assert transport_base.server_not_proven_detail(
        Route(), "sign-in") == transport_base.SERVER_NOT_PROVEN_TEXT
    assert "phase" not in proof.last()["facts"]


def test_the_report_has_the_section_healthy_or_not():
    healthy = report_mod.build(status={})
    section = healthy[healthy.index("Server checks"):]
    section = section[:section.index("Failures seen")]
    assert "guards    streams guarded" in section
    assert "refusals  none in this session" in section

    plugin = scram.plugin_for()
    _with_count(b"1")(plugin, scram.Server())
    transport_base.server_not_proven_detail(Route(), "sign-in", "authenticating")
    report = report_mod.build(status={})
    section = report[report.index("Server checks"):]
    section = section[:section.index("Failures seen")]
    assert "refusals  1 in this session" in section
    assert "refused: iteration_count  (sasl check)" in section
    for row in ("phase", "route", "mechanism", "step", "proof_sent",
                "server_fields", "iterations", "accepted"):
        assert re.search(r"^\s+%s\s+\S" % row, section, re.MULTILINE), row
    assert "2 of 3: the server's challenge received" in section
    short = report_mod.summary(status={})
    assert "refused 1 server refusal(s); last: check=iteration_count" in short
    # The trace has the event too, with the same names and no more.
    events = TRACE.render(0)
    assert "server_not_proven" in events


def test_only_the_last_few_are_kept():
    for _ in range(proof.KEEP + 5):
        proof.note("xml", "declaration", stream=1)
    assert len(proof.recent()) == proof.KEEP


def _source(*parts):
    with open(os.path.join(HERE, *parts), encoding="utf-8") as handle:
        return handle.read()


def test_sign_in_registration_and_the_probe_all_answer_a_refusal():
    """Three places open a stream to a server. Each has to answer the
    refusal event, or the person waits for a timeout and reads "the server
    did not answer"; registration and the probe did not, in rc.204."""
    transport = _source("android_bridge", "transport.py")
    refused = transport[transport.index("def on_refused(_reason):"):]
    refused = refused[:refused.index("def on_no_auth")]
    assert 'server_not_proven_detail(' in refused and '"sign-in"' in refused
    assert "SERVER_NOT_PROVEN_CODE, detail" in refused

    registration = _source("android_bridge", "transport_registration.py")
    register = registration[registration.index("async def _register_inner"):
                            registration.index("async def _probe_inner")]
    assert "client.add_event_handler(REFUSED_EVENT, on_refused)" in register
    assert 'server_not_proven_detail(self._route, "registration")' in register
    probe = registration[registration.index("async def _probe_inner"):]
    assert "REFUSED_EVENT" in probe and '"probe"' in probe

    import otrv4plus_registration as codes
    assert "server_not_proven" in codes.CODES
    failure = codes.RegistrationFailed("server_not_proven", "which check")
    assert codes.classify(failure) == ("server_not_proven", "which check")


def test_the_terminal_client_says_so_and_does_not_reconnect(capsys):
    from otrv4plus_xmpp_connection import ConnectionMixin

    class Terminal(ConnectionMixin):
        pass

    terminal = Terminal.__new__(Terminal)
    terminal._shutting_down = False
    plugin = scram.plugin_for()
    _with_count(b"1")(plugin, scram.Server())
    terminal._on_stream_refused("iteration_count")
    assert terminal._shutting_down is True
    said = capsys.readouterr().err
    assert "[server not proven]" in said
    assert "check=iteration_count" in said
    assert "refused: iteration_count  (sasl check)" in said
    assert "not reconnecting" in said
    wiring = _source("client", "otrv4plus_xmpp.py")
    assert ('self.add_event_handler("stream_refused",     '
            'self._on_stream_refused)') in wiring
    assert xmlguard.REFUSED_EVENT == "stream_refused"


def test_the_app_text_points_at_the_line():
    """Android shows its own sentence for the code and, under it, the
    transport's detail, selectable. The sentence has to say the line is
    there and is safe to pass on."""
    problem = _source("android", "app", "src", "main", "java", "org",
                      "otrv4plus", "android", "connection",
                      "ConnectProblem.kt")
    text = problem[problem.index('"server_not_proven" ->'):]
    text = " ".join(text[:text.index('"tls_required"')].split())
    assert "include the line below" in text.replace('" + "', "")
    assert "no password, key or address" in text.replace('" + "', "")
    screen = _source("android", "app", "src", "main", "java", "org",
                     "otrv4plus", "android", "ui", "ConnectScreen.kt")
    shown = screen[screen.index("// The transport's own sentence"):]
    assert shown.index("SelectionContainer {") < shown.index(
        "Text(status.detail")
