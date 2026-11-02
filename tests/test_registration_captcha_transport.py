# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The live two-phase CAPTCHA flow in transport_registration._submit_captcha.

captcha.py is the parser and is tested on its own; this drives the coroutine
that uses it on a real event loop, with slixmpp stood in for by fakes, to pin
the orchestration:

  * a showable inline challenge parks the open stream, reports phase one, and
    on an answer sends ONE register-set carrying the username, the password,
    and the completed data form (hidden fields echoed, the answer in the
    answer field);
  * an image that can only be fetched from the web is refused before anything
    is sent -- the password never leaves;
  * registration over a route that verifies certificates will not submit the
    password until TLS is actually in place;
  * an abandoned screen (no answer) ends the attempt and sends nothing.

No network and no slixmpp: every rule here would otherwise need a live CAPTCHA
server to exercise.
"""
import asyncio
import base64
import concurrent.futures
import types
from xml.etree import ElementTree as ET

import pytest

from android_bridge import captcha
from android_bridge import transport_registration as tr
import otrv4plus_registration as _registration


PNG = b"\x89PNG\r\n\x1a\n" + b"captcha-image" * 4
CID = "sha1+deadbeef@bob.xmpp.org"


def _query(answer_uri="cid:" + CID, bob=True):
    bob_xml = ("<data xmlns='urn:xmpp:bob' cid='%s' type='image/png'>%s</data>"
               % (CID, base64.b64encode(PNG).decode())) if bob else ""
    return (
        "<query xmlns='jabber:iq:register'>"
        "<x xmlns='jabber:x:data' type='form'>"
        "<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:captcha</value></field>"
        "<field var='challenge' type='hidden'><value>chal-123</value></field>"
        "<field var='sid' type='hidden'><value>sid-456</value></field>"
        "<field var='ocr' label='Type the text' type='text-single'><required/>"
        "<media xmlns='urn:xmpp:media-element'>"
        "<uri type='image/png'>%s</uri></media></field>"
        "</x>%s</query>" % (answer_uri, bob_xml))


# -- slixmpp stand-ins ------------------------------------------------------

class _FakeForm:
    def __init__(self):
        self.fields = {}

    def add_field(self, var=None, ftype=None, value=None):
        self.fields[var] = {"ftype": ftype, "value": value}

    @property
    def xml(self):
        e = ET.Element("{jabber:x:data}x")
        e.set("type", "submit")
        return e


class _Xep0004:
    def __init__(self):
        self.last_form = None

    def make_form(self, ftype="submit"):
        self.last_form = _FakeForm()
        self.last_form.ftype = ftype
        return self.last_form


class _FakeRegister:
    """The <query xmlns=jabber:iq:register> builder on an outgoing Iq."""

    def __init__(self):
        self.values = {}
        self.appended = []

    def __setitem__(self, key, value):
        self.values[key] = value

    def append(self, xml):
        self.appended.append(xml)


class _FakeIq:
    def __init__(self, client):
        self._client = client
        self.register = _FakeRegister()
        self.typ = None

    def __setitem__(self, key, value):
        if key == "type":
            self.typ = value

    def __getitem__(self, key):
        if key == "register":
            return self.register
        raise KeyError(key)

    async def send(self):
        if self._client.send_exc is not None:
            raise self._client.send_exc
        self._client.sent.append(self)
        return self


class _FakeClient:
    def __init__(self, send_exc=None):
        self._x4 = _Xep0004()
        self.sent = []
        self.send_exc = send_exc

    def __getitem__(self, key):
        if key == "xep_0004":
            return self._x4
        raise KeyError(key)

    def Iq(self):
        return _FakeIq(self)


class _RecvReg:
    def __init__(self, query_el):
        self.xml = query_el


class _RecvForm:
    """The received registration form stanza _submit_captcha reads."""

    def __init__(self, query_xml):
        self._q = ET.fromstring(query_xml)

    def __getitem__(self, key):
        if key == "register":
            return _RecvReg(self._q)
        raise KeyError(key)


def _instance(verify_certificate=False):
    """A minimal object carrying just what _submit_captcha touches."""
    inst = types.SimpleNamespace()
    inst._route = types.SimpleNamespace(
        verify_certificate=verify_certificate, kind="clearnet-tls",
        host="im.example")
    inst._profile = types.SimpleNamespace(jid="alice@im.example")
    inst._password = "correct horse battery"
    inst._reg_stage1 = concurrent.futures.Future()
    inst._reg_final = concurrent.futures.Future()
    inst._reg_captcha = None
    inst._reg_answer = None
    for name in ("_submit_captcha", "_reg_set_stage1", "_reg_set_final",
                 "pending_captcha"):
        setattr(inst, name,
                getattr(tr.RegistrationMixin, name).__get__(inst))
    return inst


def _run(inst, client, query_xml, *, answer=None, feed_answer=True):
    """Drive _submit_captcha to completion on a fresh loop. Returns the `done`
    future the coroutine resolves. If feed_answer, supplies `answer` once the
    coroutine has parked."""
    loop = asyncio.new_event_loop()
    try:
        async def scenario():
            done = loop.create_future()
            task = asyncio.ensure_future(
                inst._submit_captcha(client, _RecvForm(query_xml), done))
            if feed_answer:
                for _ in range(1000):
                    await asyncio.sleep(0)
                    if inst._reg_answer is not None and inst._reg_stage1.done():
                        break
                if inst._reg_answer is not None and not inst._reg_answer.done():
                    inst._reg_answer.set_result(answer)
            await task
            return done
        return loop.run_until_complete(scenario())
    finally:
        loop.close()


# -- tests ------------------------------------------------------------------

def test_showable_challenge_parks_then_submits_one_set():
    inst = _instance()
    client = _FakeClient()
    done = _run(inst, client, _query(), answer="WXYZ")

    # Phase one was reported, and the image the UI gets is the inline one.
    assert inst._reg_stage1.result(timeout=0)[0] == "captcha_required"
    card = inst.pending_captcha()
    assert card["image_base64"] == base64.b64encode(PNG).decode()
    assert card["answer_var"] == "ocr"

    # Exactly one set went out, with the credentials as register sub-elements.
    assert len(client.sent) == 1
    iq = client.sent[0]
    assert iq.typ == "set"
    assert iq.register.values["username"] == "alice"
    assert iq.register.values["password"] == "correct horse battery"

    # The submitted form echoes the hidden fields and carries the answer.
    form = client._x4.last_form
    assert form.ftype == "submit"
    assert form.fields["ocr"]["value"] == "WXYZ"
    assert form.fields["ocr"]["ftype"] == "text-single"
    assert form.fields["FORM_TYPE"]["value"] == "urn:xmpp:captcha"
    assert form.fields["FORM_TYPE"]["ftype"] == "hidden"
    assert form.fields["challenge"]["value"] == "chal-123"
    assert form.fields["sid"]["value"] == "sid-456"
    # And that form was attached to the register query.
    assert iq.register.appended, "data form was not attached to the query"
    assert done.result() is True


def test_external_image_is_refused_before_anything_is_sent():
    inst = _instance()
    client = _FakeClient()
    done = _run(inst, client, _query(answer_uri="https://evil.example/c.png",
                                     bob=False), feed_answer=False)
    # Nothing sent, no password, and the phase-one signal never became a
    # CAPTCHA -- it stayed unset, so register_account() will report the refusal
    # as a terminal result from the coroutine's own classify.
    assert client.sent == []
    assert not inst._reg_stage1.done()
    with pytest.raises(_registration.RegistrationFailed) as e:
        done.result()
    assert e.value.code == "registration_captcha_external"


def test_no_tls_means_the_password_is_not_submitted(monkeypatch):
    monkeypatch.setattr(tr, "_tls_in_place", lambda client: False)
    inst = _instance(verify_certificate=True)
    client = _FakeClient()
    done = _run(inst, client, _query(), feed_answer=False)
    assert client.sent == []
    assert not inst._reg_stage1.done()
    with pytest.raises(_registration.RegistrationFailed) as e:
        done.result()
    assert e.value.code == "tls_required"


def test_tls_in_place_allows_the_submit(monkeypatch):
    monkeypatch.setattr(tr, "_tls_in_place", lambda client: True)
    inst = _instance(verify_certificate=True)
    client = _FakeClient()
    done = _run(inst, client, _query(), answer="AB12")
    assert len(client.sent) == 1
    assert done.result() is True


def test_abandoned_screen_times_out_and_sends_nothing(monkeypatch):
    # Shrink the park so the test does not actually wait three minutes.
    monkeypatch.setattr(tr, "CAPTCHA_ANSWER_TIMEOUT", 0.05)
    inst = _instance()
    client = _FakeClient()
    done = _run(inst, client, _query(), feed_answer=False)
    assert client.sent == []
    # Phase one was still reported (the user was shown the image); the attempt
    # then ended because no answer came.
    assert inst._reg_stage1.result(timeout=0)[0] == "captcha_required"
    with pytest.raises(_registration.RegistrationFailed) as e:
        done.result()
    assert e.value.code == "cancelled"


def test_server_rejects_the_answer():
    inst = _instance()

    class _Boom(Exception):
        condition = "not-acceptable"

    client = _FakeClient(send_exc=_Boom("nope"))
    done = _run(inst, client, _query(), answer="WRONG")
    assert client.sent == []  # send raised; nothing recorded as delivered
    with pytest.raises(_Boom):
        done.result()


def test_submit_answer_without_a_pending_captcha_is_a_protocol_error():
    inst = _instance()
    # No register_account() ran, so no answer future exists.
    inst.submit_captcha_answer = \
        tr.RegistrationMixin.submit_captcha_answer.__get__(inst)
    inst._ensure_loop = lambda: asyncio.new_event_loop()
    inst._lock = __import__("threading").RLock()
    code, _ = inst.submit_captcha_answer("anything")
    assert code == "registration_protocol_error"
