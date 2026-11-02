# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""XEP-0077/0158 registration CAPTCHA parsing (android_bridge/captcha.py).

The security rule under test: the challenge image is taken ONLY from an
inline bits-of-binary object the server already sent; a media element that
points at an http(s) URL is refused, never fetched.
"""
import base64

import pytest

from android_bridge import captcha


PNG = b"\x89PNG\r\n\x1a\n" + b"fake-png-bytes" * 4
CID = "sha1+abc123@bob.xmpp.org"


def _form(answer_field, *, form_type="urn:xmpp:captcha", bob=True,
          hidden=("challenge", "sid"), instructions="Enter the text."):
    bob_xml = ("<data xmlns='urn:xmpp:bob' cid='%s' type='image/png'>%s</data>"
               % (CID, base64.b64encode(PNG).decode())) if bob else ""
    hidden_xml = "".join(
        "<field var='%s' type='hidden'><value>%s-val</value></field>" % (h, h)
        for h in hidden)
    ft = ("<field var='FORM_TYPE' type='hidden'><value>%s</value></field>"
          % form_type) if form_type else ""
    return (
        "<query xmlns='jabber:iq:register'>"
        "<x xmlns='jabber:x:data' type='form'>"
        "<instructions>%s</instructions>"
        "%s%s%s"
        "</x>%s</query>" % (instructions, ft, hidden_xml, answer_field, bob_xml))


def _ocr_field(uri="cid:" + CID, utype="image/png"):
    return ("<field var='ocr' label='Type the text' type='text-single'>"
            "<required/>"
            "<media xmlns='urn:xmpp:media-element'>"
            "<uri type='%s'>%s</uri></media></field>" % (utype, uri))


def test_is_captcha_query_detects_form_type_and_ocr():
    assert captcha.is_captcha_query(_form(_ocr_field()))
    # No FORM_TYPE but an ocr field is still a captcha.
    assert captcha.is_captcha_query(_form(_ocr_field(), form_type=""))
    # A plain username/password form is not.
    plain = ("<query xmlns='jabber:iq:register'><username/><password/>"
             "<instructions>Choose a name</instructions></query>")
    assert not captcha.is_captcha_query(plain)


def test_extract_inline_image_and_hidden_fields():
    ch = captcha.extract_challenge(_form(_ocr_field()))
    assert ch.answer_var == "ocr"
    assert ch.image_bytes == PNG
    assert ch.image_mime == "image/png"
    assert "Enter the text." in ch.instructions
    # Hidden fields are captured for the echo, FORM_TYPE included.
    assert ch.hidden["FORM_TYPE"] == ["urn:xmpp:captcha"]
    assert ch.hidden["challenge"] == ["challenge-val"]
    assert ch.hidden["sid"] == ["sid-val"]
    assert ch.image_base64() == base64.b64encode(PNG).decode()


def test_submission_echoes_hidden_and_injects_answer():
    ch = captcha.extract_challenge(_form(_ocr_field()))
    fields = captcha.submission_fields(ch, "WXYZ")
    assert fields["ocr"] == ["WXYZ"]
    assert fields["FORM_TYPE"] == ["urn:xmpp:captcha"]
    assert fields["challenge"] == ["challenge-val"]
    assert fields["sid"] == ["sid-val"]
    # The answer field is not left as a hidden echo of itself.
    assert fields["ocr"] != ["ocr-val"]


def test_external_url_image_is_refused_not_fetched():
    for scheme in ("http://evil.example/c.png", "https://x.example/c.png",
                   "ftp://f.example/c.png"):
        q = _form(_ocr_field(uri=scheme), bob=False)
        with pytest.raises(captcha.CaptchaError) as e:
            captcha.extract_challenge(q)
        assert e.value.code == "registration_captcha_external"


def test_external_url_refused_even_when_an_inline_image_also_exists():
    # A server offering both a cid and an http uri in the same media: we must
    # take the inline one, never the URL. (Belt and braces: the cid wins.)
    field = ("<field var='ocr' type='text-single'><required/>"
             "<media xmlns='urn:xmpp:media-element'>"
             "<uri type='image/png'>cid:%s</uri>"
             "<uri type='image/png'>https://evil.example/c.png</uri>"
             "</media></field>" % CID)
    ch = captcha.extract_challenge(_form(field))
    assert ch.image_bytes == PNG


def test_cid_with_no_inline_data_is_not_fetched():
    # cid referenced but no <data> in the stanza: unsupported, never a fetch.
    q = _form(_ocr_field(), bob=False)
    with pytest.raises(captcha.CaptchaError) as e:
        captcha.extract_challenge(q)
    assert e.value.code in ("registration_captcha_unsupported",
                            "registration_captcha_external")


def test_unshowable_image_type_is_refused():
    q = _form(_ocr_field(utype="image/svg+xml"))  # svg: not in the render set
    # The BOB data still declares image/png, but the media uri type is svg;
    # the BOB type wins, so craft a BOB of an unrenderable type instead.
    bob = ("<data xmlns='urn:xmpp:bob' cid='%s' type='image/svg+xml'>%s</data>"
           % (CID, base64.b64encode(PNG).decode()))
    q = q.replace("</x>", "</x>").rsplit("<data", 1)[0] + bob + "</query>"
    with pytest.raises(captcha.CaptchaError) as e:
        captcha.extract_challenge(q)
    assert e.value.code == "registration_captcha_unsupported"


def test_oversized_image_is_refused():
    big = base64.b64encode(b"\x89PNG" + b"x" * (captcha.MAX_IMAGE_BYTES + 1)).decode()
    bob = "<data xmlns='urn:xmpp:bob' cid='%s' type='image/png'>%s</data>" % (CID, big)
    q = _form(_ocr_field(), bob=False).replace("</query>", bob + "</query>")
    with pytest.raises(captcha.CaptchaError) as e:
        captcha.extract_challenge(q)
    assert e.value.code == "registration_captcha_unsupported"


def test_malformed_xml_is_a_protocol_error_not_a_crash():
    with pytest.raises(captcha.CaptchaError) as e:
        captcha.extract_challenge(b"<not-xml")
    assert e.value.code == "registration_protocol_error"
    assert not captcha.is_captcha_query(b"<not-xml")


def test_accepts_a_whole_iq_wrapper():
    inner = _form(_ocr_field())
    iq = "<iq type='result' from='srv' id='reg1'>%s</iq>" % inner
    assert captcha.is_captcha_query(iq)
    ch = captcha.extract_challenge(iq)
    assert ch.image_bytes == PNG
