"""XEP-0133 admin, driven by the form the server sends rather than a list.

Thirty-two admin commands are defined and no server implements all of them:
Prosody's subset is not ejabberd's. Hand-coding "the useful six" would offer
commands a server refuses and hide ones it supports, so nothing in
`otrv4plus_admin` knows a command's name. The server advertises its commands
over disco and each one describes its own fields; this module turns that into
questions and the answers back into a form.

Most of what follows is about the three properties that are not incidental:

  * a password field never reaches the terminal, the transcript or a traceback;
  * a form is armed only by the local user typing `/admin`, never by anything
    the server or a peer sends (the INV-06 rule, applied here);
  * `[admin]` is not a loggable tag, so its output -- user lists, JIDs -- is
    redacted from the session transcript.
"""

import pytest

adm = pytest.importorskip("otrv4plus_admin")


def field(var, **kw):
    return adm.AdminField(var, **kw)


def form(*fields, **kw):
    return adm.AdminForm(list(fields), **kw)


# ---------------------------------------------------------------------------
# passwords
# ---------------------------------------------------------------------------

class TestAPasswordNeverEscapes:

    def test_a_private_value_is_not_shown(self):
        f = field("password", type=adm.TYPE_PRIVATE, value="hunter2")
        assert "hunter2" not in f.shown_value()
        assert f.shown_value() == adm.REDACTED

    def test_an_empty_private_field_shows_nothing_not_a_stand_in(self):
        # REDACTED on an empty field would claim a password was set.
        f = field("password", type=adm.TYPE_PRIVATE, value="")
        assert f.shown_value() == ""

    def test_the_confirmation_listing_omits_it(self):
        fm = form(field("accountjid", label="JID"),
                  field("password", label="Password", type=adm.TYPE_PRIVATE))
        fm.answer("bob@example.i2p")
        fm.answer("hunter2")
        text = "\n".join(fm.describe())
        assert "bob@example.i2p" in text
        assert "hunter2" not in text

    def test_the_repr_omits_it(self):
        # A field in a traceback frame must not be a password on screen.
        f = field("password", type=adm.TYPE_PRIVATE, value="hunter2")
        assert "hunter2" not in repr(f)

    def test_a_rejected_answer_never_quotes_what_was_typed(self):
        """The coercion path is shared with text-private.

        An error that echoed the input would put a password in the message,
        and from there into the terminal and any traceback.
        """
        f = field("enabled", label="Enabled", type=adm.TYPE_BOOL)
        fm = form(f)
        with pytest.raises(adm.FormError) as exc:
            fm.answer("hunter2")
        assert "hunter2" not in str(exc.value)
        assert "Enabled" in str(exc.value)

    def test_it_still_reaches_the_wire(self):
        # Hiding it from the screen must not hide it from the server, which
        # is the one place it is supposed to go.
        fm = form(field("password", type=adm.TYPE_PRIVATE))
        fm.answer("hunter2")
        assert fm.values()["password"] == "hunter2"

    def test_summarising_a_result_hides_it_too(self):
        # get-user-password returns one.
        lines = adm.summarise({"fields": {
            "password": {"type": adm.TYPE_PRIVATE, "label": "Password",
                         "value": "hunter2"}}})
        assert not any("hunter2" in ln for ln in lines)


# ---------------------------------------------------------------------------
# filling a form in
# ---------------------------------------------------------------------------

class TestTheQuestions:

    def test_hidden_and_fixed_fields_are_not_asked_about(self):
        fm = form(field("FORM_TYPE", type=adm.TYPE_HIDDEN, value="x"),
                  field("note", type=adm.TYPE_FIXED, value="hello"),
                  field("accountjid", label="JID"))
        assert fm.current().var == "accountjid"
        assert fm.remaining == 1

    def test_a_hidden_field_is_still_submitted(self):
        # It carries the server's own bookkeeping; dropping it breaks
        # multi-stage commands.
        fm = form(field("FORM_TYPE", type=adm.TYPE_HIDDEN, value="admin"),
                  field("accountjid"))
        fm.answer("bob@example.i2p")
        assert fm.values()["FORM_TYPE"] == "admin"

    def test_a_fixed_field_is_not_submitted(self):
        fm = form(field("note", type=adm.TYPE_FIXED, value="hello"),
                  field("accountjid"))
        fm.answer("bob@example.i2p")
        assert "note" not in fm.values()

    def test_blank_skips_an_optional_field(self):
        fm = form(field("accountjid", required=True), field("email"))
        fm.answer("bob@example.i2p")
        fm.answer("")
        assert fm.is_complete()
        assert "email" not in fm.values()

    def test_blank_is_refused_for_a_required_field(self):
        """Refused here rather than sent.

        The server would refuse it too, but its error arrives without saying
        which field it meant.
        """
        fm = form(field("accountjid", label="JID", required=True))
        with pytest.raises(adm.FormError) as exc:
            fm.answer("")
        assert "JID" in str(exc.value)
        assert not fm.is_complete(), "a refused answer must not advance"

    def test_a_refused_answer_asks_again(self):
        fm = form(field("accountjid", label="JID", required=True))
        with pytest.raises(adm.FormError):
            fm.answer("  ")
        assert fm.current().var == "accountjid"
        fm.answer("bob@example.i2p")
        assert fm.is_complete()

    def test_booleans_take_words_or_digits(self):
        for yes in ("yes", "y", "true", "1", "ON"):
            fm = form(field("f", type=adm.TYPE_BOOL))
            fm.answer(yes)
            assert fm.values()["f"] is True, yes
        for no in ("no", "n", "false", "0", "Off"):
            fm = form(field("f", type=adm.TYPE_BOOL))
            fm.answer(no)
            assert fm.values()["f"] is False, no

    def test_a_multi_field_splits_on_commas(self):
        fm = form(field("jids", type=adm.TYPE_JID_MULTI))
        fm.answer("a@x.i2p, b@x.i2p ,c@x.i2p")
        assert fm.values()["jids"] == ["a@x.i2p", "b@x.i2p", "c@x.i2p"]

    def test_an_option_outside_the_list_is_refused(self):
        fm = form(field("mode", label="Mode", options=["a", "b"]))
        with pytest.raises(adm.FormError) as exc:
            fm.answer("c")
        assert "a, b" in str(exc.value)

    def test_answering_a_finished_form_raises(self):
        fm = form(field("f"))
        fm.answer("x")
        with pytest.raises(adm.FormError):
            fm.answer("y")

    def test_a_form_of_only_hidden_fields_is_complete_at_once(self):
        fm = form(field("FORM_TYPE", type=adm.TYPE_HIDDEN, value="x"))
        assert fm.is_complete()

    def test_cancelling_completes_without_values_being_asked_for(self):
        fm = form(field("a"), field("b"))
        fm.cancel_value()
        assert fm.is_complete()


class TestThePrompt:

    def test_it_marks_a_required_field(self):
        assert "required" in field("a", required=True).prompt()

    def test_it_offers_the_options(self):
        assert "a/b" in field("m", options=["a", "b"]).prompt()

    def test_it_says_how_to_answer_a_boolean(self):
        assert "yes/no" in field("b", type=adm.TYPE_BOOL).prompt()

    def test_it_says_how_to_answer_a_multi(self):
        assert "comma" in field("j", type=adm.TYPE_JID_MULTI).prompt()

    def test_the_label_falls_back_to_the_variable_name(self):
        assert field("accountjid").label == "accountjid"


# ---------------------------------------------------------------------------
# parsing whatever the server sent
# ---------------------------------------------------------------------------

class TestParsingTheServersForm:

    def test_a_plain_dict_of_fields(self):
        fm = adm.AdminForm.from_payload({"fields": {
            "accountjid": {"label": "JID", "type": "jid-single",
                           "required": True}}})
        assert fm.current().label == "JID"
        assert fm.current().required is True

    def test_a_slixmpp_style_object(self):
        class Form:
            def get_fields(self):
                return {"accountjid": {"label": "JID", "type": "jid-single"}}

            def get(self, key, default=None):
                return {"title": "Add User"}.get(key, default)

        fm = adm.AdminForm.from_payload(Form())
        assert fm.title == "Add User"
        assert fm.current().var == "accountjid"

    def test_options_are_unwrapped(self):
        fm = adm.AdminForm.from_payload({"fields": {
            "m": {"options": [{"value": "a"}, {"value": "b"}]}}})
        assert fm.current().options == ["a", "b"]

    def test_an_unparseable_payload_yields_an_empty_form(self):
        fm = adm.AdminForm.from_payload({})
        assert fm.is_complete()

    def test_summarise_never_raises_on_rubbish(self):
        assert adm.summarise(None) == []
        assert adm.summarise(object()) == []

    def test_a_long_list_is_truncated_with_its_real_size(self):
        # A registered-user list on a busy server is not something to paste
        # in full into a chat client -- but the count must still be true.
        users = ["u%d@x.i2p" % i for i in range(500)]
        lines = adm.summarise(
            {"fields": {"users": {"label": "Users", "type": "jid-multi",
                                  "value": users}}}, limit=5)
        text = "\n".join(lines)
        assert "(500 total)" in text
        assert "u499@x.i2p" not in text

    def test_fixed_text_is_shown_as_prose(self):
        lines = adm.summarise({"fields": {
            "n": {"type": adm.TYPE_FIXED, "value": "3 users online"}}})
        assert any("3 users online" in ln for ln in lines)


class TestCommandNodes:

    def test_a_bare_name_becomes_a_node(self):
        assert adm.command_node("add-user") == adm.ADMIN_NODE + "add-user"

    def test_a_full_node_is_left_alone(self):
        node = adm.ADMIN_NODE + "add-user"
        assert adm.command_node(node) == node

    def test_the_short_name_round_trips(self):
        assert adm.short_name(adm.command_node("delete-user")) == "delete-user"

    def test_a_foreign_node_keeps_its_name(self):
        assert adm.short_name("http://example.com/x") == "http://example.com/x"


# ---------------------------------------------------------------------------
# the client wiring
# ---------------------------------------------------------------------------

xmpp = pytest.importorskip("otrv4plus_xmpp")


class Client:
    """Only the admin surface, borrowed from the real class."""

    for _n in ("take_admin_field", "_handle_admin_answer", "_admin_reset",
               "_admin_ask_next", "_admin_cancel", "_admin_submit"):
        locals()[_n] = getattr(xmpp.OTRv4PlusXMPP, _n)
    del _n

    def __init__(self):
        self._admin_form = None
        self._admin_node = None
        self._admin_session = None
        self._admin_awaiting = False
        self.masked = []
        self.sent = []
        self.boundjid = type("J", (), {"server": "example.i2p"})()
        # A fake xep_0050 that records rather than sends, so the cancel path
        # is exercised for real instead of being stubbed out of existence.
        outer = self

        class _Adhoc:
            async def send_command(self, **kw):
                outer.sent.append(kw)
                return None

        class _Forms:
            @staticmethod
            def make_form(ftype="submit"):
                class F(dict):
                    def add_field(self, var, value):
                        self[var] = value
                return F()

        self.plugin = {"xep_0050": _Adhoc(), "xep_0004": _Forms()}
        self._admin_handled = []
        self.listed = 0
        self.started = []
        self._admin_warned = False

    def _admin_handle_stage(self, iq):
        self._admin_handled.append(iq)

    # -- enough of the surrounding client to drive the real dispatch_line --
    dispatch_line = xmpp.OTRv4PlusXMPP.dispatch_line
    _cmd_admin = xmpp.OTRv4PlusXMPP._cmd_admin

    def take_secret_request(self):
        return None

    def _pending_consent_peer(self):
        return None

    def is_connected(self):
        return True

    async def _admin_list(self):
        self.listed += 1

    async def _admin_start(self, name):
        self.started.append(name)

    def _mask_next_input(self, on):
        self.masked.append(bool(on))
        return True


class TestTheOneShotCapture:

    def test_it_starts_disarmed(self):
        assert Client().take_admin_field() is False

    def test_taking_it_clears_it(self):
        c = Client()
        c._admin_awaiting = True
        assert c.take_admin_field() is True
        assert c.take_admin_field() is False, (
            "an armed capture must survive exactly one dispatched line")

    def test_asking_a_question_arms_it(self, capsys):
        c = Client()
        c._admin_form = form(field("accountjid"))
        c._admin_ask_next()
        assert c._admin_awaiting is True

    def test_a_password_question_asks_for_hiding(self, capsys):
        c = Client()
        c._admin_form = form(field("password", type=adm.TYPE_PRIVATE))
        c._admin_ask_next()
        assert c.masked == [True]

    def test_an_ordinary_question_does_not(self, capsys):
        c = Client()
        c._admin_form = form(field("accountjid"))
        c._admin_ask_next()
        assert c.masked == []

    def test_reset_disarms_and_unmasks(self):
        c = Client()
        c._admin_awaiting = True
        c._admin_form = form(field("a"))
        c._admin_reset()
        assert c._admin_awaiting is False
        assert c._admin_form is None
        assert c.masked == [False], "a reset must not leave input hidden"

    def _cancel(self, c, word="/cancel"):
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            c._handle_admin_answer(word)
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    def test_cancel_wipes_the_form_locally(self, capsys):
        c = Client()
        c._admin_form = form(field("a"))
        c._admin_node, c._admin_session = "n", "s"
        self._cancel(c)
        assert "cancelled" in capsys.readouterr().out
        assert c._admin_form is None
        assert c._admin_awaiting is False

    def test_cancel_tells_the_server_to_drop_the_session(self, capsys):
        c = Client()
        c._admin_form = form(field("a"))
        c._admin_node, c._admin_session = "n", "s"
        self._cancel(c)
        capsys.readouterr()
        assert c.sent and c.sent[0]["action"] == "cancel"
        assert c.sent[0]["sessionid"] == "s"

    def test_abort_is_the_same_as_cancel(self, capsys):
        c = Client()
        c._admin_form = form(field("a"))
        c._admin_node, c._admin_session = "n", "s"
        self._cancel(c, "/abort")
        capsys.readouterr()
        assert c._admin_form is None

    def test_cancel_with_no_session_sends_nothing(self, capsys):
        c = Client()
        c._admin_form = form(field("a"))
        self._cancel(c)
        capsys.readouterr()
        assert c.sent == []

    def test_a_field_value_that_looks_like_a_command_is_still_a_value(self):
        # The reason the capture is taken before command parsing.
        import asyncio
        c = Client()
        c._admin_form = form(field("motd"), field("spare"))
        c._handle_admin_answer("/etc/motd is not a command")
        assert c._admin_form.values()["motd"] == "/etc/motd is not a command"

    def test_the_last_answer_submits_the_form(self, capsys):
        import asyncio
        c = Client()
        c._admin_form = form(field("accountjid", label="JID"))
        c._admin_node, c._admin_session = "n", "s"
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            c._handle_admin_answer("bob@example.i2p")
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        capsys.readouterr()
        assert c.sent and c.sent[0]["action"] == "complete"
        assert c.sent[0]["payload"]["accountjid"] == "bob@example.i2p"

    def test_the_submission_summary_omits_a_password(self, capsys):
        import asyncio
        c = Client()
        c._admin_form = form(field("password", label="Password",
                                   type=adm.TYPE_PRIVATE))
        c._admin_node, c._admin_session = "n", "s"
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            c._handle_admin_answer("hunter2")
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        out = capsys.readouterr().out
        assert "hunter2" not in out
        # ...but the server still gets it.
        assert c.sent[0]["payload"]["password"] == "hunter2"

    def test_a_rejected_answer_re_arms_rather_than_losing_the_form(self,
                                                                  capsys):
        c = Client()
        c._admin_form = form(field("jid", label="JID", required=True))
        c._handle_admin_answer("")
        assert c._admin_form is not None
        assert c._admin_awaiting is True, (
            "a refused answer must ask again, not leave the form stranded")
        assert "JID" in capsys.readouterr().out

    def test_an_answer_with_no_form_open_does_nothing(self):
        Client()._handle_admin_answer("anything")   # must not raise


class TestTheInvariants:

    def test_a_slash_line_reaches_the_form_not_the_command_parser(self):
        """Driven through the real dispatch_line, not by reading the source.

        A field value may legitimately begin with "/" -- a MOTD, a path, a
        message announcement. An earlier version of this test asserted the
        ORDER of two strings in the source, which a mutation to
        `if False and self.take_admin_field():` walked straight past.
        """
        import asyncio
        c = Client()
        # Two fields so answering the first does not finish the form and
        # reach the submit path, which needs a running loop.
        c._admin_form = form(field("motd"), field("spare"))
        c._admin_awaiting = True
        assert c.dispatch_line(None, "/tui") is True
        assert c._admin_form.values()["motd"] == "/tui", (
            "the line was parsed as a command instead of answering the form")

    def test_a_slash_command_still_works_with_no_form_open(self):
        import asyncio
        c = Client()
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            assert c.dispatch_line(None, "/admin") is True
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        assert c._admin_form is None
        assert c.listed == 1, "/admin should have listed the server's commands"

    def test_only_the_local_command_path_arms_a_form(self):
        """INV-06, applied to admin forms.

        `_admin_awaiting` may be set only where this client decided to ask a
        question. If anything reachable from an inbound stanza could set it,
        a server or a peer could make the next line typed into form input.
        """
        import inspect
        import re
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        setters = re.findall(r"^\s*(?:self\.)?_admin_awaiting\s*=\s*(\S+)",
                             src, re.M)
        assert setters, "the flag is gone; this test needs rewriting"
        # Exactly one place sets it True, and that is _admin_ask_next.
        assert setters.count("True") == 1
        fn = inspect.getsource(xmpp.OTRv4PlusXMPP._admin_ask_next)
        assert "_admin_awaiting = True" in fn

    def test_admin_output_is_not_written_to_the_transcript(self):
        """[admin] carries JIDs, user lists and passwords.

        It is deliberately absent from _LOG_SAFE_TAGS, so `_log_line_for_file`
        falls through to "<unlogged line: N chars>".
        """
        redacted = xmpp._log_line_for_file(
            "[admin] Password: hunter2")
        assert "hunter2" not in redacted
        assert "unlogged line" in redacted

    def test_the_admin_tag_is_coloured_for_attention(self):
        # It is the one surface that is not end-to-end encrypted and the one
        # that can delete an account.
        assert xmpp._TAG_COLOURS["admin"] == "bold_yellow"

    def _run(self, coro):
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_the_client_says_admin_is_not_end_to_end(self, capsys):
        c = Client()
        self._run(c._cmd_admin(""))
        out = capsys.readouterr().out
        assert "NOT" in out and "OTR" in out, (
            "admin is the one surface that is not end-to-end encrypted and "
            "the user must be told before the first command")
        assert c.listed == 1

    def test_the_notice_is_said_once_per_session(self, capsys):
        c = Client()
        self._run(c._cmd_admin(""))
        capsys.readouterr()
        self._run(c._cmd_admin(""))
        assert "OTR" not in capsys.readouterr().out

    def test_a_second_command_is_refused_while_a_form_is_open(self, capsys):
        c = Client()
        c._admin_warned = True
        c._admin_form = form(field("a"))
        self._run(c._cmd_admin("add-user"))
        assert "already open" in capsys.readouterr().out
        assert c.started == []

    def test_the_data_form_and_adhoc_plugins_are_registered(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert 'register_plugin("xep_0004")' in src
        assert 'register_plugin("xep_0050")' in src

    def test_the_unused_wrapper_plugin_is_not_registered(self):
        # xep_0133 is thirty-two thin wrappers this client does not call.
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert 'register_plugin("xep_0133")' not in src
