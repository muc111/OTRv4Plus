"""The IRC client's SMP flow, brought level with the XMPP client's.

WHAT WAS WRONG
==============
Three things, seen on a handset:

1. **A y/n trust prompt on first contact.** `Trust this fingerprint? Type y
   or n` — a decision nobody can make, because on first contact there is
   nothing to compare against. The XMPP client pins silently and reports a
   *change*. Worse, the prompt was armed by a remote DAKE, which is the shape
   INV-06 exists to keep out of the client.

2. **`/smp` did not ask for anything.** Bare `/smp` printed "Type
   `/smp <passphrase>` (it will be visible on this terminal)" — asking the
   user to put a shared secret into their own scrollback. `_finish_trust`
   had been promising "it will ask for the passphrase" since v10.15, and
   `set_input_mask()` had existed the whole time with **no caller**.

3. **The responder was never asked.** A peer's SMP1 arriving with no stored
   passphrase went nowhere the user could see, so verification could only
   ever be driven from one side.

WHAT REPLACED IT
================
The XMPP client's flow, using the same `otrv4plus_smpflow.SmpFlow` rather
than a second implementation of it. That matters for INV-06: the property is
that a remote peer may make the client ASK for the passphrase but never make
the next typed line BECOME one, and in SmpFlow that is structural — there is
no edge from a remote transition into AWAITING_SECRET. A reimplementation
would be a second chance to get it wrong.

`SMP_UX_AUDIT.md` §7 item 4 asked for exactly this and for INV-06's test to
be extended to `otrv4+.py`. The first half shipped (the `smp_secret` pending
was removed); the coverage never did. It is here.

Enforces INV-06 and INV-11 for the IRC client.
"""

import ast
import os
import threading as _threading

import pytest

otr = pytest.importorskip("otrv4plus")
smpflow = pytest.importorskip("otrv4plus_smpflow")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "otrv4+.py")

CLIENT = otr.EnhancedOTRv4IRCClient

#: Every method the guided flow needs, bound onto the stub below. Named
#: explicitly so adding a method to the flow without considering how a peer
#: might reach it shows up here.
FLOW_METHODS = (
    "_smp_verify", "_announce_secret_required", "_handle_smp_consent",
    "_arm_secret_prompt", "_disarm_secret_prompt", "_consume_secret_line",
    "_decline_smp_request", "_resume_smp", "_check_smp_secret_required",
)


class Stub:
    """Only the collaborators the flow touches.

    Deliberately not a live client: the flow needs a panel, a storage object
    and a way to send, and a stub makes that surface visible. Anything it
    reaches for that is not here is a dependency nobody intended.
    """

    def __init__(self, stored=None, held=False):
        self.lines = []
        self.sent = []
        self.started = []
        self.resumed = []
        self.declined = []
        self.stored = dict(stored or {})
        self.held = held
        self._smp_flows = smpflow.SmpFlowRegistry()
        self._secret_request = None
        self._secret_purpose = None
        self._smp_consent_shown = None
        self._prompt_refresh_cb = None
        self._pending_action = None
        self._pending_lock = _threading.Lock()
        for name in FLOW_METHODS + ("_dispatch_pending_response",
                                    "_get_pending", "_clear_pending"):
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    # -- collaborators ------------------------------------------------
    def add_message(self, peer, msg, sec=None):
        self.lines.append(msg)

    def debug(self, *a, **k):
        pass

    def _panel_sec(self, peer):
        return None

    def _set_pending(self, kind, peer, **kw):
        self._pending_action = {"type": kind, "peer": peer}

    def _handle_trust_response(self, peer, response, action):
        pass

    def _start_smp(self, peer, secret):
        self.started.append((peer, secret))

    def send_otr_message(self, peer, msg):
        self.sent.append((peer, msg))

    @property
    def session_manager(self):
        return _Manager(self)

    def said(self, needle):
        return any(needle in str(line) for line in self.lines)


class _Storage:
    def __init__(self, owner):
        self._o = owner

    def get_secret(self, peer):
        return self._o.stored.get(peer, "")

    def set_secret(self, peer, secret):
        self._o.stored[peer] = secret


class _Manager:
    def __init__(self, owner):
        self._o = owner

    @property
    def smp_storage(self):
        return _Storage(self._o)

    def smp_secret_required(self, peer):
        return self._o.held

    def resume_held_smp1(self, peer):
        self._o.resumed.append(peer)
        return "?OTRv4 SMP2"

    def decline_held_smp1(self, peer):
        self._o.declined.append(peer)
        return "?OTRv4 ABORT"


@pytest.fixture(autouse=True)
def _mask_off():
    """The mask is module-global. A test that armed a prompt and failed
    before disarming would otherwise hide the next test's input."""
    otr.set_input_mask(False)
    yield
    otr.set_input_mask(False)


class TestTheInitiator:
    """`/smp` asks for what is missing, hidden, and starts."""

    def test_a_bare_smp_arms_a_masked_read(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        assert otr._mask_input is True, "the passphrase would be echoed"
        assert s._secret_request == "GlacialWolf"
        assert s._secret_purpose == "start"

    def test_it_no_longer_tells_the_user_to_type_it_visibly(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        assert not s.said("visible on this terminal")
        assert not s.said("/smp <passphrase>")

    def test_the_line_becomes_the_passphrase_and_starts_smp(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        assert s._consume_secret_line("correct horse battery") is True
        assert s.stored["GlacialWolf"] == "correct horse battery"
        assert s.started == [("GlacialWolf", "correct horse battery")]

    def test_a_stored_passphrase_skips_the_prompt(self):
        s = Stub(stored={"GlacialWolf": "already known"})
        s._smp_verify("GlacialWolf")
        assert otr._mask_input is False
        assert s._secret_request is None
        assert s.started == [("GlacialWolf", "already known")]

    def test_asking_twice_does_not_re_arm(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._smp_verify("GlacialWolf")
        assert s.said("Already asking you")

    def test_the_passphrase_is_never_put_in_a_message(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._consume_secret_line("correct horse battery")
        assert not s.said("correct horse battery"), (
            "the passphrase was printed to the panel")
        assert not any("correct horse battery" in str(m)
                       for _, m in s.sent)


class TestTheMaskIsAlwaysLifted:
    """A mask left on hides the user's ordinary chat; `_secret_request` left
    set makes their next line a passphrase. Every exit has to clear both."""

    @pytest.mark.parametrize("answer,why", [
        ("correct horse battery", "accepted"),
        ("", "cancelled with an empty line"),
        ("short", "rejected as too short"),
        ("x" * (otr.SMP_MAX_LEN + 1), "rejected as too long"),
    ])
    def test_after_every_outcome(self, answer, why):
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._consume_secret_line(answer)
        assert otr._mask_input is False, "mask still on after %s" % why
        assert s._secret_request is None, "still armed after %s" % why

    def test_a_storage_failure_still_lifts_it(self, monkeypatch):
        def explode(self, peer, secret):
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(_Storage, "set_secret", explode)
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._consume_secret_line("correct horse battery")
        assert otr._mask_input is False
        assert s._secret_request is None
        assert s.stored == {}

    def test_a_rejected_length_never_names_the_value(self):
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._consume_secret_line("hunter2")
        assert not s.said("hunter2")
        assert s.said("characters")

    def test_nothing_is_consumed_when_nothing_was_asked(self):
        s = Stub()
        assert s._consume_secret_line("an ordinary message") is False
        assert s.stored == {}


class TestTheResponder:
    """A peer's SMP1 gets the user asked, and only a local answer opens the
    passphrase prompt."""

    def test_a_held_smp1_produces_a_consent_prompt(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        assert s._smp_flows.get("BurningVortex").state == \
            smpflow.AWAITING_LOCAL_CONSENT
        assert s.said("wants to verify")
        assert s._pending_action == {"type": "smp_consent",
                                     "peer": "BurningVortex"}

    def test_the_consent_prompt_arms_nothing(self):
        """THE assertion. A remote message may ask; it may not decide that
        the next line is a secret."""
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        assert otr._mask_input is False
        assert s._secret_request is None
        assert s._consume_secret_line("an ordinary message") is False

    def test_only_a_local_yes_opens_the_prompt(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        s._handle_smp_consent("BurningVortex", "y")
        assert otr._mask_input is True
        assert s._secret_request == "BurningVortex"
        assert s._secret_purpose == "resume"

    def test_the_answer_resumes_the_held_smp1_without_a_second_round_trip(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        s._handle_smp_consent("BurningVortex", "y")
        s._consume_secret_line("correct horse battery")
        assert s.resumed == ["BurningVortex"]
        assert s.sent == [("BurningVortex", "?OTRv4 SMP2")]

    def test_declining_tells_the_peer_and_arms_nothing(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        s._handle_smp_consent("BurningVortex", "n")
        assert s.declined == ["BurningVortex"]
        assert s.sent == [("BurningVortex", "?OTRv4 ABORT")]
        assert s._secret_request is None
        assert otr._mask_input is False

    def test_cancelling_at_the_passphrase_declines_rather_than_hanging(self):
        """An empty line after consenting must not leave the peer waiting."""
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        s._handle_smp_consent("BurningVortex", "y")
        s._consume_secret_line("")
        assert s.declined == ["BurningVortex"]

    def test_a_resent_smp1_does_not_print_a_second_prompt(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        first = len(s.lines)
        s._check_smp_secret_required("BurningVortex")
        assert len(s.lines) == first

    def test_an_ordinary_message_at_the_prompt_stays_ordinary(self):
        """The prompt promises "an ordinary message here is just an ordinary
        message". If a non-answer were taken as consent, a peer's SMP1 plus
        the user's next sentence would open the passphrase read between
        them -- which is INV-06 with two steps instead of one."""
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        consumed = s._dispatch_pending_response("what are you up to")
        assert consumed is False, "the line was swallowed instead of sent"
        assert s._secret_request is None, "an ordinary message opened the read"
        assert otr._mask_input is False
        assert s._smp_flows.get("BurningVortex").state == \
            smpflow.AWAITING_LOCAL_CONSENT, "the question was abandoned"
        assert s._pending_action == {"type": "smp_consent",
                                     "peer": "BurningVortex"}, \
            "the prompt was not re-armed, so a later y would be ignored"

    @pytest.mark.parametrize("answer", ["y", "Y", "yes", "YES"])
    def test_only_these_count_as_consent(self, answer):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        assert s._dispatch_pending_response(answer) is True
        assert s._secret_request == "BurningVortex"

    @pytest.mark.parametrize("answer", ["n", "N", "no", "NO"])
    def test_only_these_count_as_refusal(self, answer):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        assert s._dispatch_pending_response(answer) is True
        assert s.declined == ["BurningVortex"]
        assert s._secret_request is None

    def test_a_later_yes_still_works_after_an_ordinary_message(self):
        s = Stub(held=True)
        s._check_smp_secret_required("BurningVortex")
        s._dispatch_pending_response("hang on")
        s._dispatch_pending_response("y")
        assert s._secret_request == "BurningVortex"

    def test_no_held_message_means_no_prompt(self):
        s = Stub(held=False)
        s._check_smp_secret_required("BurningVortex")
        assert s.lines == []
        assert s._pending_action is None


class TestInv06CoversTheIrcClientNow:
    """`SMP_UX_AUDIT.md` §7 item 4: *"IRC. Remove the remotely-armed generic
    capture and extend INV-06's test to cover otrv4+.py."*

    The removal shipped. The coverage did not, and `otrv4+.py` was never
    walked by `test_no_remote_input_capture.py` — which is how the client
    could grow a masked read without anyone checking what could reach it.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def methods():
        with open(ENGINE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        out = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault(node.name, []).append(node)
        return out

    @staticmethod
    def _calls(node):
        names = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                if isinstance(f, ast.Attribute):
                    names.add(f.attr)
                elif isinstance(f, ast.Name):
                    names.add(f.id)
        return names

    def _reachable(self, entry, methods, seen=None):
        seen = seen if seen is not None else set()
        frontier = [entry]
        while frontier:
            name = frontier.pop()
            if name in seen:
                continue
            seen.add(name)
            for defn in methods.get(name, ()):
                for called in self._calls(defn):
                    if called not in seen and called in methods:
                        frontier.append(called)
        return seen

    def test_exactly_one_method_arms_the_masked_read(self, methods):
        """One door, so there is one thing to check the reachability of."""
        armers = set()
        for name, defns in methods.items():
            for defn in defns:
                for node in ast.walk(defn):
                    if not isinstance(node, ast.Assign):
                        continue
                    for t in node.targets:
                        if (isinstance(t, ast.Attribute)
                                and t.attr == "_secret_request"
                                and not isinstance(node.value, ast.Constant)):
                            armers.add(name)
        assert armers == {"_arm_secret_prompt"}, (
            "_secret_request is set outside _arm_secret_prompt: %s" % armers)

    @pytest.mark.parametrize("inbound", [
        "_handle_data_message",
        "_handle_session_established",
        "process_dake3",
        "_enh_route_tlvs",
        "_enh_handle_smp_tlv",
        "_announce_secret_required",
        "_check_smp_secret_required",
        "handle_line",
    ])
    def test_no_inbound_path_reaches_the_armer(self, inbound, methods):
        """A remote message may reach the CONSENT prompt and stop there.
        `_arm_secret_prompt` is reachable only from `_smp_verify` (a typed
        /smp) and `_handle_smp_consent` (a typed y)."""
        if inbound not in methods:
            pytest.skip("%s is not in this build" % inbound)
        reachable = self._reachable(inbound, methods)
        assert "_arm_secret_prompt" not in reachable, (
            "%s can reach the passphrase prompt; a peer would then decide "
            "what the user's next line means (INV-06)" % inbound)

    @pytest.mark.parametrize("local", ["_smp_verify", "_handle_smp_consent"])
    def test_the_local_paths_do_reach_it(self, local, methods):
        """The other half: a check that passes because nothing reaches the
        armer at all would be worthless."""
        assert "_arm_secret_prompt" in self._reachable(local, methods)

    def test_the_old_smp_secret_pending_has_not_come_back(self, methods):
        """Checked against the AST, not the text.

        Two comments in the file quote the old call on purpose, to explain
        what was removed and why. A substring search matches the explanation
        of the fix and fails forever -- which is the trap
        `test_no_remote_input_capture.py` documents for the XMPP side.
        """
        with open(ENGINE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute)
                    and func.attr == "_set_pending"):
                continue
            if not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant):
                assert first.value != "smp_secret", (
                    "the remotely-armed generic capture is back at line %d"
                    % node.lineno)


class TestFirstContactPinsInsteadOfAsking:
    """INV-11 semantics on IRC: pin on first contact, report a change, never
    auto-accept a change."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        with open(ENGINE, encoding="utf-8") as fh:
            return fh.read()

    def test_the_yes_no_trust_prompt_is_gone(self, source):
        assert "Trust this fingerprint? Type" not in source, (
            "first contact still asks a question the user cannot answer, and "
            "it is armed by a remote DAKE"
        )

    def test_first_contact_pins(self, source):
        assert "First contact — fingerprint pinned" in source

    def test_a_change_is_reported_and_not_trusted(self, source):
        start = source.index("_fingerprint_changed(peer, remote_fp)")
        block = source[start:start + 1500]
        assert "FINGERPRINT CHANGED" in block
        assert "trusted=False" in block, (
            "a changed fingerprint was auto-accepted; INV-11 says the old pin "
            "stands until the user clears it deliberately"
        )
        assert "/trust-reset" in block

    def test_the_changed_check_treats_no_entry_as_first_contact(self):
        """Not as a change: crying wolf on every new nick would train the
        user to ignore the one that matters."""
        class Empty:
            trust_db = type("D", (), {"_db": {}})()

        stub = type("S", (), {"session_manager": Empty(), "debug": lambda *a: None})()
        changed = CLIENT._fingerprint_changed.__get__(stub)
        assert changed("nick", "AABB") is False

    def test_a_different_stored_fingerprint_is_a_change(self):
        class Db:
            _db = {"nick": {"fingerprint": "OLDFP"}}

        stub = type("S", (), {
            "session_manager": type("M", (), {"trust_db": Db()})(),
            "debug": lambda *a: None,
        })()
        changed = CLIENT._fingerprint_changed.__get__(stub)
        assert changed("nick", "NEWFP") is True
        assert changed("nick", "OLDFP") is False


class TestBothClientsAgreeOnTheBounds:
    """The length bounds lived in the XMPP client only, so the IRC client had
    none. Two clients disagreeing about how long a shared secret may be is a
    way for one side to store something the other refuses."""

    def test_the_engine_defines_them(self):
        assert otr.SMP_MIN_LEN == 8
        assert otr.SMP_MAX_LEN == 512

    def test_the_xmpp_client_uses_the_engines(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        assert (xmpp.SMP_MIN_LEN, xmpp.SMP_MAX_LEN) == \
            (otr.SMP_MIN_LEN, otr.SMP_MAX_LEN)

    @pytest.mark.parametrize("length,ok", [
        (otr.SMP_MIN_LEN - 1, False),
        (otr.SMP_MIN_LEN, True),
        (otr.SMP_MAX_LEN, True),
        (otr.SMP_MAX_LEN + 1, False),
    ])
    def test_the_irc_client_enforces_them(self, length, ok):
        s = Stub()
        s._smp_verify("GlacialWolf")
        s._consume_secret_line("x" * length)
        assert ("GlacialWolf" in s.stored) is ok
