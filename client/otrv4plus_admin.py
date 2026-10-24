"""XEP-0133 service administration, driven by the forms the server sends.

WHY THIS IS GENERIC RATHER THAN A LIST OF COMMANDS
--------------------------------------------------
XEP-0133 defines thirty-two admin commands and slixmpp implements all of them,
but no server implements all of them and Prosody's subset is not ejabberd's.
Hand-coding "the six useful ones" would therefore be wrong twice over: it would
offer commands a given server refuses, and hide ones it supports.

So nothing here knows what a command is called or what it needs.  The server
advertises its commands over service discovery, and each command answers with a
XEP-0004 data form describing its own fields.  This module turns that form into
a sequence of questions and the answers back into a form.  A server that adds a
command gets it for free; one that removes a field stops asking for it.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
Any network I/O.  This module is a state machine over fields and answers, so
the whole of the awkward part -- required fields, hidden fields, multi-stage
forms, passwords that must not echo -- is testable without a server, an event
loop or a socket.

SECURITY
--------
Three properties, none of which is incidental:

1. **A form is armed only by the local user typing `/admin`.**  Nothing a
   remote peer or the server can send may put this client into a state where
   the next line typed becomes form input.  This is the same rule as INV-06 for
   the SMP passphrase and it is enforced the same way: the client holds a
   one-shot request that only its own command handler sets.

2. **`text-private` values never appear anywhere but the wire.**  `add-user`
   and `change-user-password` carry passwords.  They are excluded from every
   rendering path in this module -- `describe()`, `summary()`, the repr of a
   field -- so a value cannot reach the terminal, the session transcript or a
   traceback by being formatted alongside something that was safe.

3. **Admin traffic is NOT end-to-end encrypted.**  It is ordinary XMPP between
   an operator and their own server, protected by the transport (I2P, or TLS)
   and nothing else.  OTR does not apply and cannot: the server is the intended
   recipient.  The caller is expected to say so before the first command.
"""

#: Field types from XEP-0004 that this module gives special treatment.
TYPE_PRIVATE = "text-private"      # a password: never rendered
TYPE_HIDDEN = "hidden"             # server bookkeeping: echoed back untouched
TYPE_FIXED = "fixed"               # informational text: not a question
TYPE_BOOL = "boolean"
TYPE_MULTI = "text-multi"
TYPE_LIST_MULTI = "list-multi"
TYPE_JID_MULTI = "jid-multi"

#: Types the user is never asked about.
NOT_A_QUESTION = frozenset({TYPE_HIDDEN, TYPE_FIXED})

#: What is printed in place of a private value, everywhere.
REDACTED = "<not shown>"

#: Values accepted for a boolean field, and what they mean.
_TRUE = frozenset({"1", "true", "yes", "y", "on"})
_FALSE = frozenset({"0", "false", "no", "n", "off"})

#: Separator for the multi-valued field types.
MULTI_SEP = ","


class AdminField:
    """One field of a server-sent form.

    `value` is write-once from the user's answer, or pre-filled by the server
    for hidden and fixed fields.
    """

    __slots__ = ("var", "label", "type", "required", "options", "value",
                 "desc")

    def __init__(self, var, label=None, type="text-single", required=False,
                 options=None, value=None, desc=None):
        self.var = str(var)
        self.label = str(label) if label else self.var
        self.type = str(type or "text-single")
        self.required = bool(required)
        self.options = list(options or [])
        self.value = value
        self.desc = str(desc) if desc else ""

    # -- what a user is shown ---------------------------------------------

    @property
    def is_private(self) -> bool:
        return self.type == TYPE_PRIVATE

    @property
    def is_question(self) -> bool:
        return self.type not in NOT_A_QUESTION

    @property
    def is_multi(self) -> bool:
        return self.type in (TYPE_MULTI, TYPE_LIST_MULTI, TYPE_JID_MULTI)

    def prompt(self) -> str:
        """The question, with whatever help the form itself provided."""
        bits = [self.label]
        if self.required:
            bits.append("(required)")
        if self.type == TYPE_BOOL:
            bits.append("[yes/no]")
        elif self.options:
            bits.append("[%s]" % "/".join(str(o) for o in self.options[:8]))
        elif self.is_multi:
            bits.append("[comma-separated]")
        line = " ".join(bits) + ":"
        if self.desc:
            line = "%s\n    %s" % (line, self.desc)
        return line

    def shown_value(self):
        """The value, or a stand-in when showing it would leak it.

        The single choke point for rendering a value. Every path that displays
        a field goes through here so a password cannot escape by being
        formatted somewhere that forgot to check.
        """
        if self.is_private:
            return REDACTED if self.value not in (None, "") else ""
        if self.value is None:
            return ""
        if isinstance(self.value, (list, tuple)):
            return MULTI_SEP.join(str(v) for v in self.value)
        return str(self.value)

    def __repr__(self):                                  # pragma: no cover
        return "AdminField(%r, type=%r, value=%r)" % (
            self.var, self.type, REDACTED if self.is_private else self.value)


class FormError(ValueError):
    """A rejected answer.  Carries no value, only the reason."""


class AdminForm:
    """A form part-way through being filled in.

    Answers arrive one line at a time because that is how the client's input
    loop works, so this holds a cursor rather than taking a dict: the caller
    asks what to prompt for, hands back a line, and repeats until complete.
    """

    def __init__(self, fields, title=None, instructions=None):
        self.fields = list(fields)
        self.title = str(title) if title else ""
        self.instructions = str(instructions) if instructions else ""
        self._index = 0
        self._advance()

    # -- construction ------------------------------------------------------

    @classmethod
    def from_payload(cls, payload):
        """Build from a slixmpp form, or from the plain dict a test supplies.

        Tolerant on purpose. slixmpp's form objects differ across versions and
        this module should not care: anything that yields (var, spec) pairs
        with the XEP-0004 key names works.
        """
        fields, title, instructions = [], "", ""
        try:
            title = payload.get("title", "") or ""
            instructions = payload.get("instructions", "") or ""
        except Exception:
            pass
        raw = None
        for getter in ("get_fields", "getFields"):
            fn = getattr(payload, getter, None)
            if callable(fn):
                try:
                    raw = fn()
                    break
                except Exception:
                    raw = None
        if raw is None:
            raw = payload.get("fields", payload) if hasattr(
                payload, "get") else payload
        try:
            items = raw.items()
        except AttributeError:
            items = [(f.get("var"), f) for f in raw]
        for var, spec in items:
            if var is None:
                continue
            get = spec.get if hasattr(spec, "get") else (lambda k, d=None: d)
            fields.append(AdminField(
                var=var,
                label=get("label"),
                type=get("type") or "text-single",
                required=bool(get("required")),
                options=[o.get("value") if hasattr(o, "get") else o
                         for o in (get("options") or [])],
                value=get("value"),
                desc=get("desc"),
            ))
        return cls(fields, title, instructions)

    # -- the cursor --------------------------------------------------------

    def _advance(self):
        """Move to the next field a user should actually be asked about."""
        while (self._index < len(self.fields)
               and not self.fields[self._index].is_question):
            self._index += 1

    def current(self):
        """The field awaiting an answer, or None when the form is done."""
        return None if self.is_complete() else self.fields[self._index]

    def is_complete(self) -> bool:
        return self._index >= len(self.fields)

    @property
    def remaining(self) -> int:
        return sum(1 for f in self.fields[self._index:] if f.is_question)

    def answer(self, text):
        """Record one answer and move on.  Raises FormError if unusable.

        An empty answer to an optional field is a skip, which is how a user
        gets past the many optional fields on commands like `add-user`. An
        empty answer to a REQUIRED field is refused rather than sent, because
        the server would refuse it anyway and its error would arrive without
        saying which field it meant.
        """
        field = self.current()
        if field is None:
            raise FormError("the form is already complete")
        text = "" if text is None else str(text)
        if not text.strip():
            if field.required:
                raise FormError("%s is required" % field.label)
            field.value = None
        else:
            field.value = self._coerce(field, text)
        self._index += 1
        self._advance()
        return field

    @staticmethod
    def _coerce(field, text):
        """Turn a typed line into what the field expects.

        Never mentions `text` in an exception. A boolean field is not secret,
        but `_coerce` is shared with `text-private` and an error message that
        quoted the input would put a password in a traceback.
        """
        text = text.strip()
        if field.type == TYPE_BOOL:
            low = text.lower()
            if low in _TRUE:
                return True
            if low in _FALSE:
                return False
            raise FormError("%s expects yes or no" % field.label)
        if field.is_multi:
            return [p.strip() for p in text.split(MULTI_SEP) if p.strip()]
        if field.options:
            allowed = [str(o) for o in field.options]
            if text not in allowed:
                raise FormError("%s must be one of: %s"
                                % (field.label, ", ".join(allowed)))
        return text

    def cancel_value(self):
        """`_index` past the end, so `is_complete` is true and nothing sends."""
        self._index = len(self.fields)

    # -- output ------------------------------------------------------------

    def values(self):
        """var -> value, for submission.  Skipped optional fields are omitted.

        Hidden fields ARE included: they carry the server's own bookkeeping
        and dropping them breaks multi-stage commands.
        """
        out = {}
        for f in self.fields:
            if f.type == TYPE_FIXED:
                continue
            if f.value is None:
                continue
            out[f.var] = f.value
        return out

    def describe(self):
        """What was filled in, for showing back before submission.

        Passwords are not in it. This is the line a user reads to check they
        are about to do the right thing, and it must be safe to have on screen
        and in the transcript.
        """
        lines = []
        for f in self.fields:
            if not f.is_question or f.value is None:
                continue
            lines.append("  %s: %s" % (f.label, f.shown_value()))
        return lines


def summarise(payload, limit=40):
    """Render whatever a completed command sent back.

    Admin results are either a form of fields or a list of items, and the
    interesting ones (`get-online-users-list`, `get-registered-users-num`) are
    exactly the shapes a person wants pasted into a terminal. Anything that
    cannot be parsed returns nothing rather than a guess -- the caller prints a
    plain "completed" instead of inventing structure that was not there.

    `limit` bounds the output: a registered-user list on a busy server is not
    something to paste in full into a chat client.
    """
    lines = []
    try:
        form = AdminForm.from_payload(payload)
    except Exception:
        return lines
    for f in form.fields:
        if f.type == TYPE_HIDDEN:
            continue
        shown = f.shown_value()
        if not shown and f.type != TYPE_FIXED:
            continue
        if f.type == TYPE_FIXED:
            if shown:
                lines.append("  %s" % shown)
            continue
        if isinstance(f.value, (list, tuple)) and len(f.value) > limit:
            head = MULTI_SEP.join(str(v) for v in f.value[:limit])
            lines.append("  %s: %s … (%d total)"
                         % (f.label, head, len(f.value)))
        else:
            lines.append("  %s: %s" % (f.label, shown))
    return lines


#: The admin node prefix every XEP-0133 command hangs off.
ADMIN_NODE = "http://jabber.org/protocol/admin#"


def command_node(name) -> str:
    """Full node for a command, accepting either a bare name or a full node."""
    name = str(name).strip()
    if name.startswith(ADMIN_NODE):
        return name
    return ADMIN_NODE + name.lstrip("#")


def short_name(node) -> str:
    """The bare command name, for display."""
    node = str(node)
    return node[len(ADMIN_NODE):] if node.startswith(ADMIN_NODE) else node
