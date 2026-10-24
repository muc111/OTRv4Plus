# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's `/admin` command: XEP-0133 service administration.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py), which it is only ever used
as. The form logic itself is otrv4plus_admin.py; this is the part that
talks to the server and to the person at the terminal."""
import asyncio

import otrv4plus_admin as _admin
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)


class AdminMixin:
    """`/admin` and the form it walks through. Mixed into OTRv4PlusXMPP."""

    # -- XEP-0133 service administration -----------------------------------
    #
    # Nothing here knows the name of a single admin command.  The server
    # advertises what it supports and each command describes its own fields,
    # so Prosody's subset and ejabberd's differ without this code caring.
    # See otrv4plus_admin.py for why that is the design rather than a list.
    #
    # This is the ONE part of the client that deliberately speaks plaintext to
    # a third party.  The server is the intended recipient of an admin
    # command, so OTR does not apply -- there is nobody to be end-to-end with.
    # `_admin_warned` makes sure that is said once per session before the
    # first command rather than buried in the docs.

    async def _cmd_admin(self, arg):
        """`/admin` lists what the server offers; `/admin <cmd>` runs one."""
        try:
            if not self.is_connected():
                print("[admin] not connected")
                return
            if self._admin_form is not None:
                print("[admin] a form is already open — answer it, or "
                      "/cancel")
                return
            if not self._admin_warned:
                self._admin_warned = True
                print("[admin] NOTE: admin commands are ordinary XMPP to your "
                      "own server.")
                print("[admin] They are protected by the transport (I2P or "
                      "TLS) and NOT by OTR —")
                print("[admin] the server is the intended recipient, so there "
                      "is nobody to be end-to-end with.")
            if not arg:
                await self._admin_list()
            else:
                await self._admin_start(arg)
        except Exception as exc:
            self._admin_reset()
            print("[admin] failed: %s" % _sanitise(str(exc), 200))

    async def _admin_list(self):
        """Ask the server which admin commands it actually has."""
        server = self.boundjid.server
        print("[admin] asking %s what it supports…" % _sanitise(server, 64))
        try:
            items = await self.plugin["xep_0050"].get_commands(
                jid=server, local=False)
        except Exception as exc:
            print("[admin] the server would not list its commands: %s"
                  % _sanitise(str(exc), 160))
            print("[admin] that usually means this account is not an admin "
                  "on %s" % _sanitise(server, 64))
            return
        names = []
        try:
            for item in items["disco_items"]["items"]:
                node = item[1] if len(item) > 1 else ""
                if node and node.startswith(_admin.ADMIN_NODE):
                    names.append(_admin.short_name(node))
        except Exception:
            pass
        if not names:
            print("[admin] the server advertises no XEP-0133 commands for "
                  "this account")
            return
        print("[admin] %d command(s):" % len(names))
        for name in sorted(names):
            print("[admin]   %s" % name)
        print("[admin] run one with:  /admin <command>")

    async def _admin_start(self, name):
        """Execute a command and either show the result or open its form."""
        server = self.boundjid.server
        node = _admin.command_node(name)
        print("[admin] %s → %s" % (_admin.short_name(node),
                                   _sanitise(server, 64)))
        try:
            iq = await self.plugin["xep_0050"].send_command(
                jid=server, node=node, action="execute")
        except Exception as exc:
            print("[admin] refused: %s" % _sanitise(str(exc), 200))
            return
        self._admin_node = node
        self._admin_session = iq["command"]["sessionid"]
        self._admin_handle_stage(iq)

    def _admin_handle_stage(self, iq):
        """One round trip: finished, or a form to fill in."""
        cmd = iq["command"]
        status = cmd["status"]
        for note in self._admin_notes(cmd):
            print("[admin] %s" % note)
        if status == "completed":
            lines = _admin.summarise(cmd["form"])
            if lines:
                for line in lines:
                    print("[admin] %s" % _sanitise(line, 400))
            else:
                print("[admin] done")
            self._admin_reset()
            return
        try:
            form = _admin.AdminForm.from_payload(cmd["form"])
        except Exception:
            form = None
        if form is None or form.is_complete():
            print("[admin] the server wants something this client cannot "
                  "render — no form fields in its reply")
            self._admin_reset()
            return
        self._admin_form = form
        if form.title:
            print("[admin] %s" % _sanitise(form.title, 200))
        if form.instructions:
            print("[admin] %s" % _sanitise(form.instructions, 400))
        print("[admin] %d question(s). Blank skips an optional one, /cancel "
              "aborts." % form.remaining)
        self._admin_ask_next()

    @staticmethod
    def _admin_notes(cmd):
        """Whatever the server said in <note/>, which is often the real answer."""
        out = []
        try:
            notes = cmd["notes"]
        except Exception:
            return out
        for note in notes or []:
            try:
                text = note[1] if isinstance(note, (list, tuple)) else str(note)
            except Exception:
                continue
            if text:
                out.append(_sanitise(str(text), 300))
        return out

    def _admin_ask_next(self):
        """Print the current question and arm the one-shot input capture."""
        form = self._admin_form
        if form is None:
            return
        field = form.current()
        if field is None:
            asyncio.ensure_future(self._admin_submit())
            return
        print("[admin] %s" % field.prompt())
        # Hidden input for a password field, on the same mechanism the SMP
        # passphrase uses. If hiding does not work on this front end the user
        # is told, rather than being promised privacy that is not there.
        if field.is_private:
            if not self._mask_next_input(True):
                print("[admin] ⚠ this terminal will ECHO what you type")
        self._admin_awaiting = True

    def _handle_admin_answer(self, line):
        """One typed line, as the answer to the current field."""
        form = self._admin_form
        if form is None:
            return
        if line.strip().lower() in ("/cancel", "/abort"):
            print("[admin] cancelled — nothing was sent")
            asyncio.ensure_future(self._admin_cancel())
            return
        try:
            form.answer(line)
        except _admin.FormError as exc:
            # The message names the FIELD, never the value: this path is
            # shared with text-private and an echoed answer would be a
            # password on screen and in the transcript.
            print("[admin] %s" % _sanitise(str(exc), 200))
            self._admin_ask_next()
            return
        self._admin_ask_next()

    async def _admin_submit(self):
        """Send the completed form."""
        form, node = self._admin_form, self._admin_node
        session = self._admin_session
        if form is None:
            return
        shown = form.describe()
        if shown:
            print("[admin] submitting:")
            for line in shown:
                print("[admin] %s" % _sanitise(line, 300))
        try:
            payload = self.plugin["xep_0004"].make_form(ftype="submit")
            for var, value in form.values().items():
                payload.add_field(var=var, value=value)
            iq = await self.plugin["xep_0050"].send_command(
                jid=self.boundjid.server, node=node, action="complete",
                sessionid=session, payload=payload)
        except Exception as exc:
            self._admin_reset()
            print("[admin] the server refused it: %s" % _sanitise(str(exc), 200))
            return
        self._admin_handle_stage(iq)

    async def _admin_cancel(self):
        """Tell the server to drop the session, then forget it locally."""
        node, session = self._admin_node, self._admin_session
        self._admin_reset()
        if not (node and session):
            return
        try:
            await self.plugin["xep_0050"].send_command(
                jid=self.boundjid.server, node=node, action="cancel",
                sessionid=session)
        except Exception:
            # A cancel that does not arrive costs the server one idle
            # session and costs us nothing; the local state is already gone.
            pass

    def _admin_reset(self):
        """Forget the form, the session and any armed capture.

        Called on every exit path, including the failures. A form left half
        open would keep `_admin_awaiting` set and swallow the next line the
        user typed, which is precisely the behaviour INV-06 exists to forbid.
        """
        self._admin_form = None
        self._admin_node = None
        self._admin_session = None
        self._admin_awaiting = False
        try:
            self._mask_next_input(False)
        except Exception:
            pass

    def take_admin_field(self):
        """Consume the locally-armed admin-form request, if any.

        Same rule and same reason as `take_secret_request` above: armed only
        by this user typing `/admin`, cleared unconditionally on read, so it
        survives exactly one dispatched line.

        A form is a sequence of questions, so unlike the SMP prompt it re-arms
        itself after each answer -- but only from `_admin_ask_next`, and only
        while a form this user started is still open.  Nothing the server or a
        peer sends reaches that path, which is the property that matters: the
        server describes the QUESTIONS, it cannot decide that the next thing
        typed is an answer.
        """
        armed, self._admin_awaiting = self._admin_awaiting, False
        return armed
