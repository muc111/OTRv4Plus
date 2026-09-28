# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A small, real XMPP c2s endpoint on loopback for clearnet registration tests.

Real TCP, real STARTTLS with a certificate signed by a throw-away CA (the
client validates it -- nothing here turns verification off), a real stream
restart after TLS, and XEP-0077 in-band registration in the shapes Prosody and
ejabberd use:

    ok            <register/> offered; form asks username + password; set -> result
    conflict      as ok, but the set is answered <conflict/>
    captcha       the form is a XEP-0004 data form carrying a XEP-0158 CAPTCHA
    not_allowed   the registration GET is answered <not-allowed/>
    no_register   no <register/> feature; SASL only
    close_after_tls   the server drops the connection after the TLS restart
    no_starttls   no <starttls/> offered at all

It records what it saw (`self.log`) so a test can assert on the order of
events and on whether a password ever reached it -- `password_received`
records only THAT one arrived, never its value.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading

NS_STREAM = "http://etherx.jabber.org/streams"


def make_ca_and_cert(hostname: str, directory: str | None = None):
    """(ca_path, cert_path, key_path) for `hostname`, via the openssl CLI."""
    d = directory or tempfile.mkdtemp()
    ca_key, ca_crt = os.path.join(d, "ca.key"), os.path.join(d, "ca.crt")
    key, csr, crt = (os.path.join(d, n) for n in ("srv.key", "srv.csr", "srv.crt"))
    ext = os.path.join(d, "ext.cnf")
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", ca_key, "-out", ca_crt, "-subj", "/CN=OTRv4Plus test CA")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
        "-out", csr, "-subj", "/CN=" + hostname)
    with open(ext, "w") as f:
        f.write("subjectAltName=DNS:%s\n" % hostname)
    run("openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
        "-CAcreateserial", "-out", crt, "-days", "2", "-extfile", ext)
    return ca_crt, crt, key


class XmppTestServer:
    def __init__(self, domain: str, cert: str, key: str, mode: str = "ok"):
        self.domain, self.mode = domain, mode
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.log: list[str] = []
        self.password_received = False
        self.registered_user = None
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    # -- plumbing -------------------------------------------------------------

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.log.append("tcp_accepted")
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _read_until(self, conn, pattern, buf):
        rx = re.compile(pattern, re.S)
        while True:
            m = rx.search(buf)
            if m:
                return m, buf[m.end():]
            data = conn.recv(8192)
            if not data:
                raise ConnectionError("client closed")
            buf += data.decode("utf-8", "replace")

    def _header(self):
        return ("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                "xmlns:stream='%s' from='%s' id='s1' version='1.0'>"
                % (NS_STREAM, self.domain))

    def _client(self, conn):
        try:
            self._session(conn)
        except (OSError, ConnectionError, ssl.SSLError) as exc:
            self.log.append("closed:%s" % type(exc).__name__)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _session(self, conn):
        buf = ""
        _, buf = self._read_until(conn, r"<stream:stream[^>]*>", buf)
        self.log.append("stream_open")
        if self.mode == "no_starttls":
            conn.sendall((self._header() + "<stream:features><mechanisms "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN"
                          "</mechanism></mechanisms><register xmlns='http://jabber.org/"
                          "features/iq-register'/></stream:features>").encode())
            self._read_until(conn, r"$^", buf)          # wait for the client to leave
            return
        conn.sendall((self._header() + "<stream:features><starttls xmlns="
                      "'urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
                      "</stream:features>").encode())
        _, buf = self._read_until(conn, r"<starttls[^>]*/>", buf)
        conn.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        tls = self.ctx.wrap_socket(conn, server_side=True)
        self.log.append("tls_ok")
        buf = ""
        _, buf = self._read_until(tls, r"<stream:stream[^>]*>", buf)
        self.log.append("stream_restarted")
        if self.mode == "close_after_tls":
            tls.close()
            self.log.append("server_closed")
            return
        feats = ("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                 "<mechanism>SCRAM-SHA-1</mechanism><mechanism>PLAIN</mechanism>"
                 "</mechanisms>")
        if self.mode != "no_register":
            feats = "<register xmlns='http://jabber.org/features/iq-register'/>" + feats
        tls.sendall((self._header() + "<stream:features>" + feats +
                     "</stream:features>").encode())
        while True:
            m, buf = self._read_until(
                tls, r"<iq\b[^>]*>.*?</iq>|<iq\b[^>]*/>|<auth\b[^>]*>.*?</auth>|"
                     r"<auth\b[^>]*/>|</stream:stream>", buf)
            stanza = m.group(0)
            if stanza.startswith("</stream"):
                self.log.append("client_closed_stream")
                return
            if stanza.startswith("<auth"):
                self.log.append("sasl_auth")
                tls.sendall(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            b"<not-authorized/></failure>")
                continue
            iid = re.search(r"\bid=['\"]([^'\"]+)", stanza)
            iid = iid.group(1) if iid else "x"
            typ = re.search(r"\btype=['\"]([a-z]+)", stanza)
            typ = typ.group(1) if typ else ""
            if "jabber:iq:register" not in stanza:
                tls.sendall(("<iq type='error' id='%s'><error type='cancel'>"
                             "<service-unavailable xmlns='urn:ietf:params:xml:ns:"
                             "xmpp-stanzas'/></error></iq>" % iid).encode())
                continue
            if typ == "get":
                self.log.append("register_get")
                tls.sendall(self._form(iid).encode())
            elif typ == "set":
                self.log.append("register_set")
                if "<password>" in stanza and "</password>" in stanza:
                    self.password_received = True
                u = re.search(r"<username>([^<]*)</username>", stanza)
                if self.mode == "conflict":
                    tls.sendall(("<iq type='error' id='%s'><error type='cancel'>"
                                 "<conflict xmlns='urn:ietf:params:xml:ns:"
                                 "xmpp-stanzas'/></error></iq>" % iid).encode())
                else:
                    self.registered_user = u.group(1) if u else None
                    tls.sendall(("<iq type='result' id='%s'/>" % iid).encode())

    def _form(self, iid):
        if self.mode == "not_allowed":
            return ("<iq type='error' id='%s'><error type='cancel'><not-allowed "
                    "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>" % iid)
        if self.mode == "captcha":
            return ("<iq type='result' id='%s'><query xmlns='jabber:iq:register'>"
                    "<instructions>Solve the CAPTCHA</instructions>"
                    "<x xmlns='jabber:x:data' type='form'>"
                    "<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:captcha"
                    "</value></field>"
                    "<field var='username' type='text-single'><required/></field>"
                    "<field var='password' type='text-private'><required/></field>"
                    "<field var='ocr' type='text-single' label='Enter the text'>"
                    "<required/></field></x></query></iq>" % iid)
        return ("<iq type='result' id='%s'><query xmlns='jabber:iq:register'>"
                "<instructions>Choose a username and password</instructions>"
                "<username/><password/></query></iq>" % iid)
