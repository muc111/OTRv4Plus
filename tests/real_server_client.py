# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One sign-in or registration against a real XMPP server, through the same
client the apps build. Run as a script by tests/test_real_prosody.py; prints
one line of JSON.

A process of its own on purpose: the hardening patches slixmpp's classes and
slixmpp picks its own event loop, and neither should be shared with the test
run that asks.

    python real_server_client.py signin   <port> <jid> <password>
    python real_server_client.py register <port> <jid> <password>
    python real_server_client.py injected <port> <jid> <password>

`injected` puts a party on the path: a relay in front of the server that adds
a DOCTYPE to the first thing the server says, before TLS exists. That is the
attacker a clearnet connection has before STARTTLS completes.

The client is the one `android_bridge.transport` builds (stream guard, SCRAM
hardening), with the policy it applies where the address authenticates the
server (I2P, Tor): certificate checks off, SCRAM only.
"""
import asyncio
import json
import os
import ssl
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "client"))

TIMEOUT = 40.0


def build(jid: str, password: str, register: bool):
    from android_bridge import transport
    from android_bridge.transport_registration import _enable_registration

    client = transport._default_client_factory()(jid, password)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    client.ssl_context = context
    transport._restrict_to_scram(client)
    if register:
        _enable_registration(client)
    return client


INJECTED = b'<!DOCTYPE stream [<!ENTITY a "aaaaaaaaaa">]>'


async def relay_that_injects(real_port: int):
    """A TCP relay to the real server that prepends `INJECTED` to the first
    bytes the server sends. Returns (server, port)."""

    async def handle(reader, writer):
        up_reader, up_writer = await asyncio.open_connection(
            "127.0.0.1", real_port)
        state = {"first": True}

        async def pipe(source, sink, inject):
            try:
                while True:
                    data = await source.read(65536)
                    if not data:
                        break
                    if inject and state["first"]:
                        state["first"] = False
                        data = INJECTED + data
                    sink.write(data)
                    await sink.drain()
            except Exception:
                pass
            finally:
                try:
                    sink.close()
                except Exception:
                    pass

        await asyncio.gather(pipe(reader, up_writer, False),
                             pipe(up_reader, writer, True))

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def run(mode: str, port: int, jid: str, password: str) -> dict:
    from android_bridge import server_proof
    from android_bridge.xmlguard import REFUSED_EVENT

    relay = None
    if mode == "injected":
        relay, port = await relay_that_injects(port)
    client = build(jid, password, register=(mode == "register"))
    done = asyncio.get_running_loop().create_future()
    seen = []

    def finish(outcome):
        if not done.done():
            done.set_result(outcome)

    def note(name):
        def handler(_event=None):
            seen.append(name)
        return handler

    for name in ("connected", "tls_success", "auth_success", "session_start",
                 "failed_auth", "no_auth", "disconnected"):
        client.add_event_handler(name, note(name))
    client.add_event_handler("session_start", lambda _e: finish("signed_in"))
    client.add_event_handler("failed_auth", lambda _e: finish("auth_failed"))
    client.add_event_handler("no_auth", lambda _e: finish("no_auth"))
    client.add_event_handler(
        REFUSED_EVENT, lambda reason: finish("refused:%s" % reason))
    client.add_event_handler(
        "connection_failed", lambda _e: finish("connection_failed"))

    if mode == "register":
        async def on_register(_form):
            seen.append("register_offered")
            iq = client.Iq()
            iq["type"] = "set"
            iq["register"]["username"] = jid.split("@", 1)[0]
            iq["register"]["password"] = password
            try:
                await iq.send()
                seen.append("registered")
            except Exception as exc:
                finish("registration_rejected:%s" % type(exc).__name__)
        client.add_event_handler("register", on_register)

    client.connect(host="127.0.0.1", port=port)
    try:
        outcome = await asyncio.wait_for(done, TIMEOUT)
    except asyncio.TimeoutError:
        outcome = "timeout"
    mechanism = None
    try:
        mechanism = client.plugin["feature_mechanisms"].mech.name
    except Exception:
        pass
    detail = ""
    if outcome.startswith("refused:"):
        # What the apps would put on the screen for this refusal.
        from android_bridge.transport_base import server_not_proven_detail
        detail = server_not_proven_detail(
            None, "registration" if mode == "register" else "sign-in")
    result = {
        "outcome": outcome,
        "events": seen,
        "mechanism": mechanism,
        "detail": detail,
        "guards": server_proof.guards_line(),
        "refusals": [{"check": r["check"], "reason": r["reason"],
                      "facts": r["facts"]} for r in server_proof.recent()],
        "report_section": server_proof.render(),
    }
    try:
        client.abort()
    except Exception:
        pass
    if relay is not None:
        relay.close()
    await asyncio.sleep(0.1)
    return result


def main(argv) -> int:
    mode, port, jid, password = argv[1], int(argv[2]), argv[3], argv[4]
    result = asyncio.run(run(mode, port, jid, password))
    print("RESULT " + json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
