# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The hardened client against a real Prosody.

Everything else that tests the stream guard and the SCRAM hardening drives
slixmpp's handlers with a server written for the test. That proves the
checks refuse what they should. It cannot prove they pass what a real server
sends, which is the failure that would matter most: the guard misfiring, and
nobody able to sign in.

So this starts a real Prosody on a loopback port, with a throwaway config and
certificate, and runs the client the apps build (tests/real_server_client.py,
in a process of its own) through it: a sign-in, a wrong password, an in-band
registration that carries on into a sign-in, and a party on the path that
injects a DOCTYPE before TLS.

WHICH PROSODY. Whatever `prosody` and `prosodyctl` are on PATH, or the pair
named by OTRV4PLUS_PROSODY / OTRV4PLUS_PROSODYCTL. CI installs Ubuntu's
package (0.12.4); the same file was run by hand against 13.0.7 built from
source on 2026-11-15, with the same results.

Skips when no Prosody is installed, EXCEPT where
OTRV4PLUS_REQUIRE_REAL_SERVER=1 (CI): there a missing server is a failure,
because a test that can skip unnoticed is one that eventually does not run.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "tests", "real_server_client.py")

PROSODY = os.environ.get("OTRV4PLUS_PROSODY") or shutil.which("prosody")
PROSODYCTL = (os.environ.get("OTRV4PLUS_PROSODYCTL")
              or shutil.which("prosodyctl"))
OPENSSL = shutil.which("openssl")
REQUIRED = os.environ.get("OTRV4PLUS_REQUIRE_REAL_SERVER") == "1"

PASSWORD = "correct horse battery staple"


def _unavailable(why):
    if REQUIRED:
        pytest.fail("OTRV4PLUS_REQUIRE_REAL_SERVER=1 and %s. Install it "
                    "(`sudo apt-get install prosody`), or the hardened "
                    "client is not tested against a real server." % why)
    pytest.skip(why)


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _listening(port, within):
    deadline = time.time() + within
    while time.time() < deadline:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


class Server:
    def __init__(self, directory, port, config):
        self.directory, self.port, self.config = directory, port, config

    def ctl(self, *args):
        return subprocess.run([PROSODYCTL, "--config", self.config] + list(args),
                              capture_output=True, text=True, timeout=60)

    def add_account(self, user, password=PASSWORD):
        done = self.ctl("register", user, "localhost", password)
        assert done.returncode == 0, done.stdout + done.stderr

    def client(self, mode, user, password=PASSWORD):
        done = subprocess.run(
            [sys.executable, CLIENT, mode, str(self.port),
             "%s@localhost" % user, password],
            capture_output=True, text=True, timeout=120)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                return json.loads(line[len("RESULT "):])
        raise AssertionError("the client printed no result:\n%s\n%s"
                             % (done.stdout[-2000:], done.stderr[-2000:]))


@pytest.fixture(scope="module")
def server():
    if not PROSODY or not PROSODYCTL:
        _unavailable("no prosody on PATH")
    if not OPENSSL:
        _unavailable("no openssl on PATH (for the throwaway certificate)")
    with tempfile.TemporaryDirectory() as directory:
        os.makedirs(os.path.join(directory, "data"))
        key = os.path.join(directory, "key.pem")
        certificate = os.path.join(directory, "cert.pem")
        made = subprocess.run(
            [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "2", "-subj", "/CN=localhost", "-keyout", key,
             "-out", certificate], capture_output=True, text=True)
        assert made.returncode == 0, made.stderr
        port = _free_port()
        config = os.path.join(directory, "prosody.cfg.lua")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write('''-- Written by tests/test_real_prosody.py; thrown away after the run.
run_as_root = true
pidfile = "%(d)s/prosody.pid"
data_path = "%(d)s/data"
interfaces = { "127.0.0.1" }
c2s_ports = { %(port)d }
-- This repository's server modules, with the limits
-- prosody/install-server-limits.sh sets: the sign-in under test goes
-- through the same code a deployed server runs.
plugin_paths = { "%(modules)s" }
modules_enabled = { "roster", "saslauth", "tls", "register", "disco", "ping",
                    "adhoc", "otrv4plus_one_session", "otrv4plus_capacity",
                    "otrv4plus_moderation" }
modules_disabled = { "s2s" }
max_resources = 1
max_online_users = 1600
login_rate = 10
login_burst = 40
max_registrations_per_hour = 30
max_registered_users = 5000
allow_registration = true
authentication = "internal_hashed"
c2s_require_encryption = true
log = { info = "%(d)s/prosody.log", error = "%(d)s/prosody.err" }
ssl = { key = "%(d)s/key.pem", certificate = "%(d)s/cert.pem" }
VirtualHost "localhost"
''' % {"d": directory, "port": port,
       "modules": os.path.join(ROOT, "prosody")})
        process = subprocess.Popen(
            [PROSODY, "--config", config, "-F"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            if not _listening(port, within=30):
                process.terminate()
                output = process.communicate(timeout=10)[0]
                pytest.fail("Prosody did not start listening:\n%s"
                            % output[-3000:])
            yield Server(directory, port, config)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


def test_which_prosody_this_ran_against(server, capsys):
    """Recorded in the test output (`-rs` or `-s`), so a green run says
    which server it was green against."""
    about = server.ctl("about").stdout
    found = re.search(r"^Prosody (\d\S*)", about, re.MULTILINE)
    with capsys.disabled():
        print("\n[real server] Prosody %s (%s)"
              % (found.group(1) if found else "?", PROSODY))
    assert found, "prosodyctl about named no version:\n" + about[:500]


def test_a_sign_in_passes_every_guard(server):
    server.add_account("alice")
    result = server.client("signin", "alice")
    assert result["outcome"] == "signed_in", result
    assert result["mechanism"].startswith("SCRAM-"), result["mechanism"]
    assert result["refusals"] == []
    # The checks were in the path and held: one stream before TLS, one
    # after, one after signing in; and the server's signature verified.
    assert "streams guarded 3" in result["guards"], result["guards"]
    assert "server proofs verified 1" in result["guards"]
    assert "3 of 3 fixes active" in result["guards"]
    assert result["events"].index("tls_success") < result["events"].index(
        "auth_success") < result["events"].index("session_start")


def test_a_wrong_password_is_a_wrong_password(server):
    """An ordinary failure must stay one: `auth_failed`, not a server that
    did not prove itself."""
    server.add_account("carol")
    result = server.client("signin", "carol", "not the password")
    assert result["outcome"] == "auth_failed", result
    assert result["refusals"] == []
    assert "server proofs verified 0" in result["guards"]


def test_registering_carries_straight_on_into_a_proven_sign_in(server):
    result = server.client("register", "bob")
    assert result["outcome"] == "signed_in", result
    assert "registered" in result["events"]
    assert result["events"].index("registered") < result["events"].index(
        "auth_success")
    assert result["refusals"] == []
    assert "server proofs verified 1" in result["guards"]
    # And the account it made is a real one.
    again = server.client("signin", "bob")
    assert again["outcome"] == "signed_in", again


def test_a_party_on_the_path_before_tls_is_refused(server):
    server.add_account("dave")
    result = server.client("injected", "dave")
    assert result["outcome"] == "refused:declaration", result
    assert "tls_success" not in result["events"]
    assert "auth_success" not in result["events"]
    (refusal,) = result["refusals"]
    assert refusal["check"] == "xml" and refusal["reason"] == "declaration"
    facts = refusal["facts"]
    assert facts["stream"] == 1 and facts["tls"] == "none"
    assert facts["stream_bytes"] == 0 and facts["stream_stanzas"] == 0
    assert "before TLS" in result["report_section"]
    # The same account, with nobody on the path, is fine.
    assert server.client("signin", "dave")["outcome"] == "signed_in"


def test_the_projects_own_server_modules_loaded_without_error(server):
    """The three modules in prosody/ are in this server's config. A module
    that failed to load says so in the error log; a sign-in above would
    still have passed without it, so this looks."""
    with open(os.path.join(server.directory, "prosody.log"),
              encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    problems = [line for line in log.splitlines()
                if "otrv4plus" in line and ("error" in line.lower()
                                            or "traceback" in line.lower())]
    assert problems == [], "\n".join(problems[:10])
    listed = server.ctl("shell", "module:list()").stdout
    if "otrv4plus" in listed:        # `prosodyctl shell` needs the admin
        for name in ("otrv4plus_capacity", "otrv4plus_one_session",
                     "otrv4plus_moderation"):
            assert name in listed, name




# ── prosody/install-server-limits.sh, for real ──────────────────────────────

INSTALLER = os.path.join(ROOT, "prosody", "install-server-limits.sh")


def _installer(config, modules, *args, **env):
    """The install script against `config`, with the real prosodyctl and
    the real socket lister. RESTART=0: this test starts and stops Prosody
    itself, there is no systemd unit to restart."""
    environment = dict(os.environ, PROSODY_CFG=config, PROSODY_MODULES=modules,
                       PROSODYCTL=PROSODYCTL, RESTART="0")
    environment.update(env)
    return subprocess.run(["bash", INSTALLER] + list(args), env=environment,
                          capture_output=True, text=True, timeout=180)


class Running:
    """Prosody on a config, for the length of a `with`."""

    def __init__(self, directory, config, port):
        self.server = Server(directory, port, config)
        self.process = None

    def __enter__(self):
        self.process = subprocess.Popen(
            [PROSODY, "--config", self.server.config, "-F"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not _listening(self.server.port, within=30):
            self.process.terminate()
            pytest.fail("Prosody did not start listening:\n%s"
                        % self.process.communicate(timeout=10)[0][-3000:])
        return self.server

    def __exit__(self, *_exc):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        return False


def test_the_install_script_closes_a_real_server_which_still_signs_in():
    """The whole of it, on a real Prosody: a server set up by hand listens
    on every address and federates; `--check` says so, from the real socket
    list; the script's edit passes the real `prosodyctl check config`; the
    server then listens on this machine only, and the hardened client still
    signs in to it, through the three modules the script installed."""
    if not PROSODY or not PROSODYCTL:
        _unavailable("no prosody on PATH")
    if not OPENSSL:
        _unavailable("no openssl on PATH (for the throwaway certificate)")
    if shutil.which("ss") is None:
        _unavailable("no `ss` on PATH (iproute2), to see what is listening")
    with tempfile.TemporaryDirectory() as directory:
        os.makedirs(os.path.join(directory, "data"))
        modules = os.path.join(directory, "modules")
        made = subprocess.run(
            [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "2", "-subj", "/CN=localhost",
             "-keyout", os.path.join(directory, "key.pem"),
             "-out", os.path.join(directory, "cert.pem")],
            capture_output=True, text=True)
        assert made.returncode == 0, made.stderr
        port, federation_port = _free_port(), _free_port()
        config = os.path.join(directory, "prosody.cfg.lua")
        # As someone following a setup guide leaves it: no `interfaces`, so
        # every address; federation on; none of our modules or limits.
        original = '''run_as_root = true
pidfile = "%(d)s/prosody.pid"
data_path = "%(d)s/data"
c2s_ports = { %(port)d }
s2s_ports = { %(s2s)d }
plugin_paths = { "%(modules)s" }
modules_enabled = {
\t"roster";
\t"saslauth";
\t"tls";
\t"register";
\t"disco";
\t"ping";
\t"adhoc";
}
allow_registration = true
authentication = "internal_hashed"
c2s_require_encryption = true
log = { info = "%(d)s/prosody.log", error = "%(d)s/prosody.err" }
ssl = { key = "%(d)s/key.pem", certificate = "%(d)s/cert.pem" }
VirtualHost "localhost"
''' % {"d": directory, "port": port, "s2s": federation_port,
       "modules": modules}
        with open(config, "w", encoding="utf-8") as handle:
            handle.write(original)

        # With nothing of this test's started yet, the script must see
        # nothing listening. If it does, another Prosody (or something on
        # one of its ports) runs on this machine, and "before" and "after"
        # below would be about that one.
        baseline = _installer(config, modules, "--check")
        if "listening beyond this machine: YES" in baseline.stdout:
            _unavailable("something on this machine already listens on one "
                         "of Prosody's ports (a system Prosody? stop it: "
                         "`sudo systemctl disable --now prosody`)")

        # 1. Before: found from the real socket list, and nothing changed.
        with Running(directory, config, port):
            looked = _installer(config, modules, "--check", HIDDEN_SERVICE="1")
        assert looked.returncode == 2, looked.stdout + looked.stderr
        before = looked.stdout[:looked.stdout.index("CHECK ONLY")]
        assert "listening beyond this machine: YES" in before, looked.stdout
        assert ":%d" % port in before
        assert "federation (s2s): ON" in before
        with open(config, encoding="utf-8") as handle:
            assert handle.read() == original
        assert not os.path.exists(modules)

        # 2. The script, with the real `prosodyctl check config` judging it.
        applied = _installer(config, modules, HIDDEN_SERVICE="1")
        assert applied.returncode == 0, applied.stdout + applied.stderr
        assert "checking the configuration" in applied.stdout
        with open(config, encoding="utf-8") as handle:
            written = handle.read()
        assert 'interfaces = { "127.0.0.1" }' in written
        assert '"otrv4plus_capacity";' in written

        # 3. After: this machine only, federation off, nothing left to do,
        #    and a sign-in through the guards and the installed modules.
        with Running(directory, config, port) as server:
            again = _installer(config, modules, "--check", HIDDEN_SERVICE="1")
            assert again.returncode == 0, again.stdout + again.stderr
            assert "listening beyond this machine: no" in again.stdout
            assert "federation (s2s): off" in again.stdout
            assert "nothing to change" in again.stdout
            server.add_account("erin")
            result = server.client("signin", "erin")
            assert result["outcome"] == "signed_in", result
            assert "server proofs verified 1" in result["guards"]
            with open(os.path.join(directory, "prosody.log"),
                      encoding="utf-8", errors="replace") as handle:
                problems = [line for line in handle.read().splitlines()
                            if "otrv4plus" in line and "error" in line.lower()]
            assert problems == [], "\n".join(problems[:10])

        # 4. And a second real run does nothing at all.
        second = _installer(config, modules, HIDDEN_SERVICE="1")
        assert second.returncode == 0
        assert "nothing to change" in second.stdout
        assert len([name for name in os.listdir(directory)
                    if ".bak-" in name]) == 1


# ── what the install script says stops a sign-in ────────────────────────────
#
# Each setting goes into a server's configuration. The script is asked what
# it makes of it; then a real sign-in is tried on that server. STOP must
# mean the client could not sign in, and no STOP that it could: a script
# that cries wolf is ignored, and one that misses a lockout is worse.
#
# Two answers depend on the Prosody version, so the set of outcomes allowed
# is per setting and the equality is what is asserted. Measured 2026-11-15:
#
#   setting                              0.12.4               13.0.7
#   default_iteration_count = 1000       refused (count)      signs in (4096)
#   default_iteration_count = 3000000    refused (count)      refused (count)
#   "SCRAM-<hash>" disabled              no mechanism         no mechanism
#   "SCRAM-<hash>-PLUS" disabled         signs in             auth_failed
SIGN_IN_SETTINGS = [
    ("", {"signed_in"}),
    ("default_iteration_count = 4096", {"signed_in"}),
    ("default_iteration_count = 1000",
     {"signed_in", "refused:iteration_count"}),
    ("default_iteration_count = 3000000", {"refused:iteration_count"}),
    ('disable_sasl_mechanisms = { "PLAIN" }', {"signed_in"}),
    ('disable_sasl_mechanisms = { "SCRAM-SHA-1" }', {"no_auth"}),
    ('disable_sasl_mechanisms = { "SCRAM-SHA-1-PLUS" }',
     {"signed_in", "auth_failed"}),
    ('password_hash = "SHA-256"', {"signed_in"}),
    ('password_hash = "SHA-256"\n'
     'disable_sasl_mechanisms = { "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS" }',
     {"signed_in"}),
    ('password_hash = "SHA-256"\n'
     'disable_sasl_mechanisms = { "SCRAM-SHA-256" }', {"no_auth"}),
]


@pytest.mark.parametrize(
    "setting,outcomes", SIGN_IN_SETTINGS,
    ids=[setting.replace("\n", "; ") or "defaults"
         for setting, _ in SIGN_IN_SETTINGS])
def test_what_the_script_calls_a_stop_is_a_sign_in_that_fails(setting,
                                                              outcomes):
    if not PROSODY or not PROSODYCTL:
        _unavailable("no prosody on PATH")
    if not OPENSSL:
        _unavailable("no openssl on PATH (for the throwaway certificate)")
    with tempfile.TemporaryDirectory() as directory:
        os.makedirs(os.path.join(directory, "data"))
        made = subprocess.run(
            [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "2", "-subj", "/CN=localhost",
             "-keyout", os.path.join(directory, "key.pem"),
             "-out", os.path.join(directory, "cert.pem")],
            capture_output=True, text=True)
        assert made.returncode == 0, made.stderr
        port = _free_port()
        config = os.path.join(directory, "prosody.cfg.lua")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write('''run_as_root = true
pidfile = "%(d)s/prosody.pid"
data_path = "%(d)s/data"
interfaces = { "127.0.0.1" }
c2s_ports = { %(port)d }
modules_enabled = {
\t"roster";
\t"saslauth";
\t"tls";
\t"disco";
\t"ping";
}
modules_disabled = { "s2s" }
authentication = "internal_hashed"
c2s_require_encryption = true
%(setting)s
log = { info = "%(d)s/prosody.log", error = "%(d)s/prosody.err" }
ssl = { key = "%(d)s/key.pem", certificate = "%(d)s/cert.pem" }
VirtualHost "localhost"
''' % {"d": directory, "port": port, "setting": setting})

        said = _installer(config, os.path.join(directory, "modules"),
                          "--check").stdout
        none = "settings that stop the apps signing in: none" in said
        stop = "settings that stop the apps signing in: YES" in said
        assert none != stop, said

        with Running(directory, config, port) as server:
            # Created under this configuration: the iteration count is
            # stored with the password.
            server.add_account("zed")
            result = server.client("signin", "zed")

        outcome = result["outcome"]
        assert outcome in outcomes, result
        assert stop == (outcome != "signed_in"), (
            "the script said %s and the sign-in ended %r\n%s"
            % ("STOP" if stop else "nothing", outcome, said))
        if outcome == "refused:iteration_count":
            # The one way an honest server produces "the server did not
            # prove it knows this account": this is what the screen says.
            (refusal,) = result["refusals"]
            assert refusal["facts"]["proof_sent"] == "no"
            assert "rounds of password hashing" in result["detail"]
            assert "default_iteration_count" in result["detail"]
            assert "The password itself was not sent." in result["detail"]
            assert "default_iteration_count" in result["report_section"]
        elif outcome != "signed_in":
            # Any other lockout is not the server failing to prove itself.
            assert result["refusals"] == []


def test_ci_installs_a_server_and_may_not_skip_these():
    """In CI a Prosody is installed before the suite and
    OTRV4PLUS_REQUIRE_REAL_SERVER=1 is set for it, so everything in this
    file runs there or fails there. Read from the workflow, because a test
    that skips is green."""
    with open(os.path.join(ROOT, ".github", "workflows", "python.yml"),
              encoding="utf-8") as handle:
        workflow = handle.read()
    install = workflow.index("- name: A real Prosody for the sign-in tests")
    suite = workflow.index("- name: pytest")
    after = workflow.index("- name: Failures as annotations")
    assert install < suite < after
    assert ("apt-get install -y --no-install-recommends prosody"
            in workflow[install:suite])
    # The package starts a system Prosody on every address; the tests bring
    # their own, and the install script would see the system one's sockets.
    assert "systemctl disable --now prosody" in workflow[install:suite]
    assert 'OTRV4PLUS_REQUIRE_REAL_SERVER: "1"' in workflow[suite:after]
