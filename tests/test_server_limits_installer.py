# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""prosody/install-server-limits.sh on a throwaway config. Owner
(2026-10-20), after the stress runs: "remove the account cap and add 1600
users online at once", then a 5,000-account backstop; the generational collector is what let the 1,600
run recover from a join burst (docs/STRESS_TEST.md)."""
import os
import shutil
import pathlib
import subprocess
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "prosody", "install-server-limits.sh")

CFG = """admins = { "alice@x.i2p" }
modules_enabled = {
\t"roster";
}
max_online_users = 2000
max_registered_users = 2000
VirtualHost "x.i2p"
"""


@pytest.fixture
def tmp_path():
    # pytest's own tmp_path asks for the user name, which conftest stubs.
    with tempfile.TemporaryDirectory() as d:
        yield pathlib.Path(d)


def _run(tmp_path, **env):
    cfg = tmp_path / "prosody.cfg.lua"
    if not cfg.exists():
        cfg.write_text(CFG)
    e = dict(os.environ, RESTART="0", PROSODYCTL="true", PROSODY_CFG=str(cfg),
             PROSODY_MODULES=str(tmp_path / "mods"), **env)
    subprocess.run(["bash", SCRIPT], env=e, check=True, capture_output=True)
    return cfg.read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_defaults_online_1600_accounts_5000_generational_gc(tmp_path):
    out = _run(tmp_path)
    assert "max_online_users = 1600\n" in out
    assert "max_registered_users = 5000\n" in out
    assert 'gc = { mode = "generational" }\n' in out
    # Global options stay before the first VirtualHost.
    assert out.index("gc =") < out.index("VirtualHost")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_safe_to_run_again_and_overridable(tmp_path):
    _run(tmp_path)
    out = _run(tmp_path, MAX_ONLINE_USERS="1800")
    assert out.count("gc =") == 1 and out.count("max_online_users") == 1
    assert "max_online_users = 1800\n" in out


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_result_is_valid_lua(tmp_path):
    lupa = pytest.importorskip("lupa")
    out = _run(tmp_path)
    lua = lupa.LuaRuntime()
    lua.execute("function VirtualHost() end\n" + out.replace('VirtualHost "x.i2p"',
                                                              'VirtualHost("x.i2p")'))
    assert lua.eval("gc.mode") == "generational"
    assert lua.eval("max_online_users") == 1600


def _script(tmp_path, *args, config=None, **env):
    """Run the script; return the finished process (any exit status)."""
    cfg = tmp_path / "prosody.cfg.lua"
    if config is not None:
        cfg.write_text(config)
    elif not cfg.exists():
        cfg.write_text(CFG)
    # SS="true": a socket lister that lists nothing. Whatever this machine
    # happens to be listening on (a developer's own Prosody, anything on
    # port 5000) is not this test's business.
    e = dict(os.environ, RESTART="0", PROSODYCTL="true", PROSODY_CFG=str(cfg),
             PROSODY_MODULES=str(tmp_path / "mods"), SS="true")
    e.update(env)
    return subprocess.run(["bash", SCRIPT] + list(args), env=e,
                          capture_output=True, text=True)


# ── red team 2026-11: a hidden server must not be findable ──────────────────

def _run_out(tmp_path, **env):
    cfg = tmp_path / "prosody.cfg.lua"
    if not cfg.exists():
        cfg.write_text(CFG)
    e = dict(os.environ, RESTART="0", PROSODYCTL="true", PROSODY_CFG=str(cfg),
             PROSODY_MODULES=str(tmp_path / "mods"), **env)
    done = subprocess.run(["bash", SCRIPT], env=e, check=True,
                          capture_output=True, text=True)
    return cfg.read_text(), done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_by_default_nothing_about_listening_changes_and_it_says_so(tmp_path):
    out, said = _run_out(tmp_path)
    assert "interfaces" not in out and "modules_disabled" not in out
    assert "federation (s2s) is on" in said
    assert "HIDDEN_SERVICE=1" in said


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_hidden_service_binds_to_loopback_and_turns_federation_off(tmp_path):
    out, said = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert 'interfaces = { "127.0.0.1" }\n' in out
    assert 'modules_disabled = { "s2s"; }\n' in out
    assert "hide_os_type = true\n" in out
    for key in ("interfaces =", "modules_disabled =", "hide_os_type ="):
        assert out.index(key) < out.index("VirtualHost"), key
    assert "federation (s2s) is on" not in said
    again, _ = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert again == out


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("existing,entries", [
    ('modules_disabled = {\n\t"offline";\n}\n', ('"s2s"', '"offline"')),
    ('modules_disabled = { "offline" }\n', ('"s2s"', '"offline"')),
    ('modules_disabled = { }\n', ('"s2s"',)),
    ('modules_disabled = {\n\t"s2s";\n}\n', ('"s2s"',)),
])
def test_an_existing_disabled_list_keeps_what_it_had(tmp_path, existing,
                                                     entries):
    (tmp_path / "prosody.cfg.lua").write_text(
        CFG.replace("VirtualHost", existing + "VirtualHost"))
    out, _ = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert out.count("modules_disabled") == 1
    block = out[out.index("modules_disabled"):]
    block = block[:block.index("}") + 1]
    for entry in entries:
        assert block.count(entry) == 1, (entry, block)
    lua = shutil.which("lua5.4") or shutil.which("lua") or shutil.which("luajit")
    if lua:
        check = "VirtualHost = function() end\n" + out
        subprocess.run([lua, "-e", check], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_a_narrower_interface_option_is_not_mistaken_for_the_global_one(
        tmp_path):
    """`c2s_interfaces` is left as the operator wrote it and the global
    line is still added. Since 2026-11-15 the run also FAILS (exit 3): that
    line keeps a server asked to be hidden reachable, and saying "done"
    would be the wrong answer. See the exit-code tests below."""
    (tmp_path / "prosody.cfg.lua").write_text(
        CFG.replace("VirtualHost", 'c2s_interfaces = { "*" }\nVirtualHost'))
    done = _script(tmp_path, HIDDEN_SERVICE="1")
    out = (tmp_path / "prosody.cfg.lua").read_text()
    assert done.returncode == 3
    assert 'c2s_interfaces = { "*" }\n' in out
    assert '\ninterfaces = { "127.0.0.1" }\n' in out


def test_the_session_module_logs_no_names():
    with open(os.path.join(ROOT, "prosody",
                           "mod_otrv4plus_one_session.lua")) as fh:
        source = fh.read()
    for line in source.splitlines():
        if "module:log(" in line:
            assert "%s" not in line, line


# ── 2026-11-15: --check, a second run that does nothing, and exit codes ─────

needs_bash = pytest.mark.skipif(shutil.which("bash") is None,
                                reason="needs bash")


def _backups(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir() if ".bak-" in p.name)


def _fake_ss(tmp_path, lines):
    """A stand-in for `ss -H -ltnp` that prints `lines`."""
    script = tmp_path / "fake_ss"
    script.write_text("#!/bin/sh\ncat <<'END'\n%s\nEND\n" % "\n".join(lines))
    script.chmod(0o755)
    return str(script)


SS_OPEN = [
    'LISTEN 0 128 0.0.0.0:5222 0.0.0.0:* users:(("lua5.4",pid=811,fd=9))',
    'LISTEN 0 128 [::]:5269 [::]:* users:(("lua5.4",pid=811,fd=11))',
    'LISTEN 0 128 127.0.0.1:5582 0.0.0.0:* users:(("lua5.4",pid=811,fd=12))',
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=400,fd=3))',
    'LISTEN 0 128 127.0.0.1:7070 0.0.0.0:* users:(("i2pd",pid=500,fd=20))',
]
SS_CLOSED = [
    'LISTEN 0 128 127.0.0.1:5222 0.0.0.0:* users:(("lua5.4",pid=811,fd=9))',
    'LISTEN 0 128 [::1]:5222 [::]:* users:(("lua5.4",pid=811,fd=10))',
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=400,fd=3))',
]


@needs_bash
def test_check_changes_nothing_and_says_what_it_would(tmp_path):
    done = _script(tmp_path, "--check")
    assert done.returncode == 2, done.stdout + done.stderr
    assert (tmp_path / "prosody.cfg.lua").read_text() == CFG
    assert _backups(tmp_path) == []
    assert not (tmp_path / "mods").exists()
    said = done.stdout
    assert "CHECK ONLY: nothing is changed" in said
    for module in ("mod_otrv4plus_one_session.lua",
                   "mod_otrv4plus_capacity.lua",
                   "mod_otrv4plus_moderation.lua"):
        assert "%s: would be installed" % module in said
    # The diff: what would be added, and the two limits it would change.
    assert '+max_online_users = 1600' in said
    assert '-max_online_users = 2000' in said
    assert '+\t"otrv4plus_capacity";' in said
    assert "Run it without --check to apply them" in said


@needs_bash
def test_after_applying_check_finds_nothing_to_change(tmp_path):
    assert _script(tmp_path).returncode == 0
    done = _script(tmp_path, "--check")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "nothing to change" in done.stdout
    assert "up to date" in done.stdout
    assert "would change" not in done.stdout


@needs_bash
def test_a_second_run_backs_up_nothing_and_restarts_nothing(tmp_path):
    """Idempotent in what it DOES, not only in what it leaves: the first
    version rewrote the config, made another backup and restarted Prosody
    (signing everyone out) on every run."""
    first = _script(tmp_path)
    assert first.returncode == 0
    assert len(_backups(tmp_path)) == 1
    after_first = (tmp_path / "prosody.cfg.lua").read_text()
    stamps = {p.name: p.stat().st_mtime_ns for p in (tmp_path / "mods").iterdir()}

    second = _script(tmp_path)
    assert second.returncode == 0
    assert "nothing to change" in second.stdout
    assert "No backup was made and Prosody was not restarted" in second.stdout
    assert len(_backups(tmp_path)) == 1, "a second run made another backup"
    assert (tmp_path / "prosody.cfg.lua").read_text() == after_first
    assert stamps == {p.name: p.stat().st_mtime_ns
                      for p in (tmp_path / "mods").iterdir()}
    assert "installing the modules" not in second.stdout


@needs_bash
def test_a_changed_module_alone_is_a_change(tmp_path):
    assert _script(tmp_path).returncode == 0
    (tmp_path / "mods" / "mod_otrv4plus_capacity.lua").write_text("-- old\n")
    done = _script(tmp_path, "--check")
    assert done.returncode == 2
    assert "mod_otrv4plus_capacity.lua: would be updated" in done.stdout
    assert "already as this script would leave it" in done.stdout
    applied = _script(tmp_path)
    assert applied.returncode == 0
    with open(os.path.join(ROOT, "prosody", "mod_otrv4plus_capacity.lua")) as fh:
        assert (tmp_path / "mods" / "mod_otrv4plus_capacity.lua").read_text() == fh.read()
    assert len(_backups(tmp_path)) == 1, "the config did not change: no new backup"


@needs_bash
def test_what_was_true_before_is_said_before_anything_is_changed(tmp_path):
    """On a server meant to be hidden, an open listener is how it was found.
    The run that closes it must say it was open, first."""
    done = _script(tmp_path, "--check", SS=_fake_ss(tmp_path, SS_OPEN),
                   HIDDEN_SERVICE="1")
    said = done.stdout
    before = said.index("what is true now, before anything is changed")
    assert before < said.index("CHECK ONLY")
    block = said[before:said.index("CHECK ONLY")]
    assert "listening beyond this machine: YES" in block
    assert "0.0.0.0:5222" in block and "[::]:5269" in block
    # Loopback sockets and other programs' sockets are not Prosody's exposure.
    assert "127.0.0.1:5582" not in block
    assert ":22" not in block and "7070" not in block
    assert "federation (s2s): ON" in block
    assert "settings that stop the apps signing in: none" in block
    # It would fix both, so this is "changes to make", not a failure.
    assert done.returncode == 2
    assert '+interfaces = { "127.0.0.1" }' in said


@needs_bash
def test_a_closed_server_is_reported_closed(tmp_path):
    _script(tmp_path, HIDDEN_SERVICE="1")
    done = _script(tmp_path, "--check", SS=_fake_ss(tmp_path, SS_CLOSED),
                   HIDDEN_SERVICE="1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "listening beyond this machine: no" in done.stdout
    assert "federation (s2s): off" in done.stdout


@needs_bash
def test_hidden_and_still_listening_is_exit_3_not_a_note(tmp_path):
    """Everything this script sets is set, and Prosody is still reachable:
    with HIDDEN_SERVICE=1 that is a failure with its own status."""
    _script(tmp_path, HIDDEN_SERVICE="1")
    done = _script(tmp_path, "--check", SS=_fake_ss(tmp_path, SS_OPEN),
                   HIDDEN_SERVICE="1")
    assert done.returncode == 3, done.stdout + done.stderr
    assert "FAILED (3): HIDDEN_SERVICE=1" in done.stderr
    assert "0.0.0.0:5222" in done.stderr
    # Without HIDDEN_SERVICE the same state is the operator's choice.
    plain = _script(tmp_path, "--check", SS=_fake_ss(tmp_path, SS_OPEN))
    assert plain.returncode == 0
    assert "listening beyond this machine: YES" in plain.stdout


@needs_bash
def test_an_override_that_keeps_it_reachable_is_named_by_line(tmp_path):
    config = CFG.replace("VirtualHost",
                         'c2s_interfaces = { "*" }\n'
                         'https_interfaces = { "127.0.0.1" }\nVirtualHost')
    # Looking first: the line number is the one in the file as it stands.
    looked = _script(tmp_path, "--check", config=config, HIDDEN_SERVICE="1")
    assert looked.returncode == 2
    assert "It would still not hide the server" in looked.stdout
    assert 'line 7: c2s_interfaces = { "*" }' in looked.stdout

    done = _script(tmp_path, HIDDEN_SERVICE="1")
    assert done.returncode == 3
    assert "override the global interfaces" in done.stderr
    # After the run the file has three more lines above it.
    assert 'line 10: c2s_interfaces = { "*" }' in done.stderr
    written = (tmp_path / "prosody.cfg.lua").read_text().splitlines()
    assert written[9] == 'c2s_interfaces = { "*" }'
    # A narrower option that names only this machine is not a problem.
    assert "https_interfaces" not in done.stderr
    # The rest was still applied: federation is closed whatever else is not.
    out = (tmp_path / "prosody.cfg.lua").read_text()
    assert 'modules_disabled = { "s2s"; }' in out


@needs_bash
@pytest.mark.parametrize("line,refused", [
    ("default_iteration_count = 1000", True),
    ("default_iteration_count = 4095", True),
    ("default_iteration_count = 3000000", True),
    ("default_iteration_count = 4096", False),
    ("default_iteration_count = 100000", False),
    ("default_iteration_count = 2000000", False),
    ("-- default_iteration_count = 1", False),
    ('disable_sasl_mechanisms = { "DIGEST-MD5", "SCRAM-SHA-1" }', True),
    ('disable_sasl_mechanisms = { "DIGEST-MD5" }', False),
    ('disable_sasl_mechanisms = {\n\t"PLAIN";\n\t"SCRAM-SHA-1-PLUS";\n}', True),
    # Prosody offers one SCRAM family, the one its passwords are stored in.
    # Disabling the other family removes nothing the apps use.
    ('password_hash = "SHA-256"\n'
     'disable_sasl_mechanisms = { "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS" }', False),
    ('password_hash = "SHA-256"\n'
     'disable_sasl_mechanisms = { "SCRAM-SHA-256" }', True),
    ("default_iteration_count = 99999999999999999999999", True),
])
def test_a_setting_the_apps_refuse_is_exit_4_with_the_line_to_change(
        tmp_path, line, refused):
    """The apps end a sign-in whose SCRAM iteration count is outside
    4096..2,000,000 and sign in with SCRAM only over I2P and Tor
    (android_bridge/sasl_hardening.py). A server set otherwise locks
    everyone out; the script says so first and fails.

    (prosodyctl here is `true`, so the Prosody version is unknown and the
    two rules that depend on it count as stopping the sign-in. The versions
    are below, and tests/test_real_prosody.py holds every rule against a
    real server.)"""
    config = CFG.replace("VirtualHost", line + "\nVirtualHost")
    done = _script(tmp_path, config=config)
    said = done.stdout + done.stderr
    stops = "settings that stop the apps signing in: "
    if refused:
        assert done.returncode == 4, said
        assert "FAILED (4)" in done.stderr
        assert stops + "YES" in done.stdout
        assert done.stdout.index(stops + "YES") < done.stdout.index("backup:")
        # The limits were still installed: this is reported, not a blocker.
        assert "max_online_users = 1600" in (tmp_path / "prosody.cfg.lua").read_text()
    else:
        assert done.returncode == 0, said
        assert stops + "none" in done.stdout


@needs_bash
def test_the_bounds_are_the_apps_bounds():
    import sys
    sys.path.insert(0, ROOT)
    from android_bridge import sasl_hardening
    with open(SCRIPT) as fh:
        script = fh.read()
    assert "APP_MIN_ITERATIONS=%d\n" % sasl_hardening.MIN_ITERATIONS in script
    assert "APP_MAX_ITERATIONS=%d\n" % sasl_hardening.MAX_ITERATIONS in script


@needs_bash
def test_exit_3_wins_over_exit_4_and_both_are_said(tmp_path):
    config = CFG.replace("VirtualHost",
                         'c2s_interfaces = { "0.0.0.0" }\n'
                         "default_iteration_count = 12\nVirtualHost")
    done = _script(tmp_path, config=config, HIDDEN_SERVICE="1")
    assert done.returncode == 3
    assert "FAILED (3)" in done.stderr
    assert "a setting that stops the apps signing in" in done.stderr


@needs_bash
def test_an_unknown_argument_is_a_usage_error(tmp_path):
    done = _script(tmp_path, "--chek")
    assert done.returncode == 64
    assert "unknown argument: --chek" in done.stderr
    assert "Usage:" in done.stderr
    assert (tmp_path / "prosody.cfg.lua").read_text() == CFG
    helped = _script(tmp_path, "--help")
    assert helped.returncode == 0 and "Exit status" in helped.stdout


@needs_bash
def test_the_diff_prints_only_the_lines_it_changes(tmp_path):
    """A Prosody config holds secrets (component and database passwords). A
    diff with context would print the line beside one this script changes,
    into output people paste into bug reports."""
    config = CFG.replace(
        "max_online_users = 2000\n",
        'component_secret = "hunter2-do-not-print"\n'
        "max_online_users = 2000\n"
        'sql = { password = "also-not-this" }\n')
    done = _script(tmp_path, "--check", config=config)
    assert done.returncode == 2
    assert "-max_online_users = 2000" in done.stdout
    assert "hunter2" not in done.stdout + done.stderr
    assert "also-not-this" not in done.stdout + done.stderr
    applied = _script(tmp_path)
    assert "hunter2" not in applied.stdout + applied.stderr
    assert "also-not-this" not in applied.stdout + applied.stderr


@needs_bash
@pytest.mark.skipif(not any(shutil.which(name) for name in (
    "lua5.4", "lua5.3", "lua5.2", "lua5.1", "lua", "luajit")),
    reason="needs a Lua interpreter")
def test_an_edit_that_would_break_the_config_stops_before_touching_it(tmp_path):
    """`sed` replaces one line. `interfaces` written over three becomes a
    line and two orphans. That used to be written, caught by prosodyctl and
    rolled back; it is now caught in the scratch copy."""
    config = CFG.replace("VirtualHost",
                         'interfaces = {\n\t"192.0.2.7";\n}\nVirtualHost')
    done = _script(tmp_path, config=config, HIDDEN_SERVICE="1")
    assert done.returncode == 1
    assert "would not be valid Lua, so nothing was changed" in done.stderr
    assert "put it on one line" in done.stderr
    assert (tmp_path / "prosody.cfg.lua").read_text() == config
    assert _backups(tmp_path) == []
    assert not (tmp_path / "mods").exists()


@needs_bash
@pytest.mark.skipif(not any(shutil.which(name) for name in (
    "lua5.4", "lua5.3", "lua5.2", "lua5.1", "lua", "luajit")),
    reason="needs a Lua interpreter")
def test_a_config_already_broken_is_left_alone(tmp_path):
    config = CFG.replace("max_online_users = 2000", "max_online_users = = 2000")
    done = _script(tmp_path, config=config)
    assert done.returncode == 1
    assert "is not valid Lua as it stands" in done.stderr
    assert (tmp_path / "prosody.cfg.lua").read_text() == config


@needs_bash
def test_a_failed_prosodyctl_check_puts_config_and_modules_back(tmp_path):
    assert _script(tmp_path).returncode == 0                # a first install
    before = (tmp_path / "prosody.cfg.lua").read_text()
    old_module = "-- the version that was running\n"
    (tmp_path / "mods" / "mod_otrv4plus_capacity.lua").write_text(old_module)
    done = _script(tmp_path, PROSODYCTL="false", MAX_ONLINE_USERS="1700")
    assert done.returncode == 1
    assert "prosodyctl check config failed" in done.stderr
    assert (tmp_path / "prosody.cfg.lua").read_text() == before
    assert (tmp_path / "mods" / "mod_otrv4plus_capacity.lua").read_text() == old_module


@needs_bash
def test_a_commented_out_module_is_not_counted_as_enabled(tmp_path):
    config = CFG.replace('\t"roster";',
                         '\t"roster";\n\t--"otrv4plus_capacity";')
    done = _script(tmp_path, config=config)
    assert done.returncode == 0
    out = (tmp_path / "prosody.cfg.lua").read_text()
    live = [line for line in out.splitlines()
            if '"otrv4plus_capacity"' in line and not line.strip().startswith("--")]
    assert len(live) == 1, out


@needs_bash
def test_another_list_naming_s2s_is_not_mistaken_for_disabling_it(tmp_path):
    """`modules_disabled = { }` on one line used to be read up to the next
    closing brace anywhere below, so a different list that named "s2s" made
    federation look off."""
    config = CFG.replace(
        "VirtualHost",
        'modules_disabled = { }\n'
        'some_other_list = {\n\t"s2s";\n}\nVirtualHost')
    done = _script(tmp_path, config=config)
    assert "federation (s2s): ON" in done.stdout
    hidden = _script(tmp_path, HIDDEN_SERVICE="1")
    assert hidden.returncode == 0, hidden.stdout + hidden.stderr
    out = (tmp_path / "prosody.cfg.lua").read_text()
    block = out[out.index("modules_disabled"):]
    assert '"s2s"' in block[:block.index("}")]


@needs_bash
def test_a_per_host_list_does_not_count_as_the_global_one(tmp_path):
    config = CFG + 'modules_disabled = { "s2s" }\n'       # after VirtualHost
    done = _script(tmp_path, config=config)
    assert "federation (s2s): ON" in done.stdout


# ── the two rules that depend on the Prosody version ────────────────────────

def _fake_prosodyctl(tmp_path, version):
    """A prosodyctl that says its version and passes every check."""
    script = tmp_path / "fake_prosodyctl"
    script.write_text(
        "#!/bin/sh\n"
        'case "$*" in *about*) printf "Prosody %s\\n\\n# Prosody directories\\n";; esac\n'
        "exit 0\n" % version)
    script.chmod(0o755)
    return str(script)


LOW = "default_iteration_count = 1000"
NO_PLUS = 'disable_sasl_mechanisms = { "SCRAM-SHA-1-PLUS" }'


@needs_bash
@pytest.mark.parametrize("version,line,stops,says", [
    # Measured 2026-11-15 with the hardened client (see the script, and
    # tests/test_real_prosody.py::test_what_the_script_calls_a_stop_...).
    ("0.12.4", LOW, True, "end the sign-in below that"),
    ("13.0.7", LOW, False, "Prosody 13.0.7 uses 4096 instead"),
    ("0.12.4", NO_PLUS, False, "only on connections older than TLS 1.3"),
    ("13.0.7", NO_PLUS, True, "as if the password were wrong"),
    ("14.1", NO_PLUS, True, "as if the password were wrong"),
])
def test_two_rules_go_by_the_prosody_version(tmp_path, version, line, stops,
                                             says):
    config = CFG.replace("VirtualHost", line + "\nVirtualHost")
    done = _script(tmp_path, config=config,
                   PROSODYCTL=_fake_prosodyctl(tmp_path, version))
    said = done.stdout + done.stderr
    assert says in said, said
    if stops:
        assert done.returncode == 4, said
        assert "settings that stop the apps signing in: YES" in done.stdout
    else:
        assert done.returncode == 0, said
        assert "settings that stop the apps signing in: none" in done.stdout
        assert "worth changing, though the apps sign in as it is:" in done.stdout


@needs_bash
def test_the_version_is_asked_only_when_a_rule_needs_it(tmp_path):
    """An ordinary config costs no extra prosodyctl run (and none of its
    surprises) before anything is changed."""
    calls = tmp_path / "calls"
    script = tmp_path / "counting_prosodyctl"
    script.write_text('#!/bin/sh\necho "$*" >> "%s"\nexit 0\n' % calls)
    script.chmod(0o755)
    assert _script(tmp_path, "--check", PROSODYCTL=str(script)).returncode == 2
    assert not calls.exists()
    config = CFG.replace("VirtualHost", LOW + "\nVirtualHost")
    _script(tmp_path, "--check", config=config, PROSODYCTL=str(script))
    assert "about" in calls.read_text()


# ── nothing this script prints names where the machine is ───────────────────

ADDRESS4, ADDRESS6 = "203.0.113.9", "2001:db8::7"      # RFC 5737 / 3849
SS_SPECIFIC = [
    'LISTEN 0 128 %s:5222 0.0.0.0:* users:(("lua5.4",pid=811,fd=9))' % ADDRESS4,
    'LISTEN 0 128 [%s]:5269 [::]:* users:(("lua5.4",pid=811,fd=11))' % ADDRESS6,
    'LISTEN 0 128 *:5281 *:* users:(("lua5.4",pid=811,fd=13))',
]


@needs_bash
@pytest.mark.parametrize("hidden", ["1", "0"])
def test_a_specific_address_of_this_machine_is_never_printed(tmp_path, hidden):
    """The output of this script is what an operator pastes when asking for
    help. For a hidden server the machine's address is the secret: the old
    `interfaces` line, a narrower `c2s_interfaces`, and the sockets Prosody
    holds all name it. The port is said; the address is not."""
    config = CFG.replace(
        "VirtualHost",
        'interfaces = { "%s", "%s" }\n'
        'c2s_interfaces = { "%s" }\nVirtualHost' % (ADDRESS4, ADDRESS6, ADDRESS4))
    lister = _fake_ss(tmp_path, SS_SPECIFIC)
    looked = _script(tmp_path, "--check", config=config, SS=lister,
                     HIDDEN_SERVICE=hidden)
    applied = _script(tmp_path, SS=lister, HIDDEN_SERVICE=hidden)
    again = _script(tmp_path, "--check", SS=lister, HIDDEN_SERVICE=hidden)
    everything = "".join(done.stdout + done.stderr
                         for done in (looked, applied, again))
    assert ADDRESS4 not in everything
    assert ADDRESS6 not in everything and "2001" not in everything
    # What is needed to act is still there: which ports, and which line.
    assert "(an address of this machine):5222" in looked.stdout
    assert "(an address of this machine):5269" in looked.stdout
    assert "*:5281" in looked.stdout                    # a wildcard says nothing
    if hidden == "1":
        assert "-interfaces = (not printed: it names an address of this machine)" \
            in looked.stdout
        assert '+interfaces = { "127.0.0.1" }' in looked.stdout
        assert "c2s_interfaces = (not printed" in looked.stdout
        assert applied.returncode == 3
        # Named by its line in the file as it is now, and by its key.
        written = (tmp_path / "prosody.cfg.lua").read_text().splitlines()
        number = 1 + [line.startswith("c2s_interfaces")
                      for line in written].index(True)
        assert ("line %d: c2s_interfaces = (not printed" % number
                in applied.stderr)
    else:
        # Left as the operator wrote it, and shown without its value.
        assert applied.returncode == 0
        assert "interfaces = (not printed: it names an address of this machine)" \
            in applied.stdout
    # The file itself is of course untouched by the withholding.
    assert ADDRESS4 in (tmp_path / "prosody.cfg.lua").read_text()


@needs_bash
def test_a_socket_is_judged_by_its_owner_where_the_owner_is_shown(tmp_path):
    """Port 5000 is Prosody's file-transfer proxy and a great many other
    things. Shown the owner (as root is), the script believes it; not shown
    one, it goes by the port."""
    owned = _fake_ss(tmp_path, [
        'LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* users:(("python3",pid=77,fd=3))',
        'LISTEN 0 128 0.0.0.0:5222 0.0.0.0:* users:(("nginx",pid=78,fd=6))',
    ])
    done = _script(tmp_path, "--check", SS=owned)
    assert "listening beyond this machine: no" in done.stdout
    unowned = _fake_ss(tmp_path, [
        "LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*",
        "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*",
    ])
    done = _script(tmp_path, "--check", SS=unowned)
    assert "listening beyond this machine: YES" in done.stdout
    assert "0.0.0.0:5000" in done.stdout and "8080" not in done.stdout
    # A port the config names counts too, when no owner is shown.
    config = CFG.replace("VirtualHost", "c2s_ports = { 8080 }\nVirtualHost")
    done = _script(tmp_path, "--check", config=config, SS=unowned)
    assert "0.0.0.0:8080" in done.stdout


@needs_bash
def test_what_could_not_be_looked_at_is_not_reported_as_closed(tmp_path):
    """No `ss`: the answer is "could not tell", never "no"; and on a server
    asked to be hidden that is a failure, because the one thing the run is
    for was not established."""
    assert _script(tmp_path, HIDDEN_SERVICE="1").returncode == 0
    missing = str(tmp_path / "no-such-ss")
    done = _script(tmp_path, "--check", SS=missing, HIDDEN_SERVICE="1")
    assert "listening beyond this machine: COULD NOT TELL" in done.stdout
    assert "listening beyond this machine: no" not in done.stdout
    assert done.returncode == 3, done.stdout + done.stderr
    assert "could not be confirmed" in done.stderr
    assert "Install iproute2" in done.stderr
    # Not asked to be hidden: said, and not a failure.
    plain = _script(tmp_path, "--check", SS=missing)
    assert "COULD NOT TELL" in plain.stdout
    assert plain.returncode == 0, plain.stdout + plain.stderr


@needs_bash
@pytest.mark.parametrize("entry", ['"c2s_limit_sessions";',
                                   '"c2s_limit_sessions",',
                                   '"c2s_limit_sessions"'])
def test_the_old_one_session_module_is_replaced_however_it_is_written(
        tmp_path, entry):
    """It refuses the NEW sign-in, ours the old one: the two must not both
    run. Only the `;` form used to be replaced."""
    config = CFG.replace('\t"roster";', '\t"roster";\n\t%s' % entry)
    assert _script(tmp_path, config=config).returncode == 0
    out = (tmp_path / "prosody.cfg.lua").read_text()
    assert "c2s_limit_sessions" not in out
    assert out.count('"otrv4plus_one_session"') == 1


@needs_bash
def test_a_commented_out_old_module_is_left_as_it_is(tmp_path):
    config = CFG.replace('\t"roster";',
                         '\t"roster";\n\t-- "c2s_limit_sessions"; -- old')
    assert _script(tmp_path, config=config).returncode == 0
    out = (tmp_path / "prosody.cfg.lua").read_text()
    assert '-- "c2s_limit_sessions"; -- old' in out


# ── RESTART=1: the run an operator actually does ────────────────────────────
#
# It needs root, systemd and a Prosody service, none of which a test run
# has; so `id`, `systemctl` and `sleep` are stand-ins on PATH. Everything
# else is the script itself: the restart, the look at what is listening
# afterwards, the error log, XMPP Guard's flag.

def _production(tmp_path, *args, restart_closes=True, starts=True,
                log_on_restart="", **env):
    fake = tmp_path / "fakebin"
    fake.mkdir(exist_ok=True)
    state = tmp_path / "restarted"
    calls = tmp_path / "systemctl-calls"
    log = tmp_path / "prosody.err"
    if not log.exists():
        log.write_text("an old line from last week\n")
    (fake / "id").write_text("#!/bin/sh\necho 0\n")
    (fake / "sleep").write_text("#!/bin/sh\nexit 0\n")
    (fake / "systemctl").write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "%(calls)s"\n'
        'case "$1" in\n'
        '  restart) : > "%(state)s"; printf "%%s" "%(line)s" >> "%(log)s" ;;\n'
        "  is-active) exit %(active)d ;;\n"
        "esac\nexit 0\n" % {"calls": calls, "state": state, "log": log,
                            "line": log_on_restart,
                            "active": 0 if starts else 3})
    lister = fake / "ss"
    lister.write_text(
        "#!/bin/sh\n"
        'if [ -e "%s" ] && [ "%s" = 1 ]; then\ncat <<\'END\'\n%s\nEND\n'
        "else\ncat <<'END'\n%s\nEND\nfi\n"
        % (state, "1" if restart_closes else "0", "\n".join(SS_CLOSED),
           "\n".join(SS_OPEN)))
    for name in ("id", "sleep", "systemctl", "ss"):
        (fake / name).chmod(0o755)
    env.setdefault("PATH", "%s:%s" % (fake, os.environ["PATH"]))
    # Never the machine's real XMPP Guard, if this runs where one is.
    env.setdefault("XMPP_GUARD_STATE", str(tmp_path / "no-guard"))
    done = _script(tmp_path, *args, RESTART="1", SS="ss",
                   PROSODY_LOG=str(log), **env)
    done.systemctl = calls.read_text().split("\n") if calls.exists() else []
    return done


@needs_bash
def test_the_real_run_closes_it_restarts_once_and_says_before_and_after(tmp_path):
    done = _production(tmp_path, HIDDEN_SERVICE="1")
    assert done.returncode == 0, done.stdout + done.stderr
    said = done.stdout
    assert said.index("listening beyond this machine: YES") < said.index("backup:")
    assert "restarting Prosody" in said
    assert "listening beyond this machine: YES  ->  no" in said
    assert "federation (s2s): on  ->  off" in said
    assert done.systemctl.count("restart prosody") == 1
    # The old line in the error log is not this run's, and is not shown.
    assert "an old line from last week" not in said

    second = _production(tmp_path, HIDDEN_SERVICE="1")
    assert second.returncode == 0, second.stdout + second.stderr
    assert "nothing to change" in second.stdout
    assert "restart prosody" not in second.systemctl[
        len(done.systemctl) - 1:], "a run with nothing to do restarted Prosody"
    assert "listening beyond this machine: no  ->  no" in second.stdout
    assert len(_backups(tmp_path)) == 1


@needs_bash
def test_the_real_run_fails_if_prosody_still_listens_afterwards(tmp_path):
    done = _production(tmp_path, restart_closes=False, HIDDEN_SERVICE="1")
    assert done.returncode == 3
    assert "listening beyond this machine: YES  ->  YES" in done.stdout
    assert "Prosody is still listening on" in done.stderr
    assert "0.0.0.0:5222" in done.stderr
    # Not hidden: the operator's choice, said as a note.
    (tmp_path / "prosody.cfg.lua").write_text(CFG)
    plain = _production(tmp_path, restart_closes=False)
    assert plain.returncode == 0
    assert "NOTE: Prosody is listening beyond this machine" in plain.stdout


@needs_bash
def test_the_real_run_stops_when_a_module_of_ours_is_in_the_error_log(tmp_path):
    line = "mod_otrv4plus_capacity: error loading module: not found\\n"
    done = _production(tmp_path, log_on_restart=line)
    assert done.returncode == 1
    assert "a module of ours is named in Prosody's error log" in done.stderr
    assert "To go back: sudo cp" in done.stderr
    assert "error loading module" in done.stdout          # the line is shown


@needs_bash
def test_the_real_run_says_how_to_go_back_when_prosody_does_not_start(tmp_path):
    done = _production(tmp_path, starts=False)
    assert done.returncode == 1
    assert "Prosody did not start" in done.stderr
    assert "To go back: sudo cp" in done.stderr
    assert ".bak-" in done.stderr


@needs_bash
def test_the_real_run_needs_root_and_says_so_before_anything(tmp_path):
    fake = tmp_path / "notroot"
    fake.mkdir()
    (fake / "id").write_text("#!/bin/sh\necho 1000\n")
    (fake / "id").chmod(0o755)
    done = _script(tmp_path, RESTART="1",
                   PATH="%s:%s" % (fake, os.environ["PATH"]))
    assert done.returncode == 1
    assert "run it with sudo (or with --check to only look)" in done.stderr
    assert "what is true now" not in done.stdout
    assert (tmp_path / "prosody.cfg.lua").read_text() == CFG


@needs_bash
def test_xmpp_guard_is_told_only_when_something_is_about_to_change(tmp_path):
    """XMPP Guard fingerprints the config and modules. Its maintenance flag
    turns this script's own changes into the new baseline; raised on a run
    that changes nothing, it would be an hour in which a real change went
    unreported."""
    guard = tmp_path / "guard"
    guard.mkdir()
    first = _production(tmp_path, XMPP_GUARD_STATE=str(guard))
    assert first.returncode == 0, first.stdout + first.stderr
    assert (guard / "maintenance").exists()
    assert "XMPP Guard: maintenance mode on" in first.stdout
    (guard / "maintenance").unlink()
    second = _production(tmp_path, XMPP_GUARD_STATE=str(guard))
    assert second.returncode == 0
    assert not (guard / "maintenance").exists()


@needs_bash
def test_it_passes_shellcheck():
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck not installed")
    done = subprocess.run(["shellcheck", "-S", "warning", SCRIPT],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout


