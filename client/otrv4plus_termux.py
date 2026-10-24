# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Setting up Termux for the terminal client: packages, the sound server, the
microphone, and the audio self-tests behind /audioprobe and /audiotest.

Moved out of otrv4plus_xmpp.py, whose main() runs `_bootstrap_termux` before
signing in. The client's own Opus loader and voice check are passed in, so
the hooks the Android bridge binds into them are the ones used here too.
"""
import asyncio
import builtins
import os
import secrets
import struct
import sys
import time

import otrv4plus_host as _host
from otrv4plus_host import TERMUX_PREFIX, _run, _which
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)
from otrv4plus_tunnels import _pipe_read_exact

#: The engine (otrv4+.py), for its overwrite-and-unlink; set by bind_engine().
_otr = None


def bind_engine(otr) -> None:
    """Take the engine from the client, which has loaded it."""
    global _otr
    _otr = otr


# -----------------------------------------------------------------------------
# Automated Termux / Android provisioning
# -----------------------------------------------------------------------------
# Goal: a user receives this single file, runs it, and ends up with a working
# encrypted voice-capable client without being walked through anything.
#
# Everything below runs with shell=False and explicit argv lists. Nothing is
# interpolated into a shell, so a hostile environment variable or filename
# cannot become command injection. Every subprocess has a timeout, so a wedged
# helper cannot hang startup forever.
#
# The provisioning is idempotent. Expensive steps (package installation) are
# gated behind a version-stamped marker file; runtime steps (starting the sound
# server, loading the microphone source) are re-checked on every launch because
# they do not survive a reboot.
# -----------------------------------------------------------------------------

BOOTSTRAP_VERSION = 5
BOOTSTRAP_MARKER = os.path.expanduser(
    "~/.otrv4plus/.bootstrap-v%d" % BOOTSTRAP_VERSION)

# Package name -> the executable or library proving it is installed.
_APT_REQUIREMENTS = (
    ("pulseaudio", "bin/parec"),
    ("libopus", "lib/libopus.so"),
    ("termux-api", "bin/termux-microphone-record"),
    # Termux splits OpenSSL: the `openssl` package ships libcrypto/libssl,
    # while the `openssl` COMMAND comes from `openssl-tool`. Checking for
    # bin/openssl while installing `openssl` can never succeed, so each entry
    # must name the package that actually provides the file being tested.
    ("openssl", "lib/libcrypto.so"),
    ("openssl-tool", "bin/openssl"),
    ("git", "bin/git"),
)

# Import name -> pip distribution name. These differ often enough that keying
# on the import name is the only reliable check.
_PIP_REQUIREMENTS = (
    ("slixmpp", "slixmpp"),
    ("aiodns", "aiodns"),
    ("cryptography", "cryptography"),
    ("opuslib", "opuslib"),
    ("socks", "pysocks"),
)

_PULSE_SOURCE_MODULE = "module-sles-source"




def _termux_env():
    """Environment for child processes, with the Termux library path set.

    PortAudio and PulseAudio clients resolve libpulse.so at load time; without
    this on the child's environment they fail with a bare dlopen error that is
    very hard to diagnose.
    """
    env = dict(os.environ)
    libdir = os.path.join(TERMUX_PREFIX, "lib")
    current = env.get("LD_LIBRARY_PATH", "")
    if libdir not in current.split(os.pathsep):
        env["LD_LIBRARY_PATH"] = (
            libdir + (os.pathsep + current if current else ""))
    return env


def _apt_missing():
    """Return the apt packages whose proof-of-install file is absent."""
    missing = []
    for package, relative in _APT_REQUIREMENTS:
        if not os.path.exists(os.path.join(TERMUX_PREFIX, relative)):
            missing.append(package)
    return missing


def _pip_missing():
    """Return the pip distributions whose import name does not resolve."""
    import importlib
    importlib.invalidate_caches()
    missing = []
    for module, distribution in _PIP_REQUIREMENTS:
        try:
            importlib.import_module(module)
        except Exception:
            missing.append(distribution)
    return missing


def _apt_install(packages):
    """Install apt packages, tolerating unrelated post-install failures.

    Termux's xdg-utils post-install script fails on many devices and poisons
    apt's exit status for every package in the same transaction. The return
    code is therefore ignored entirely; success is judged solely by re-testing
    for each package's proof file afterwards.

    --no-install-recommends keeps the broken xdg-utils/qt6 dependency chain
    out of the transaction in the first place.
    """
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    _run(["apt-get", "update", "-y"], timeout=180, env=env)
    _run(
        ["apt-get", "install", "-y", "--no-install-recommends",
         "-o", "Dpkg::Options::=--force-confold",
         "-o", "Dpkg::Options::=--force-confdef"] + list(packages),
        timeout=900, env=env,
    )


def _pip_install(distributions):
    """Install pip distributions into the Termux Python."""
    _run(
        [sys.executable, "-m", "pip", "install", "--break-system-packages",
         "--disable-pip-version-check", "-q"] + list(distributions),
        timeout=900,
    )


def _pulse_running():
    return _run(["pulseaudio", "--check"], timeout=15,
                env=_termux_env())[0] == 0


def _pulse_start():
    """Start PulseAudio as a persistent daemon. Returns (started, diagnosis).

    `pulseaudio --start` forks the daemon and RETURNS — it does not block —
    so it must be run with its output captured rather than detached. An
    earlier version detached it, which discarded the daemon's own error
    message and left this function reporting the unrelated output of a later
    `--check` call.

    Timing matters more than retrying. A cold daemon on Android can take well
    over ten seconds to load its modules and accept connections. The first
    attempt is therefore given a long, patient window; `-k` is only used
    afterwards, because killing during startup destroys a daemon that was
    simply slow — which is precisely what happened before.
    """
    if _which("pulseaudio") is None:
        return False, "pulseaudio binary not found — pkg install pulseaudio"

    env = _termux_env()
    common = ["--exit-idle-time=-1"]

    def _await_daemon(seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if _pulse_running():
                return True
            time.sleep(0.4)
        return False

    # Attempt 1: patient. Captured, so a real failure is explained.
    rc, out, err = _run(["pulseaudio", "--start"] + common, timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    first_error = (err or out or "").strip()

    # Attempt 2: clear a stale runtime directory, then start again. Only now
    # is -k safe, because attempt 1 has been given every chance to finish.
    _run(["pulseaudio", "-k"], timeout=20, env=env)
    time.sleep(1.0)
    rc, out, err = _run(["pulseaudio", "--start"] + common, timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    second_error = (err or out or "").strip()

    # Attempt 3: explicit daemonize, for builds where --start misbehaves.
    rc, out, err = _run(["pulseaudio", "--daemonize=yes"] + common,
                        timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    third_error = (err or out or "").strip()

    for candidate in (first_error, second_error, third_error):
        lines = [l for l in candidate.splitlines()
                 if l.strip() and not l.startswith("I: ")]
        if lines:
            return False, lines[-1][:180]
    return False, "no diagnostic produced by the daemon"


def _pulse_sources():
    """Return the list of PulseAudio source names, or [] on failure."""
    rc, out, _ = _run(["pactl", "list", "short", "sources"],
                      timeout=20, env=_termux_env())
    if rc != 0:
        return []
    names = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            names.append(parts[1])
    return names


def _pulse_input_source(sources):
    """Pick the real microphone from a source list.

    A monitor source is the loopback of the speaker output, not a microphone;
    selecting one produces a call in which each side hears only themselves.
    """
    for name in sources:
        if "monitor" not in name.lower() and "input" in name.lower():
            return name
    for name in sources:
        if "monitor" not in name.lower():
            return name
    return None


def _ensure_microphone_source():
    """Guarantee a non-monitor capture source exists and is the default.

    Returns (source_name_or_None, note).
    """
    sources = _pulse_sources()
    source = _pulse_input_source(sources)

    if source is None:
        # Load the Android OpenSL ES capture module. Loading it twice creates
        # duplicate sources, so this only runs when none was found.
        _run(["pactl", "load-module", _PULSE_SOURCE_MODULE],
             timeout=30, env=_termux_env())
        time.sleep(1.0)
        sources = _pulse_sources()
        source = _pulse_input_source(sources)

    if source is None:
        return None, "no capture source available"

    _run(["pactl", "set-default-source", source], timeout=20,
         env=_termux_env())
    return source, "ok"


def _termux_api_present():
    """Check the Termux:API companion app, not merely the CLI package.

    The termux-api apt package only installs shell shims; the actual Android
    bridge is a separate APK. Without the APK the shims block forever waiting
    on a socket, so this probe is timeout-bounded.
    """
    if _which("termux-microphone-record") is None:
        return False, "termux-api package not installed"
    rc, out, err = _run(["termux-microphone-record", "-i"], timeout=12)
    if rc == 124:
        return False, "Termux:API app not installed (command hung)"
    blob = (out + err).lower()
    if "permission" in blob:
        return True, "permission-needed"
    return True, "ok"


def _request_microphone_permission():
    """Trigger Android's RECORD_AUDIO prompt for Termux.

    PulseAudio's OpenSL ES source records through the Termux process itself
    and cannot raise a runtime permission dialog; only the Termux:API bridge
    can. A one-second recording is therefore started purely to make the system
    dialog appear, then stopped, and the resulting file is destroyed with the
    OTR engine's overwrite-and-unlink (file-level only). It contains a second of ambient audio
    at most and never survives this function.
    """
    target = os.path.join(
        os.path.expanduser("~"), ".otrv4plus_permcheck_%s.m4a"
        % secrets.token_hex(4))
    try:
        # termux-microphone-record backgrounds the recorder, so its output
        # must not be captured for the same reason pulseaudio --start cannot.
        _run(["termux-microphone-record", "-f", target, "-l", "1"],
             timeout=20, detach=True)
        time.sleep(2.0)
        _run(["termux-microphone-record", "-q"], timeout=20, detach=True)
        time.sleep(0.5)
    finally:
        try:
            if os.path.exists(target):
                shred = getattr(_otr, "_secure_file_destroy", None)
                if shred is not None:
                    shred(target)
                else:
                    with open(target, "r+b") as handle:
                        length = os.path.getsize(target)
                        handle.write(os.urandom(max(length, 1)))
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.remove(target)
        except Exception:
            try:
                os.remove(target)
            except Exception:
                pass


def _capture_selftest(seconds=3.0):
    """Verify the microphone actually delivers samples.

    Goes through otrv4plus_audio, so it tests whichever backend voice will
    actually use — AAudio on Android. The previous version drove parec, which
    meant a device with a perfectly working AAudio microphone was reported as
    broken and the user was told to repair PulseAudio, which was both wrong
    and unfixable on hardware where module-sles-source does not load.

    Returns (ok, bytes_captured, peak_amplitude, backend_name).

    Peak is reported rather than asserted: a silent room is not a failure, but
    a peak of zero alongside a healthy byte count is the signature of a
    revoked RECORD_AUDIO permission, or of a null source, and is worth telling
    the user about. Nothing is written to disk and no samples are printed.
    """
    try:
        import otrv4plus_audio as _aud
    except Exception:
        return False, 0, 0, "none"

    stream = None
    total, peak = 0, 0
    backend = "none"
    try:
        stream, _notes = _aud.open_capture(which=_which,
                                           read_exact=_pipe_read_exact,
                                           env=_termux_env())
        backend = stream.name
        deadline = time.monotonic() + float(seconds)
        while time.monotonic() < deadline:
            frame = stream.read_frame(timeout_ms=200)
            if not frame:
                continue
            total += len(frame)
            n = len(frame) // 2
            peak = max(peak, max(abs(v) for v in struct.unpack("<%dh" % n,
                                                               frame)))
    except Exception:
        return False, total, peak, backend
    finally:
        if stream is not None:
            try:
                stream.stop()
            except Exception:
                pass
    return True, total, peak, backend

def _persist_shell_profile():
    """Append the audio environment to ~/.bashrc, exactly once.

    Written so that a plain `bash` session (not just this script) has a working
    sound stack, which matters when the user runs the client a second time.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    marker = "# --- OTRv4+ audio environment (managed) ---"
    try:
        existing = ""
        if os.path.exists(bashrc):
            with open(bashrc, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        if marker in existing:
            return False
        with open(bashrc, "a", encoding="utf-8") as fh:
            fh.write("\n%s\n" % marker)
            fh.write("export LD_LIBRARY_PATH=%s/lib:$LD_LIBRARY_PATH\n"
                     % TERMUX_PREFIX)
            fh.write("pulseaudio --check 2>/dev/null || "
                     "pulseaudio --start --exit-idle-time=-1 2>/dev/null\n")
            fh.write("pactl list short sources 2>/dev/null | "
                     "grep -qv monitor || "
                     "pactl load-module %s 2>/dev/null\n" % _PULSE_SOURCE_MODULE)
            fh.write("# --- end OTRv4+ audio environment ---\n")
        return True
    except Exception:
        return False


def _probe_sam(host="127.0.0.1", port=7656, timeout=3.0):
    """Return True if a SAM v3.1 bridge answers on host:port."""
    import socket as _socket
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
        reply = sock.recv(256)
        sock.close()
        return b"RESULT=OK" in reply
    except Exception:
        return False


def _provision_packages(issues, load_opus):
    """Install missing packages and Python modules; find the Opus library. Appends to *issues*."""
    # -- 1. Native packages ---------------------------------------------------
    missing_apt = _apt_missing()
    if missing_apt:
        # openssl-tool provides only the command-line utility. Nothing in the
        # client calls it — libcrypto is reached through the C extensions —
        # so its absence is cosmetic and must not be presented as a failure.
        pass
    if missing_apt:
        builtins.print("  installing packages: %s" % " ".join(missing_apt))
        builtins.print("  (this can take a few minutes on first run)")
        _apt_install(missing_apt)
        still_missing = _apt_missing()
        cosmetic = {"openssl-tool"}
        blocking = [p for p in still_missing if p not in cosmetic]
        if blocking:
            issues.append(
                "could not install: %s  —  run manually: pkg install %s"
                % (" ".join(blocking), " ".join(blocking)))
            builtins.print("  ! failed: %s" % " ".join(blocking))
        if [p for p in still_missing if p in cosmetic]:
            builtins.print("    note: openssl-tool (the CLI) unavailable — "
                           "harmless, the client uses libcrypto directly")
        if not blocking:
            builtins.print("  packages installed")
    else:
        builtins.print("  packages           OK")

    # -- 2. Python distributions ---------------------------------------------
    missing_pip = _pip_missing()
    if missing_pip:
        builtins.print("  installing Python modules: %s" % " ".join(missing_pip))
        _pip_install(missing_pip)
        still_missing = _pip_missing()
        if still_missing:
            issues.append(
                "pip install failed for: %s" % " ".join(still_missing))
            builtins.print("  ! failed: %s" % " ".join(still_missing))
        else:
            builtins.print("  Python modules installed")
    else:
        builtins.print("  Python modules     OK")

    # Re-import opuslib now that it may exist. Without this the process would
    # run the whole session believing voice is unavailable.
    load_opus()

    # -- 3. Library path for child processes ----------------------------------
    libdir = os.path.join(TERMUX_PREFIX, "lib")
    if libdir not in os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep):
        os.environ["LD_LIBRARY_PATH"] = (
            libdir + os.pathsep + os.environ.get("LD_LIBRARY_PATH", ""))


def _check_audio(issues, first_run):
    """Termux:API, the audio backend and a microphone test. Appends to *issues*."""
    # -- 4. Termux:API bridge and microphone permission -----------------------
    api_ok, api_note = _termux_api_present()
    if not api_ok:
        issues.append(
            "Termux:API app missing — install it from F-Droid "
            "(same source as Termux), then re-run. Without it Android will "
            "never prompt for microphone access.")
        builtins.print("  Termux:API         MISSING")
    elif api_note == "permission-needed" or first_run:
        builtins.print("  requesting microphone permission…")
        builtins.print("  >> TAP 'ALLOW' ON THE ANDROID DIALOG <<")
        _request_microphone_permission()
        builtins.print("  microphone permission requested")
    else:
        builtins.print("  Termux:API         OK")

    # -- 5/6. Audio backend and proof that capture works ---------------------
    #
    # AAudio is the backend voice actually uses on Android: it talks to the
    # platform audio framework directly and needs no daemon, no PulseAudio and
    # no module-sles-source. So the question is not "is PulseAudio healthy" —
    # it is "does the backend voice will use deliver real samples". PulseAudio
    # is only prepared, and only diagnosed, when it is the only backend left.
    pulse_note = ""
    aaudio_ok = False
    try:
        import otrv4plus_audio as _aud
        aaudio_ok = _aud.aaudio_available()
    except Exception as exc:
        builtins.print("  audio backend      MODULE ERROR: %s"
                       % _sanitise(str(exc), 80))

    if aaudio_ok:
        builtins.print("  audio backend      AAudio (native Android)")
    else:
        builtins.print("  audio backend      AAudio unavailable — trying "
                       "PulseAudio")
        if _pulse_running():
            builtins.print("  PulseAudio         running")
        else:
            started, pulse_note = _pulse_start()
            if started:
                builtins.print("  PulseAudio         started")
            else:
                builtins.print("  PulseAudio         did not start via --start")
                if pulse_note:
                    builtins.print("                     reason: %s"
                                   % _sanitise(pulse_note, 200))
        source, _note = _ensure_microphone_source()
        if source is None:
            builtins.print("  microphone source  none listed "
                           "(may still autospawn)")
        else:
            builtins.print("  microphone source  %s" % source)

    # Run unconditionally. If this passes, everything above was noise; if it
    # fails, it is the only failure that actually matters.
    builtins.print("  testing microphone…")
    ok_capture, total, peak, backend = _capture_selftest()
    if ok_capture and total > 0 and peak > 0:
        builtins.print("  microphone test    OK via %s (peak %d)"
                       % (backend, peak))
    elif ok_capture and total > 0:
        issues.append(
            "microphone delivered only silence via %s — grant Microphone in "
            "Settings > Apps > Termux > Permissions, then re-run. Termux:API "
            "holding the permission is not enough; the Termux app itself "
            "needs it." % backend)
        builtins.print("  microphone test    SILENT (%d bytes via %s)"
                       % (total, backend))
    elif aaudio_ok:
        issues.append(
            "AAudio loaded but produced no audio. Check Settings > Apps > "
            "Termux > Permissions > Microphone, then run /audioprobe in a "
            "session for the exact backend error. Do NOT chase PulseAudio: "
            "voice does not use it.")
        builtins.print("  microphone test    NO AUDIO (AAudio)")
    else:
        detail = (" — %s" % pulse_note) if pulse_note else ""
        issues.append(
            "no working audio backend%s. AAudio (libaaudio.so) was not "
            "available and PulseAudio produced nothing. Run /audioprobe for "
            "per-backend detail." % detail)
        builtins.print("  microphone test    NO AUDIO")


def _check_router_and_core(issues, sam_host, sam_port):
    """The I2P SAM bridge, the client files, the Rust core, the shell profile and the marker. Appends to *issues*."""
    # -- 7. I2P router --------------------------------------------------------
    if _probe_sam(sam_host, sam_port):
        builtins.print("  I2P SAM bridge     OK (%s:%d)" % (sam_host, sam_port))
    else:
        issues.append(
            "no I2P SAM bridge on %s:%d — start the i2pd Android app with SAM "
            "enabled, or run: pkg install i2pd && i2pd --daemon "
            "(SAM must be enabled in i2pd.conf)" % (sam_host, sam_port))
        builtins.print("  I2P SAM bridge     NOT FOUND")

    # -- 8. OTR engine and Rust core -----------------------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    if not (os.path.exists(os.path.join(here, "otrv4+.py"))
            or os.path.exists(os.path.join(here, "otrv4plus.py"))):
        issues.append("otrv4+.py not found beside this script")
    try:
        __import__("otrv4_core")
        builtins.print("  Rust ratchet       OK")
    except Exception:
        issues.append(
            "otrv4_core (Rust ratchet) not installed — build it: "
            "cd Rust && cargo test --release && "
            "ANDROID_API_LEVEL=24 maturin build --release && "
            "pip install target/wheels/otrv4_core-*.whl --break-system-packages")
        builtins.print("  Rust ratchet       MISSING")

    # -- 9. Persist for future shells ----------------------------------------
    if _persist_shell_profile():
        builtins.print("  ~/.bashrc          updated")

    # -- 10. Stamp ------------------------------------------------------------
    try:
        os.makedirs(os.path.dirname(BOOTSTRAP_MARKER), exist_ok=True)
        with open(BOOTSTRAP_MARKER, "w", encoding="utf-8") as fh:
            fh.write("provisioned %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        os.chmod(BOOTSTRAP_MARKER, 0o600)
    except Exception:
        pass


def _print_summary(issues, voice_available):
    """What needs attention, and whether voice is available."""
    # -- Summary --------------------------------------------------------------
    builtins.print("-" * 62)
    voice_ok, voice_reason = voice_available()
    if issues:
        builtins.print(" Attention needed:")
        for issue in issues:
            builtins.print("   * %s" % issue)
        builtins.print("")
        builtins.print(" Text chat works regardless; only the items above are "
                       "required for voice.")
    else:
        builtins.print(" Device ready — encrypted text and voice both available.")
    if not voice_ok:
        builtins.print(" Voice disabled: %s" % voice_reason)
    builtins.print("=" * 62)
    builtins.print("")


def _bootstrap_termux(skip=False, force=False, sam_host="127.0.0.1",
                      sam_port=7656, *, load_opus, voice_available):
    """Provision an Android/Termux device end to end.

    No-op on non-Termux systems. Returns a list of unresolved issues; an empty
    list means the device is ready for encrypted voice calls. `load_opus` and
    `voice_available` are the client's own (otrv4plus_xmpp.py).
    """
    if not _host.IS_TERMUX or skip:
        load_opus()
        return []

    issues = []
    first_run = force or not os.path.exists(BOOTSTRAP_MARKER)

    builtins.print("=" * 62)
    builtins.print(" OTRv4+ XMPP — device provisioning")
    builtins.print("=" * 62)

    _provision_packages(issues, load_opus)

    _check_audio(issues, first_run)

    _check_router_and_core(issues, sam_host, sam_port)

    _print_summary(issues, voice_available)
    return issues


def _playback_selftest(seconds=1.0):
    """Play a quiet 440 Hz tone through the backend calls will use.

    Returns (ok, backend_name, error). Linux and Termux alike: the backends
    (AAudio, parec/pacat) are the ones voice and group calls open."""
    try:
        import math
        import otrv4plus_audio as _aud
    except Exception as exc:
        return False, "none", type(exc).__name__
    stream, backend = None, "none"
    try:
        stream, _notes = _aud.open_playback(which=_which, env=_termux_env())
        backend = stream.name
        rate, frame = _aud.SAMPLE_RATE, _aud.FRAME_SAMPLES
        n = 0
        for _ in range(int(seconds * rate / frame)):
            samples = [int(6000 * math.sin(2 * math.pi * 440 * (n + i) / rate))
                       for i in range(frame)]
            n += frame
            stream.write_frame(struct.pack("<%dh" % frame, *samples))
        return True, backend, ""
    except Exception as exc:
        return False, backend, str(exc)[:160]
    finally:
        if stream is not None:
            try:
                stream.stop()
            except Exception:
                pass


async def _audio_selftest_async(voice_available):
    """/audiotest — the microphone (3 s) and the speaker (a 1 s tone), through
    the same audio backend calls use. Termux and Linux (parec/pacat).
    `voice_available` is the client's own (otrv4plus_xmpp.py)."""
    loop = asyncio.get_event_loop()
    print("[audio] playing a 1 s tone through the speaker…")
    played, out_backend, err = await loop.run_in_executor(None, _playback_selftest)
    if played:
        print("[audio] speaker: tone sent via %s — if you heard nothing, check "
              "the output device and volume%s"
              % (out_backend, "" if _host.IS_TERMUX else " (pavucontrol, or: pactl info)"))
    else:
        print("[audio] speaker FAILED via %s: %s%s"
              % (out_backend, err or "no playback backend",
                 "" if _host.IS_TERMUX else
                 "  (Linux: sudo apt install pulseaudio-utils)"))
    print("[audio] capturing ~3 s from the microphone…")
    ok, total, peak, backend = await loop.run_in_executor(
        None, _capture_selftest)
    if not ok or total == 0:
        print("[audio] microphone FAILED — no samples via %s. Run /audioprobe "
              "for the per-backend error.%s" % (backend, "" if _host.IS_TERMUX else
              "  (Linux: sudo apt install pulseaudio-utils)"))
        return
    if peak == 0:
        if _host.IS_TERMUX:
            print("[audio] captured %d bytes via %s but pure silence — check "
                  "Settings > Apps > Termux > Permissions > Microphone (the "
                  "Termux app itself, not Termux:API)" % (total, backend))
        else:
            print("[audio] captured %d bytes via %s but pure silence — the "
                  "input may be muted or the wrong one (pavucontrol > Input "
                  "Devices, or: pactl list short sources)" % (total, backend))
        return
    print("[audio] OK — %d bytes via %s, peak amplitude %d"
          % (total, backend, peak))
    voice_ok, reason = voice_available()
    print("[audio] voice subsystem: %s" % ("ready" if voice_ok else reason))
    if not _host.IS_TERMUX and backend == "pulseaudio":
        import otrv4plus_audio as _aud
        try:
            ec = _aud.pulse_device("source", which=_which, env=_termux_env())
        except Exception:
            ec = ""
        if "echo-cancel" in ec:
            print("[audio] echo cancellation: ON (%s)" % ec)
        else:
            print("[audio] echo cancellation: OFF -- on speakers the other "
                  "side hears themselves. Turn it on (until next login):\n"
                  "        %s\n        then restart this client, or use "
                  "headphones." % _aud.ECHO_CANCEL_COMMAND)
