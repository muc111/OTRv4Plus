#!/usr/bin/env python3
"""What the clients require of the compiled core, checked before they need it.

WHY THIS EXISTS
===============
`otrv4_core` is a separately versioned compiled artefact.  `git pull` updates
the Python; only rebuilding the core updates the core -- `cargo build` plus the
`.so` copy on Termux, or `pip install ./Rust` where maturin exists.  Nothing
used to check that the two agreed, and the first thing to notice was SMP:

    [smp] start error: SMP start failed: 'builtins.RustSMPVault'
          object has no attribute 'store_from_bytearray'

`store_from_bytearray` is the correct API -- it takes the passphrase buffer and
zeroes it in place, instead of `store(bytes(raw))`, which made an immutable copy
the caller could not wipe.  It shipped in otrv4_core 0.10.25.  The handset was
running client 10.14.0 against an older core, and found out inside an executor
thread at the first verification attempt, two layers of RuntimeError deep, in a
message that read like the protocol had failed.

The fix is not a Python shim restoring the old method: that would reinstate the
unwipeable copy this project deliberately removed.  The fix is to state what the
client needs, check it at startup, and say plainly what to rebuild.

MAINTENANCE
===========
Adding a call to a core method that older builds lack means adding it here.
`tests/test_core_api_contract.py` reads the client sources and fails if a call
site exists that this manifest does not cover, so the two cannot drift.
"""

from typing import List, Tuple

# (class or None for module level, attribute, the version that introduced it)
#
# Only entries whose absence actually breaks a client belong here.  This is a
# compatibility floor, not an inventory of the module.
REQUIRED_CORE_API: Tuple[Tuple[str, str, str], ...] = (
    # The SMP secret path.  store_from_bytearray is the one that regressed.
    ("RustSMPVault", "store_from_bytearray", "0.10.25"),
    ("RustSMPVault", "store",                "0.9.0"),
    ("RustSMPVault", "has",                  "0.9.0"),
    ("RustSMPVault", "remove",               "0.9.0"),
    ("RustSMPVault", "clear",                "0.9.0"),

    # The SMP engine, including the held-SMP1 state the guided flow needs.
    ("RustSMP", "set_secret_from_vault",             "0.9.0"),
    ("RustSMP", "set_secret_from_bytearray",         "0.9.0"),
    ("RustSMP", "check_secret_set",                  "0.9.0"),
    ("RustSMP", "get_phase",                         "0.9.0"),
    ("RustSMP", "generate_smp1",                     "0.9.0"),
    ("RustSMP", "process_smp1_generate_smp2",        "0.9.0"),
    ("RustSMP", "process_smp2_generate_smp3",        "0.9.0"),
    ("RustSMP", "process_smp3_generate_smp4",        "0.9.0"),
    ("RustSMP", "process_smp4",                      "0.9.0"),
    ("RustSMP", "abort",                             "0.9.0"),
    ("RustSMP", "hold_smp1",                         "0.10.27"),
    ("RustSMP", "has_held_smp1",                     "0.10.27"),
    ("RustSMP", "resume_held_smp1_generate_smp2",    "0.10.27"),
    ("RustSMP", "discard_held_smp1",                 "0.10.27"),
)

# Two supported ways to build the core, and the message must name the one the
# reader is actually using.  Termux is the .so copy (README "Build the Rust
# core"); a development machine with maturin can use the wheel.  An earlier
# version of this hint named only the wheel, which on a phone sends the user
# to a toolchain they do not have.
REBUILD_HINT = (
    "The compiled core is older than this client. Rebuild it:\n"
    "\n"
    "  cd ~/OTRv4Plus/Rust\n"
    "  cargo build --release --features extension-module,pq-rust\n"
    "  cp target/release/libotrv4_core.so ../otrv4_core.so\n"
    "\n"
    "or, where maturin is available:\n"
    "\n"
    "  cd ~/OTRv4Plus && python3 -m pip install --break-system-packages ./Rust\n"
    "\n"
    "Then start the client again."
)


class CoreApiMismatch(RuntimeError):
    """The installed otrv4_core lacks something the client calls."""


def missing_core_api(core=None) -> List[str]:
    """Return a description of each required attribute the core lacks.

    Takes the module as an argument so a test can pass a deliberately
    incomplete stand-in without touching the real import.
    """
    if core is None:
        import otrv4_core as core            # noqa: PLC0415  (deliberately late)

    missing = []
    for owner, attr, since in REQUIRED_CORE_API:
        target = getattr(core, owner, None) if owner else core
        if target is None:
            missing.append(f"{owner} (whole class) — since otrv4_core {since}")
        elif not hasattr(target, attr):
            name = f"{owner}.{attr}" if owner else attr
            missing.append(f"{name} — since otrv4_core {since}")
    return missing


def verify_core_api(core=None, on_message=print) -> bool:
    """True when the core provides everything.  Otherwise report and return False.

    Deliberately does not raise by default: a client that cannot do SMP can
    still carry messages, and killing the process would take away the channel
    the user needs in order to be told what is wrong.  Callers that genuinely
    cannot proceed use `require_core_api`.
    """
    missing = missing_core_api(core)
    if not missing:
        return True
    on_message("[core] This build of otrv4_core is missing "
               f"{len(missing)} thing(s) this client uses:")
    for item in missing:
        on_message(f"[core]   {item}")
    for line in REBUILD_HINT.splitlines():
        on_message(f"[core] {line}")
    on_message("[core] Verification (SMP) and anything relying on it will "
               "not work until then.")
    return False


def require_core_api(core=None) -> None:
    """Raise CoreApiMismatch naming what is missing and how to fix it."""
    missing = missing_core_api(core)
    if missing:
        raise CoreApiMismatch(
            "otrv4_core is out of date; missing: "
            + ", ".join(missing) + ".\n" + REBUILD_HINT)
