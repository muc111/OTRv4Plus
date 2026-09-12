"""Development diagnostics for the Android integration (Phase 2, §6).

Answers exactly one question: did the Kotlin -> Chaquopy -> Python -> Rust
stack come up on this device?  That is the Phase 2 milestone, and it is not
"the messenger works".

Safety rules this module enforces rather than assumes:

  * Never reports a private key, seed, password, session secret, ratchet state
    or message body.  The only key-derived value it will surface is a public
    fingerprint, and only truncated.
  * `collect()` returns plain JSON-safe types, so the Kotlin side can render it
    without reaching back into Python objects.
  * Every probe is individually guarded: a diagnostic screen that crashes while
    reporting why something failed is worse than useless.

The screen that renders this is debug-only and is stripped from release builds
(see android/app/src/release/ and the isDebug guard in the Compose entry point).
`collect()` itself is safe to call in any build -- it is the screen, not the
data, that is withheld.
"""

from __future__ import annotations

import os
import platform
import sys
from typing import Any, Dict, List, Optional

__all__ = ["collect", "SENSITIVE_KEY_HINTS"]

# Substrings that must never appear in a diagnostics key or value.  Asserted by
# tests/test_android_diagnostics.py against real collected output.
SENSITIVE_KEY_HINTS = (
    "seed", "private", "secret", "password", "passphrase", "credential",
    "session_key", "chain_key", "root_key", "brace_key", "mac_key", "ratchet",
)


def _guard(fn, default=None):
    try:
        return fn()
    except Exception as exc:
        return default if default is not None else f"unavailable ({type(exc).__name__})"


def _python_info() -> Dict[str, Any]:
    version = sys.version_info
    return {
        "version": f"{version.major}.{version.minor}.{version.micro}",
        "meets_3_12_requirement": (version.major, version.minor) >= (3, 12),
        "implementation": _guard(platform.python_implementation),
        "abi_platform": _guard(lambda: sys.platform),
    }


def _abi_info() -> Dict[str, Any]:
    """Which native ABI this process is actually running.

    On Android the authoritative answer is android.os.Build.SUPPORTED_ABIS from
    Kotlin; this is the Python-visible view, which is what matters for loading
    the right otrv4_core .so.
    """
    machine = _guard(platform.machine, default="unknown")
    android_abi = {
        "aarch64": "arm64-v8a",
        "arm64": "arm64-v8a",
        "armv7l": "armeabi-v7a",
        "armv8l": "armeabi-v7a",
        "x86_64": "x86_64",
        "i686": "x86",
    }.get(str(machine), None)
    return {
        "machine": machine,
        "android_abi": android_abi or f"non-android ({machine})",
        "pointer_bits": 64 if sys.maxsize > 2 ** 32 else 32,
    }


def _rust_core_info() -> Dict[str, Any]:
    """Whether otrv4_core loaded, and what it exposes.

    Reports the presence of required entry points by name only.  Absence of a
    name is a real diagnostic signal (a stale .so), so the list is useful; the
    names themselves are public API and carry nothing sensitive.
    """
    info: Dict[str, Any] = {"loaded": False}
    try:
        import otrv4_core
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}"
        return info

    info["loaded"] = True
    info["module_file"] = _guard(lambda: os.path.basename(getattr(otrv4_core, "__file__", "") or "builtin"))

    required = [
        "Ed448KeyHandle", "X448KeyHandle", "RustDAKE", "RustSMP", "RustSMPVault",
        "RustDoubleRatchet", "generate_ed448_keypair", "generate_x448_keypair",
        "verify_ed448_sig", "aes256gcm_encrypt", "aes256gcm_decrypt",
        "mlkem1024_keygen", "mlkem1024_encaps", "mlkem1024_decaps",
        "mldsa87_keygen", "mldsa87_sign", "mldsa87_verify",
        "py_ring_sign", "py_ring_verify",
    ]
    present = [name for name in required if hasattr(otrv4_core, name)]
    info["required_symbols_present"] = len(present)
    info["required_symbols_total"] = len(required)
    info["missing_symbols"] = [n for n in required if n not in present]

    # The release-boundary check, surfaced where a developer will see it.
    info["test_gates_open"] = bool(_guard(
        lambda: hasattr(otrv4_core.RustSMPVault, "load"), default=False))
    return info


def _rust_selftest() -> Dict[str, Any]:
    """Actually exercise the Rust core, rather than only importing it.

    A loaded .so that cannot perform an operation is the failure mode worth
    catching on a real device: wrong ABI, stale build, missing CPU feature.
    Uses public test vectors and throwaway keys only -- nothing here is or
    becomes real key material.
    """
    result: Dict[str, Any] = {"ran": False}
    try:
        import otrv4_core
    except Exception:
        result["error"] = "core not loaded"
        return result

    try:
        handle = otrv4_core.generate_ed448_keypair()
        pub = bytes(handle.public_bytes())
        sig = bytes(handle.sign(b"otrv4plus-android-selftest"))
        result["ed448_sign_verify"] = bool(
            otrv4_core.verify_ed448_sig(pub, b"otrv4plus-android-selftest", sig))

        ek, dk = otrv4_core.mlkem1024_keygen()
        ct, ss1 = otrv4_core.mlkem1024_encaps(bytes(ek))
        ss2 = otrv4_core.mlkem1024_decaps(bytes(ct), bytes(dk))
        result["mlkem1024_roundtrip"] = bytes(ss1) == bytes(ss2)

        key = b"\x00" * 32
        nonce = b"\x00" * 12
        sealed = otrv4_core.aes256gcm_encrypt(key, nonce, b"probe", b"aad")
        opened = otrv4_core.aes256gcm_decrypt(key, nonce, bytes(sealed), b"aad")
        result["aes256gcm_roundtrip"] = bytes(opened) == b"probe"

        result["ran"] = True
        result["all_passed"] = all(
            v is True for k, v in result.items()
            if k.endswith(("_verify", "_roundtrip")))
    except Exception as exc:
        result["error"] = type(exc).__name__
        result["all_passed"] = False
    return result


def _otrv4plus_info() -> Dict[str, Any]:
    """Whether the Python orchestration layer imports and initialises.

    This is the part that fails first on Android: otrv4+.py pulls in Termux-only
    modules and requires Python 3.12+ for its PEP 701 f-strings.
    """
    info: Dict[str, Any] = {"imported": False}
    try:
        import otrv4_ as otr
    except Exception as exc:
        # `type(exc).__name__` alone used to be the whole story here, and on
        # the first handset that ran this app it reported "SyntaxError" with
        # no hint of which file or line -- true, and useless. failure.describe
        # adds a classified detail and `file:line in func` frames while still
        # refusing to print an arbitrary exception message.
        from . import failure
        described = failure.describe(exc)
        info["error"] = described["code"]
        info["detail"] = described["detail"] or "orchestration layer did not import"
        info["where"] = described["frames"]
        if described["caused_by"]:
            info["caused_by"] = described["caused_by"]
        return info

    info["imported"] = True
    info["has_session_manager"] = hasattr(otr, "EnhancedSessionManager")

    try:
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        fingerprint = engine.get_fingerprint() or ""
        info["engine_constructed"] = True
        # Public fingerprint, truncated: enough to confirm an identity exists and
        # to eyeball stability across restarts, useless as key material.
        info["fingerprint_prefix"] = fingerprint[:16]
        info["initialized"] = True
    except Exception as exc:
        info["engine_constructed"] = False
        info["initialized"] = False
        info["error"] = type(exc).__name__
    return info


def _native_libraries(search_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    """List loadable native libraries the app ships.

    Names only -- never paths outside the app's own directories, so this cannot
    be used to map the device.
    """
    paths = search_paths if search_paths is not None else [
        p for p in sys.path if isinstance(p, str) and p
    ]
    found: List[str] = []
    for path in paths[:40]:
        try:
            if not os.path.isdir(path):
                continue
            for entry in os.listdir(path):
                if entry.endswith(".so") and entry not in found:
                    found.append(entry)
        except Exception:
            continue
    return {"count": len(found), "names": sorted(found)[:40]}


def collect(include_selftest: bool = True,
            android_build: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Gather the Phase 2 diagnostic report.

    `android_build` is supplied by Kotlin (Build.VERSION.SDK_INT, RELEASE,
    SUPPORTED_ABIS, MODEL); Python cannot read those, and they are passed in
    rather than guessed.
    """
    report: Dict[str, Any] = {
        "android": android_build or {"note": "not supplied by host (not running on Android)"},
        "python": _python_info(),
        "abi": _abi_info(),
        "rust_core": _rust_core_info(),
        "otrv4plus": _otrv4plus_info(),
        "native_libraries": _native_libraries(),
    }
    if include_selftest:
        report["rust_selftest"] = _rust_selftest()

    report["ok"] = bool(
        report["python"].get("meets_3_12_requirement")
        and report["rust_core"].get("loaded")
        and not report["rust_core"].get("missing_symbols")
        and report["otrv4plus"].get("initialized")
        and (not include_selftest or report.get("rust_selftest", {}).get("all_passed"))
    )
    return report


def as_text(report: Optional[Dict[str, Any]] = None, **collect_kwargs) -> str:
    """Render the report as flat text, for export off the device.

    WHY THIS IS HERE AND NOT IN KOTLIN
    ----------------------------------
    The rule this module enforces is about CONTENT, and content is decided
    here. A renderer on the Kotlin side would be a second place that decides
    what a diagnostic says, and the first time someone adds a field it would
    be the place that forgot the rule. So the text is built next to the data,
    and `SENSITIVE_KEY_HINTS` is applied to the finished string rather than
    trusted to have been applied upstream.

    That last part is the real point: this is a belt-and-braces pass over
    output that is already supposed to be safe. A key whose name trips a hint
    is redacted here even though nothing should have produced it, because the
    cost of the check is nothing and the cost of being wrong is a secret in a
    file the user is about to upload to a bug tracker.
    """
    if report is None:
        report = collect(**collect_kwargs)

    lines: List[str] = ["OTRv4+ Android diagnostic report", ""]

    def render(value: Any, indent: int, key: str = "") -> None:
        pad = "  " * indent
        if isinstance(value, dict):
            for k in value:
                if _is_sensitive(str(k)):
                    lines.append("%s%s: <redacted>" % (pad, k))
                    continue
                v = value[k]
                if isinstance(v, (dict, list)):
                    lines.append("%s%s:" % (pad, k))
                    render(v, indent + 1, str(k))
                else:
                    lines.append("%s%s: %s" % (pad, k, v))
        elif isinstance(value, list):
            if not value:
                lines.append("%s(none)" % pad)
            for item in value:
                if isinstance(item, (dict, list)):
                    render(item, indent + 1, key)
                else:
                    lines.append("%s- %s" % (pad, item))
        else:
            lines.append("%s%s" % (pad, value))

    render(report, 0)
    return "\n".join(lines) + "\n"


def _is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SENSITIVE_KEY_HINTS)
