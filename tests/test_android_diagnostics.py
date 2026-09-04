#!/usr/bin/env python3
"""Diagnostics and bootstrap tests (Phase 2, §6 and §8).

The diagnostic screen is the Phase 2 milestone's evidence: it is what a real
device shows to prove Kotlin -> Chaquopy -> Python -> Rust came up. Two things
therefore need testing: that it reports the right things, and that it reports
nothing it must not.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from android_bridge import bootstrap, diagnostics          # noqa: E402
from android_bridge.diagnostics import SENSITIVE_KEY_HINTS  # noqa: E402


@pytest.fixture(scope="module")
def report():
    return diagnostics.collect()


class TestDiagnosticsContent:

    def test_reports_python_version_and_the_312_requirement(self, report):
        py = report["python"]
        assert py["version"].startswith(f"{sys.version_info.major}.{sys.version_info.minor}")
        assert py["meets_3_12_requirement"] is (sys.version_info[:2] >= (3, 12))

    def test_reports_abi(self, report):
        abi = report["abi"]
        assert abi["machine"]
        assert abi["pointer_bits"] in (32, 64)
        assert "android_abi" in abi

    def test_reports_rust_core_load_status_and_symbol_completeness(self, report):
        core = report["rust_core"]
        assert core["loaded"] is True, "otrv4_core must be importable for these tests"
        assert core["required_symbols_present"] == core["required_symbols_total"]
        assert core["missing_symbols"] == []

    def test_reports_orchestration_status(self, report):
        # bootstrap must have made otrv4_ importable
        bootstrap.load_orchestration()
        fresh = diagnostics.collect(include_selftest=False)
        assert fresh["otrv4plus"]["imported"] is True
        assert fresh["otrv4plus"]["initialized"] is True

    def test_selftest_actually_exercises_rust(self, report):
        """Importing the .so is not proof it works on this ABI."""
        st = report["rust_selftest"]
        assert st["ran"] is True
        assert st["ed448_sign_verify"] is True
        assert st["mlkem1024_roundtrip"] is True
        assert st["aes256gcm_roundtrip"] is True
        assert st["all_passed"] is True

    def test_overall_ok_flag_is_true_on_a_healthy_stack(self):
        bootstrap.load_orchestration()
        assert diagnostics.collect()["ok"] is True

    def test_surfaces_whether_test_gates_are_open(self, report):
        """A developer must be able to see they are on a non-shippable build."""
        import otrv4_core
        assert report["rust_core"]["test_gates_open"] is hasattr(
            otrv4_core.RustSMPVault, "load")

    def test_report_is_json_serialisable(self, report):
        json.dumps(report)          # must not raise: Kotlin renders this


class TestDiagnosticsLeakNothing:

    def _walk(self, node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield f"{path}.{k}", k, v
                yield from self._walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield f"{path}[{i}]", None, v
                yield from self._walk(v, f"{path}[{i}]")

    def test_no_sensitive_key_names(self, report):
        for path, key, _ in self._walk(report):
            if key is None:
                continue
            low = key.lower()
            for hint in SENSITIVE_KEY_HINTS:
                # `test_gates_open` legitimately mentions nothing sensitive;
                # guard against real key names only.
                assert hint not in low, f"diagnostics key {path} looks sensitive"

    def test_no_long_hex_blobs_anywhere(self, report):
        """A leaked key would show up as a long hex or base64 run."""
        import re
        blob = json.dumps(report)
        for match in re.findall(r"[0-9a-fA-F]{40,}", blob):
            pytest.fail(f"diagnostics contain a long hex run: {match[:24]}...")

    def test_fingerprint_is_truncated(self, report):
        bootstrap.load_orchestration()
        fresh = diagnostics.collect(include_selftest=False)
        prefix = fresh["otrv4plus"].get("fingerprint_prefix", "")
        assert len(prefix) <= 16, "only a short public fingerprint prefix may be shown"

    def test_native_library_listing_has_no_paths(self, report):
        for name in report["native_libraries"]["names"]:
            assert "/" not in name, "library listing must be names only, not paths"


class TestBootstrap:

    def test_load_is_idempotent(self):
        first = bootstrap.load_orchestration()
        second = bootstrap.load_orchestration()
        assert first is second, "module must not be executed twice"

    def test_registers_both_aliases(self):
        bootstrap.load_orchestration()
        assert sys.modules.get("otrv4_") is sys.modules.get("otrv4plus")

    def test_python_floor_is_312_and_documented(self):
        assert bootstrap.MIN_PYTHON == (3, 12)

    def test_ensure_runtime_rejects_old_python(self, monkeypatch):
        """The 3.12 floor must fail loudly, not as a SyntaxError deep in an import."""
        import collections
        fake = collections.namedtuple("v", "major minor micro")(3, 11, 9)
        monkeypatch.setattr(sys, "version_info", fake)
        with pytest.raises(bootstrap.RuntimeUnsupported) as exc:
            bootstrap.ensure_runtime()
        assert "3.12" in str(exc.value)

    def test_required_modules_are_the_measured_set(self):
        assert set(bootstrap.REQUIRED_MODULES) == {"otrv4_core", "socks"}

    def test_missing_required_module_is_reported_by_name(self, monkeypatch):
        import importlib.util as iu
        real = iu.find_spec
        monkeypatch.setattr(iu, "find_spec",
                            lambda n, *a, **k: None if n == "socks" else real(n, *a, **k))
        with pytest.raises(bootstrap.RuntimeUnsupported) as exc:
            bootstrap.ensure_runtime()
        assert "socks" in str(exc.value)

    def test_optional_dependencies_are_reported_not_fatal(self):
        assert isinstance(bootstrap.missing_optional(), list)
