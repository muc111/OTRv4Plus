# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The MLS size bounds are the same on both sides of the binding.

android_bridge/groups.py decodes every MLS frame to a bound before it
reaches Rust, and Rust/src/mls_group.rs refuses anything larger again. When
the two disagreed, a raised Rust bound did nothing (Python still refused at
~1.5 MiB) and the documented limit was not the real one. Each input now has
its own bound, the same number on both sides:

    key package   64 KiB   (a real one is ~15 KiB)
    room message   1 MiB   (application message or commit)
    Welcome        4 MiB   (carries the ratchet tree; authenticated 1:1)
"""

import ast
import base64
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST = os.path.join(ROOT, "Rust", "src", "mls_group.rs")
GROUPS = os.path.join(ROOT, "android_bridge", "groups.py")

groups = pytest.importorskip("android_bridge.groups")

# Rust constant -> Python constant, and the value both must have.
PAIRS = {
    "MAX_KEY_PACKAGE": ("MAX_KEY_PACKAGE", 64 * 1024),
    "MAX_ROOM_MESSAGE": ("MAX_ROOM_MESSAGE", 1024 * 1024),
    "MAX_WELCOME": ("MAX_WELCOME", 4 * 1024 * 1024),
}


def _eval_const(expr: str) -> int:
    """Evaluate a Rust integer constant built from literals, `<<` and `*`."""
    def ev(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.LShift, ast.Mult)):
            a, b = ev(node.left), ev(node.right)
            return a << b if isinstance(node.op, ast.LShift) else a * b
        raise ValueError("unsupported constant expression: %r" % expr)
    return ev(ast.parse(expr.replace("_", ""), mode="eval").body)


def _rust_consts():
    src = open(RUST, encoding="utf-8").read()
    return {m.group(1): _eval_const(m.group(2))
            for m in re.finditer(r"const (MAX_\w+): usize = ([^;]+);", src)}


def test_rust_and_python_bounds_are_the_same_numbers():
    rust = _rust_consts()
    for rust_name, (py_name, want) in PAIRS.items():
        assert rust.get(rust_name) == want, (rust_name, rust.get(rust_name))
        assert getattr(groups, py_name) == want, (py_name, getattr(groups, py_name))


def test_the_rust_binding_checks_each_input_against_its_own_bound():
    src = open(RUST, encoding="utf-8").read()
    assert 'bounded(kp, MAX_KEY_PACKAGE, "key package")' in src
    assert 'bounded(key_package, MAX_KEY_PACKAGE, "key package")' in src
    assert 'bounded(welcome, MAX_WELCOME, "welcome")' in src
    assert 'bounded(message, MAX_ROOM_MESSAGE, "message")' in src
    assert "MAX_MESSAGE:" not in src, "the old shared bound is back"


def test_every_python_decode_names_its_bound():
    tree = ast.parse(open(GROUPS, encoding="utf-8").read())
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_b64d"]
    assert calls, "no _b64d call sites found"
    for c in calls:
        assert len(c.args) == 2 and isinstance(c.args[1], ast.Name), ast.dump(c)
        assert c.args[1].id.startswith("MAX_"), c.args[1].id


@pytest.mark.parametrize("name", ["MAX_KEY_PACKAGE", "MAX_ROOM_MESSAGE", "MAX_WELCOME"])
def test_decode_accepts_the_bound_and_refuses_one_byte_more(name):
    limit = getattr(groups, name)
    assert len(groups._b64d(base64.b64encode(b"\x00" * limit).decode(), limit)) == limit
    with pytest.raises(ValueError):
        groups._b64d(base64.b64encode(b"\x00" * (limit + 1)).decode(), limit)
