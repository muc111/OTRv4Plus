# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""No function in the clients, the bridge or the apps grows past LIMIT lines.

The long ones were split into named steps and families (dispatch_line was
502 lines, main 460, handle_command 443), and a function that size is where
a branch nobody tests hides. The few still over the limit are listed with
their current length as a ceiling: they may shrink, never grow, and a new
one cannot join them. When one is split, lower or remove its entry.
"""
import ast
import glob
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIMIT = 200

#: (file, qualified name) -> ceiling, with why it is still long.
CEILING = {
    # SMP protocol handling: left whole on purpose, not restructured without
    # a reason in the protocol itself.
    ("client/otrv4+.py", "EnhancedOTRSession._enh_handle_smp_tlv"): 386,
    # The server load test: one async run whose callbacks share its state.
    ("client/otrv4plus_stresstest.py", "run"): 313,
    ("client/otrv4plus_irc.py", "EnhancedOTRv4IRCClient.handle_command"): 223,
    ("client/otrv4plus_irc.py", "_run_input_loop"): 202,
}


def _functions():
    paths = (glob.glob(os.path.join(ROOT, "client", "*.py"))
             + glob.glob(os.path.join(ROOT, "android_bridge", "*.py"))
             + glob.glob(os.path.join(ROOT, "desktop_bridge", "*.py")))
    for path in sorted(paths):
        if os.path.islink(path):
            continue
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        tree = ast.parse(open(path, encoding="utf-8").read())

        def walk(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    yield from walk(child, prefix + child.name + ".")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield rel, prefix + child.name, child.end_lineno - child.lineno + 1
                    yield from walk(child, prefix + child.name + ".")
        yield from walk(tree, "")


def test_no_function_is_longer_than_the_limit_or_its_ceiling():
    over = []
    for rel, name, length in _functions():
        ceiling = CEILING.get((rel, name), LIMIT)
        if length > ceiling:
            over.append("%s %s: %d lines (limit %d)" % (rel, name, length, ceiling))
    assert not over, "split these into named steps:\n  " + "\n  ".join(over)


def test_every_ceiling_still_names_a_function_over_the_limit():
    lengths = {(rel, name): n for rel, name, n in _functions()}
    stale = [k for k in CEILING if lengths.get(k, 0) <= LIMIT]
    assert not stale, "these are now within the limit; remove them from CEILING: %s" % stale


# -- Kotlin (the phone and desktop apps) ---------------------------------------

#: (file, function) -> ceiling. The screens are single composables holding
#: their own state; each section that moves out lowers its number here.
KT_CEILING = {
    ("android/app/src/main/java/org/otrv4plus/android/ui/ConnectScreen.kt", "ConnectScreen"): 206,
    ("android/app/src/main/java/org/otrv4plus/android/MainActivity.kt", "onCreate"): 322,
    ("android/app/src/main/java/org/otrv4plus/android/ui/DevShellScreen.kt", "DevShellScreen"): 246,
}


def _strip_kotlin(src):
    """Code with comment and string contents blanked, newlines kept, read in
    one pass as the compiler does: a "/*" inside a string is not a comment,
    a quote inside a comment is not a string, block comments nest, and a
    string template's ${...} is code again (with strings of its own)."""
    out, i, n = [], 0, len(src)

    def blank(text):
        out.append("".join(c if c == "\n" else " " for c in text))

    def string(i, raw):
        end = '"""' if raw else '"'
        out.append('"')
        i += len(end)
        while i < n:
            if src.startswith(end, i):
                out.append('"')
                return i + len(end)
            if not raw and src[i] == "\\":
                blank(src[i:i + 2])
                i += 2
                continue
            if src.startswith("${", i):
                out.append("  ")
                i = code(i + 2, closing=True)
                continue
            blank(src[i])
            i += 1
        return i

    def code(i, closing=False):
        depth = 0
        while i < n:
            c = src[i]
            if src.startswith("//", i):
                j = src.find("\n", i)
                j = n if j < 0 else j
                blank(src[i:j])
                i = j
            elif src.startswith("/*", i):
                level, j = 1, i + 2
                while j < n and level:
                    if src.startswith("/*", j):
                        level, j = level + 1, j + 2
                    elif src.startswith("*/", j):
                        level, j = level - 1, j + 2
                    else:
                        j += 1
                blank(src[i:j])
                i = j
            elif src.startswith('"""', i):
                i = string(i, raw=True)
            elif c == '"':
                i = string(i, raw=False)
            elif c == "'" and i + 2 < n and (src[i + 2] == "'" or src[i + 1] == "\\"):
                j = src.find("'", i + 2 if src[i + 1] == "\\" else i + 1)
                j = n if j < 0 else j + 1
                blank(src[i:j])
                i = j
            else:
                if closing:
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        if depth == 0:
                            out.append(" ")
                            return i + 1
                        depth -= 1
                out.append(c)
                i += 1
        return i

    code(0)
    return "".join(out)


def _kotlin_functions():
    import re
    paths = (glob.glob(os.path.join(ROOT, "android", "app", "src", "main", "java", "**", "*.kt"),
                       recursive=True)
             + glob.glob(os.path.join(ROOT, "desktop", "src", "main", "kotlin", "**", "*.kt"),
                         recursive=True))
    head = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[A-Za-z0-9_.]+\.)?([A-Za-z0-9_]+)\s*\(")
    for path in sorted(paths):
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        s = _strip_kotlin(open(path, encoding="utf-8").read())
        for m in head.finditer(s):
            i, depth = m.end(), 1
            while i < len(s) and depth:
                depth += {"(": 1, ")": -1}.get(s[i], 0)
                i += 1
            while i < len(s) and s[i] not in "{=":
                i += 1
            if i >= len(s) or s[i] == "=":
                continue                      # an expression body
            depth, end = 0, i
            while end < len(s):
                if s[end] == "{":
                    depth += 1
                elif s[end] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                end += 1
            yield rel, m.group(1), s.count("\n", m.start(), end) + 1


def test_the_kotlin_scan_sees_the_screens():
    names = {(rel, name) for rel, name, _ in _kotlin_functions()}
    assert set(KT_CEILING) <= names, set(KT_CEILING) - names


def test_no_kotlin_function_is_longer_than_the_limit_or_its_ceiling():
    over = []
    for rel, name, length in _kotlin_functions():
        ceiling = KT_CEILING.get((rel, name), LIMIT)
        if length > ceiling:
            over.append("%s %s: %d lines (limit %d)" % (rel, name, length, ceiling))
    assert not over, "split these into smaller composables or steps:\n  " + "\n  ".join(over)


def test_every_kotlin_ceiling_still_names_a_function_over_the_limit():
    longest = {}
    for rel, name, n in _kotlin_functions():
        longest[(rel, name)] = max(n, longest.get((rel, name), 0))
    stale = [k for k in KT_CEILING if longest.get(k, 0) <= LIMIT]
    assert not stale, "now within the limit; remove from KT_CEILING: %s" % stale
