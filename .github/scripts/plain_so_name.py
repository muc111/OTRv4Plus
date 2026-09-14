#!/usr/bin/env python3
"""Rename the extension module inside a wheel to a plain `.so`.

WHY
---
maturin names an abi3 extension `otrv4_core/otrv4_core.abi3.so`. On a handset
that produced:

    rust_core:
      error: ModuleNotFoundError
      detail: cannot import otrv4_core.otrv4_core
      where:
        - __init__.py:1 in <module>

The package was found -- its `__init__.py` executed -- and the sibling
extension beside it was not. Meanwhile every extension that DOES load in that
process is named plainly:

    _bz2.so  _ctypes.so  _datetime.so  math.so  zlib.so ...

Chaquopy ships those as `_bz2.cpython-312.so` inside its target zip and they
arrive on the device as `_bz2.so`, so its runtime normalises extension
filenames to a bare `.so` and then looks for exactly that. A file carrying the
`.abi3` infix is not what it goes looking for.

WHY THIS IS SAFE WHETHER OR NOT THAT DIAGNOSIS IS EXACTLY RIGHT
---------------------------------------------------------------
`.so` is unconditionally present in CPython's extension-suffix table on POSIX
(`_PyImport_DynLoadFiletab`), on every build, alongside `.abi3.so` and the
full SOABI form. So a plainly-named extension is importable anywhere the
suffixed one would have been, and importable in at least one place it is not.
The rename cannot cost anything; it can only remove a way to fail.

It does NOT change the binary. The file is byte-identical -- this is a name in
a zip entry, and the corresponding line in RECORD.
"""

import base64
import csv
import hashlib
import io
import os
import re
import sys
import zipfile

#: What we rewrite: an abi3 or full-SOABI infix immediately before `.so`.
SUFFIXED = re.compile(r"^(?P<stem>.+?)\.(?:abi3|cpython-\d+[\w-]*)\.so$")


def plain(name: str) -> str:
    """`pkg/mod.abi3.so` -> `pkg/mod.so`; anything else unchanged."""
    head, tail = os.path.split(name)
    m = SUFFIXED.match(tail)
    if not m:
        return name
    return os.path.join(head, m.group("stem") + ".so")


def record_line(path: str, data: bytes):
    """A RECORD row: path, sha256=<urlsafe b64, unpadded>, size."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
    return [path, "sha256=" + digest.decode("ascii").rstrip("="), str(len(data))]


def rewrite(wheel: str) -> int:
    with zipfile.ZipFile(wheel) as zf:
        items = [(i, zf.read(i.filename)) for i in zf.infolist()]

    renames = {i.filename: plain(i.filename)
               for i, _ in items if plain(i.filename) != i.filename}
    if not renames:
        print("no suffixed extension in %s; nothing to do" % wheel)
        return 0
    for old, new in renames.items():
        print("  %s -> %s" % (old, new))

    # RECORD must be rebuilt, not string-replaced: the hash stays the same
    # because the bytes do, but pip reads the PATH column and a stale one
    # leaves an entry pointing at a file that is no longer there.
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        record_name = None
        rows = []
        for info, data in items:
            name = renames.get(info.filename, info.filename)
            if name.endswith("/RECORD"):
                record_name = name
                continue                       # written last, once complete
            new_info = zipfile.ZipInfo(name, date_time=info.date_time)
            new_info.external_attr = info.external_attr
            new_info.compress_type = info.compress_type
            zf.writestr(new_info, data)
            rows.append(record_line(name, data))
        if record_name is None:
            raise SystemExit("%s has no RECORD; refusing to guess" % wheel)
        rows.append([record_name, "", ""])     # RECORD itself, per PEP 427
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(rows)
        zf.writestr(record_name, buf.getvalue())

    with open(wheel, "wb") as f:
        f.write(out.getvalue())
    return len(renames)


def main(argv):
    if len(argv) < 2:
        raise SystemExit("usage: plain_so_name.py <wheel> [<wheel> ...]")
    total = 0
    for wheel in argv[1:]:
        print("== %s" % wheel)
        total += rewrite(wheel)

    # Prove it, rather than trust the loop above.
    for wheel in argv[1:]:
        with zipfile.ZipFile(wheel) as zf:
            bad = [n for n in zf.namelist()
                   if n.endswith(".so") and plain(n) != n]
            if bad:
                raise SystemExit("still suffixed after rewrite: %s" % bad)
            sos = [n for n in zf.namelist() if n.endswith(".so")]
            if not sos:
                raise SystemExit(
                    "%s contains no .so at all -- the wheel has no extension "
                    "module, which is not something to publish quietly" % wheel)
            print("%s: %s" % (wheel, ", ".join(sos)))
    print("renamed %d entr%s" % (total, "y" if total == 1 else "ies"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
