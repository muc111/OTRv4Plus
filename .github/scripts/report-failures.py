#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Failed Gradle tests (and the tail of the build log) as ::error annotations,
readable through the API where the job log is not."""
import glob
import sys
import xml.etree.ElementTree as ET


def esc(text):
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


n = 0
for path in glob.glob("desktop/build/test-results/test/TEST-*.xml"):
    for case in ET.parse(path).getroot().iter("testcase"):
        for bad in list(case.findall("failure")) + list(case.findall("error")):
            text = (bad.get("message") or "") + "\n" + (bad.text or "")
            print("::error title=%s.%s::%s" % (case.get("classname"), case.get("name"), esc(text[:3500])))
            n += 1
if n == 0 and len(sys.argv) > 1:
    try:
        lines = open(sys.argv[1], errors="replace").read().splitlines()[-40:]
        print("::error title=build log tail::%s" % esc("\n".join(lines)[-3800:]))
    except OSError:
        pass
