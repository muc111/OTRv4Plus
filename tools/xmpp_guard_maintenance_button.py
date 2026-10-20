#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Add a maintenance-mode on/off button to an installed XMPP Guard (3.1.x).

Owner (2026-10-20): "i keep forgetting to put it on maintenance mode when
running tests or editing files can we add a button on the webconsole".

    sudo touch /var/lib/i2pd-dash/maintenance        # so this edit doesn't alarm
    sudo python3 tools/xmpp_guard_maintenance_button.py /opt/i2pd-dash
    sudo systemctl restart i2pd-dash

What it adds:
  * POST /api/maintenance {"on": true|false}: creates or removes
    <state_dir>/maintenance, exactly what `sudo touch` / `sudo rm` did. It
    still expires by itself after maintenance_minutes. Every use is written
    to the security log.
  * A button under "Server defences".

WHY IT IS SAFE TO HAVE A BUTTON. The dashboard was read-only; a button that
pauses tamper alerts is worth stealing. Any web page open in the same
browser could POST to 127.0.0.1:7071, so the endpoint requires:
  - a random token that exists only in the page the dashboard served this
    run (sent as the X-Guard-Token header; a header other sites cannot set
    without a CORS preflight, which this server never answers);
  - a same-origin Origin header when the browser sends one;
  - the dashboard's own password, if [dashboard] user/password is set.

The patch is applied only if every anchor it needs is found; otherwise
nothing is written. Both files are backed up next to themselves
(*.bak-maint). Running it twice changes nothing.
"""
import os
import py_compile
import shutil
import sys

MARK = "/api/maintenance"

PY_EDITS = [
    # A token for this run, and the page carries it.
    ('    index_path = os.path.join(HERE, "static", "index.html")\n',
     '    index_path = os.path.join(HERE, "static", "index.html")\n'
     '    import secrets as _secrets\n'
     '    guard_token = _secrets.token_urlsafe(32)\n'),
    ('                        self._send(200, f.read(), "text/html; charset=utf-8")\n',
     '                        page = f.read().replace(b"<head>", b\'<head><meta name="guard-token" content="\'\n'
     '                                                + guard_token.encode() + b\'">\', 1)\n'
     '                        self._send(200, page, "text/html; charset=utf-8")\n'),
    # The endpoint.
    ('        def stream(self):\n',
     '        def do_POST(self):\n'
     '            if not self._auth():\n'
     '                return\n'
     '            path = self.path.split("?", 1)[0]\n'
     '            if path != "/api/maintenance":\n'
     '                return self._send(404, "not found", "text/plain")\n'
     '            if not hmac.compare_digest(self.headers.get("X-Guard-Token", "").encode(), guard_token.encode()):\n'
     '                return self._send(403, "bad token: reload the page", "text/plain")\n'
     '            origin, host = self.headers.get("Origin"), self.headers.get("Host", "")\n'
     '            if origin is not None and origin != "http://" + host:\n'
     '                return self._send(403, "cross-origin request refused", "text/plain")\n'
     '            try:\n'
     '                n = int(self.headers.get("Content-Length", "0"))\n'
     '                want = json.loads(self.rfile.read(n).decode() if 0 < n <= 256 else "{}")["on"]\n'
     '            except Exception:\n'
     '                return self._send(400, "expected {\\"on\\": true|false}", "text/plain")\n'
     '            ok, msg = col.set_maintenance(bool(want))\n'
     '            self._send(200 if ok else 409, json.dumps({"ok": ok, "message": msg,\n'
     '                                                       "maintenance": col.maintenance()}),\n'
     '                       "application/json")\n'
     '\n'
     '        def stream(self):\n'),
    # The collector does it, and says so in the security log.
    ('    def accept_baseline(self):\n',
     '    def set_maintenance(self, on):\n'
     '        """Turn maintenance mode on or off from the dashboard (the same\n'
     '        <state_dir>/maintenance file as `sudo touch`). Logged either way."""\n'
     '        if self._maint_cfg:\n'
     '            return False, "maintenance = true is set in config.ini; change it there"\n'
     '        if not self.store.dir:\n'
     '            return False, "no state_dir: XMPP Guard keeps no files, so there is nothing to switch"\n'
     '        f = os.path.join(self.store.dir, "maintenance")\n'
     '        try:\n'
     '            if on:\n'
     '                with open(f, "a"):\n'
     '                    pass\n'
     '                os.utime(f, None)\n'
     '            elif os.path.exists(f):\n'
     '                os.remove(f)\n'
     '        except OSError as e:\n'
     '            return False, f"could not change {f}: {e.strerror}"\n'
     '        mins = int(self._maint_window // 60)\n'
     '        if on:\n'
     '            self.event("warning", "system", f"Maintenance mode turned ON from the dashboard "\n'
     '                       f"(file-integrity alerts paused; switches off by itself in {mins} min)", persist=True)\n'
     '        else:\n'
     '            self.event("info", "system", "Maintenance mode turned OFF from the dashboard", persist=True)\n'
     '        self.sentinel["maintenance"] = self.maintenance()\n'
     '        return True, ("on for " + str(mins) + " min") if on else "off"\n'
     '\n'
     '    def accept_baseline(self):\n'),
]

HTML_EDITS = [
    # The button, under the maintenance banner (shown on and off).
    ('  $("#defAlarm").innerHTML = alarm;\n',
     '  alarm += `<div style="margin-top:8px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">'
     '<button id="maintBtn" data-on="${se.maintenance ? 1 : 0}" style="padding:6px 12px;border-radius:6px;'
     'border:1px solid var(--warning);background:${se.maintenance ? "var(--warning)" : "transparent"};'
     'color:${se.maintenance ? "#000" : "var(--warning)"};cursor:pointer;font-weight:600">'
     '${se.maintenance ? "Turn maintenance off" : "Turn maintenance on"}</button>'
     '<span id="maintMsg" style="opacity:.8">${se.maintenance ? "File-integrity alerts are paused." : '
     '"Turn on before editing configs or running a stress test; it switches off by itself."}</span></div>`;\n'
     '  $("#defAlarm").innerHTML = alarm;\n'),
    # Its click handler, once for the page.
    ('</script>',
     'document.addEventListener("click", async (e) => {\n'
     '  const b = e.target.closest && e.target.closest("#maintBtn");\n'
     '  if (!b) return;\n'
     '  const on = b.dataset.on !== "1", msg = document.getElementById("maintMsg");\n'
     '  if (!on && !confirm("Turn maintenance mode off? File-integrity alerts come back on.")) return;\n'
     '  b.disabled = true;\n'
     '  try {\n'
     '    const t = (document.querySelector(\'meta[name="guard-token"]\') || {}).content || "";\n'
     '    const r = await fetch("api/maintenance", {method: "POST", headers: {"Content-Type": "application/json",\n'
     '      "X-Guard-Token": t}, body: JSON.stringify({on})});\n'
     '    const j = (r.headers.get("content-type") || "").includes("json") ? await r.json() : {message: await r.text()};\n'
     '    if (msg) msg.textContent = r.ok ? "Maintenance " + j.message + "." : "Not changed: " + j.message;\n'
     '    if (r.ok) { b.dataset.on = j.maintenance ? "1" : "0";\n'
     '      b.textContent = j.maintenance ? "Turn maintenance off" : "Turn maintenance on"; }\n'
     '  } catch (err) { if (msg) msg.textContent = "Not changed: " + err; }\n'
     '  b.disabled = false;\n'
     '});\n'
     '</script>'),
]


def _apply(path, edits, last=False):
    text = open(path, encoding="utf-8").read()
    if MARK in text or "maintBtn" in text:
        return None
    for old, _new in edits:
        if text.count(old) < 1:
            raise SystemExit(f"STOPPED: {path} does not contain the expected line:\n  {old.strip()[:90]}\n"
                             "Nothing was changed.")
    for old, new in edits:
        if last and old == "</script>":
            i = text.rindex(old)
            text = text[:i] + new + text[i + len(old):]
        else:
            text = text.replace(old, new, 1)
    return text


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    root = sys.argv[1]
    py, html = os.path.join(root, "i2pd_dash.py"), os.path.join(root, "static", "index.html")
    new_py = _apply(py, PY_EDITS)
    new_html = _apply(html, HTML_EDITS, last=True)
    if new_py is None and new_html is None:
        print("Already patched; nothing to do.")
        return
    if new_py is not None:
        tmp = py + ".new"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(new_py)
        try:
            py_compile.compile(tmp, doraise=True)
        except py_compile.PyCompileError as e:
            os.remove(tmp)
            raise SystemExit(f"STOPPED: the patched i2pd_dash.py does not compile ({e.msg}). Nothing changed.")
        shutil.copy2(py, py + ".bak-maint")
        shutil.copymode(py, tmp)
        os.replace(tmp, py)
        print(f"patched {py} (backup: {py}.bak-maint)")
    if new_html is not None:
        shutil.copy2(html, html + ".bak-maint")
        tmp = html + ".new"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(new_html)
        shutil.copymode(html, tmp)
        os.replace(tmp, html)
        print(f"patched {html} (backup: {html}.bak-maint)")
    print("Now: sudo systemctl restart i2pd-dash  (and reload the dashboard page)")


if __name__ == "__main__":
    main()
