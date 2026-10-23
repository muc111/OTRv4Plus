# OTRv4Plus on Qubes OS 4.2 — feasibility report

Date: 2026-10-12. Scope: run OTRv4Plus in an isolated Qubes OS setup that
talks to the Android app and to the terminal client on Ubuntu and Termux.
Files: [`qubes/`](../qubes/) (operator guide: [`qubes/README.md`](../qubes/README.md)).

> **Where this was done.** The work was done in an Ubuntu 24.04 cloud
> container, not on Qubes. That container has no Xen and no dom0, and no
> qrexec, Salt minion or template system. Everything marked **measured**
> was run there. Anything that needs a real Qubes machine is marked
> **to run on Qubes**, with the exact commands and the result to expect.
> No Qubes result in this report is claimed without that mark.

---

## 1. Executive summary

**Verdict: feasible now, for chat, file transfer, secure groups and voice
calls.** The recommended build is a native Debian package of the existing
terminal client. It runs in a qube with **no network**
(`otr-chat`, `netvm = none`). The qube reaches an I2P router in a second
qube (`sys-i2p`) only through qrexec, and only to that router's SAM port.

* The client is the same code that runs on Ubuntu and Termux. It speaks the
  same wire protocol as the Android app (OTRv4+: X448 + ML-KEM-1024,
  ML-DSA-87; MLS groups; Opus voice), so cross-platform use needs nothing
  new.
* Chat, files and groups only need SAM over TCP, which the stock
  `qubes.ConnectTCP` service carries. **Voice does not**: calls use SAM
  *UDP datagrams*. This study adds a small qrexec relay
  (`qubes/relay/otrv4plus-qubes-relay`, about 320 lines, no cryptography)
  that carries both, without changing the client. 8 tests cover it, and an
  end-to-end run through it is described below.
* The client and its dependencies are built **offline** in `otr-build`, with
  SHA-256-pinned inputs. The build is **reproducible**: two builds produced
  byte-identical `.deb` files (measured). Packages are signed with split-GPG
  (`otr-sign`), and the template installs a package only if its signature
  verifies (measured with a throwaway key: a genuine package verified and a
  one-byte change was rejected).
* **Measured isolation:** the installed client ran in a network namespace
  with no network and its SAM traffic went through the relay. It made
  **one** IP-level connection (to 127.0.0.1:7656) and **zero** DNS queries.
  The router received `HELLO` and `NAMING LOOKUP` through the relay.
* Not recommended: Waydroid (running the APK) and Electron or other web
  shells. A Compose Multiplatform desktop GUI would look most like the
  Android app and is a reasonable *next* step. It is not the first one,
  because it adds a JVM and a second bridge to the attack surface
  (§4).

What could not be done here and must be done on Qubes hardware: applying the
Salt states, checking the qrexec policy, audio and microphone through the
Qubes audio path, a live call between a qube and a phone, and lynis or
rkhunter in the templates (§7).

## 2. Threat model

**Assets.** Long-term identity keys (Ed448 + ML-DSA-87 OTR keys and MLS
leaf keys) and session state, all in `otr-chat`'s private volume. Message
content and files. The account password. Metadata: who talks to whom,
when, and from which IP address.

**Adversaries, and what the design does about each.**

| Adversary | Capability | Mitigation |
|---|---|---|
| Network observer / ISP | Watches the IP traffic of the machine | Everything goes over I2P. `otr-chat` has no IP route at all, so a bug in the client cannot send traffic in the clear. |
| Compromised `sys-i2p` (router exploit) | Code execution in sys-i2p | sys-i2p never holds keys or plaintext. It sees only SAM traffic, which is end-to-end encrypted (OTRv4+ / MLS / AEAD media). It can stop service or observe timing, but it cannot read messages or reach `otr-chat` except through the two allowed qrexec services, both of which carry only SAM. |
| Malicious peer / server | Sends crafted XMPP, OTR, MLS or media | Parsers are in Rust (the core). The client's existing hardening applies, and fuzzing is in `Rust/fuzz/`. A compromise stays inside `otr-chat`, which has no network to exfiltrate through except the SAM bridge. |
| Compromised other qube (e.g. `work`) | Tries to reach the chat qube | Policy refuses ConnectTCP *into* otr-chat, refuses clipboard in both directions, and asks in dom0 for every file copy. |
| Supply chain (PyPI, crates.io, Rust toolchain) | Swapped artefact | The networked fetch runs in a disposable qube. The offline build re-checks the SHA-256 lock (wheels), cargo's `Cargo.lock` checksums (crates) and the Rust project's GPG signature (toolchain). A reproducible build lets two people compare results. |
| Compromised build qube | Backdoored package | It cannot sign by itself: the key is in `otr-sign` and dom0 confirms each signature. Rebuilding independently and comparing hashes detects a tampered build. |
| Physical / evil maid | Disk access | Out of scope; Qubes full-disk encryption covers it. Private keys are also protected by the client's own `secure_store` encryption. |

**Out of scope.** A compromised dom0 or Xen. Global passive adversaries
against I2P (an inherent limit of low-latency mix networks). The Android
device's own security.

## 3. Android app analysis

What the APK is, and what that means for a desktop version.

* **UI.** Kotlin with Jetpack Compose and Material 3 (compose-bom 2024.10.01),
  minSdk 26, targetSdk 35. Screens: Connect, Chats, People, Rooms, Chat,
  Call, Profile and Settings, with a dark purple theme (`#1C1B1F` surface,
  `#E6E1E5` text).
* **Logic.** Almost none of it is in Kotlin. The app runs the **same
  Python** as the terminal client through Chaquopy (`android_bridge/*`
  plus the `otrv4plus_*` modules), and the **same Rust core**
  (`otrv4_core`, PyO3) for all cryptography, MLS and Opus.
* **Network.** A bundled i2pd (SAM) or an external router app. There is no
  clearnet path for the I2P profile, and name lookups go through SAM.
* **Consequence.** The terminal client is not a port: it *is* the app's
  engine, without the Compose layer. So the shortest path to a Qubes
  version is to package that engine. The only parts that are Android-only
  are the UI and the Android audio and Opus host binding (Linux uses
  `opuslib` over the system libopus, with parec/pacat).

**Interoperability.** Termux and Ubuntu clients and the APK already
interoperate in daily use: 1:1 chat with SMP, files, MLS groups, group
files, and 1:1 and group calls (rc.54 to rc.63). The qube runs the same
client, so it inherits all of that. The only part that is new on Qubes is
the transport (qrexec in place of a local router).

## 4. Candidate architectures

Scores run from 1 to 5, where 5 is best.

| # | Architecture | Security | Isolation fit | UI parity | Effort | Maintenance | Verdict |
|---|---|---|---|---|---|---|---|
| A | **Native .deb of the terminal client + split network (sys-i2p over qrexec)** | 5 | 5 | 2 (terminal) | 5 (done here) | 5 (same code as Termux/Ubuntu) | **Recommended** |
| B | Same as A, but i2pd *inside* the chat qube (`netvm = sys-firewall`) | 3 | 3 | 2 | 5 | 5 | Simpler, but the keys share a qube with a network-facing router. Acceptable as a fallback only. |
| C | Compose Multiplatform Desktop (reuses the Compose UI) + the Python engine as a subprocess | 4 | 5 (same split network) | 5 | 2 | 3 | **Next step** for a GUI. It adds a JVM (about 150 MB and a larger attack surface) and a stdin/stdout bridge in place of Chaquopy. |
| D | Flatpak / AppImage of A | 3 | 3 | 2 | 3 | 3 | Adds a sandbox layer that Qubes already provides better, and Flatpak's own networking and portals add surface. Weaker update control (§5). |
| E | Snap / Podman container in a qube | 2 | 2 | 2 | 3 | 2 | snapd auto-updates (against the requirements). Containers duplicate qube isolation and add a daemon. |
| F | Waydroid running the APK | 1 | 1 | 5 | 1 | 1 | **Not viable.** It needs the binder kernel module and GPU access (no GPU in Qubes AppVMs without passthrough), runs a full Android userland, and puts Android's network stack in a qube. |
| G | GTK4 / Qt / Flutter / Tauri / Electron rewrite of the UI | 3–4 (Electron: 2) | 5 | 3 | 1 | 2 | A second UI to maintain. Electron and Tauri bring a web engine. Not justified while C exists. |
| H | Three-qube key split (keys in a vault qube, crypto by RPC) | 5 | 5 | 2 | 1 | 1 | Deferred. The core is in-process by design (the PyO3 handle model), so this would need an RPC for every ratchet step and every media frame. It costs latency on calls and a large new interface. Revisit if the core gains a stable IPC boundary. |

**Why A.** It is the only option that is secure, small and finished. It
needs no network in the qube that holds the keys, adds no new runtime, and
ships the same bytes that are tested in CI on every commit.

## 5. Recommended build method

Full commands: [`qubes/README.md`](../qubes/README.md). Summary:

```
otr-fetch-dvm (disposable, networked) ─ fetch-sources.sh ─▶ bundle ─ qvm-copy ─▶
otr-build (netvm none) ─ build-core.sh ─ build-deb.sh ─▶ *.deb ─ qubes-gpg-client (dom0 asks) ─▶ otr-sign
                                                   └─ qvm-copy ─▶ otr-chat-tpl / otr-i2p-tpl ─ Salt: gpgv, apt install
```

1. **Qubes and policy.** `qubesctl state.sls otrv4plus.dom0` creates three
   templates cloned from `debian-13-minimal` and five qubes:
   * `otr-chat`: netvm none, the sam-proxy service on, the menu entry set.
   * `sys-i2p`: netvm sys-firewall, autostart, the i2pd service on.
   * `otr-build` and `otr-sign`: netvm none.
   * `otr-fetch-dvm`: a disposable template with networking.

   It also installs `/etc/qubes/policy.d/30-otrv4plus.policy`.

   *Why Debian 13 and not 12:* the client requires Python ≥ 3.12, and
   Debian 12 has 3.11. A `fedora-42-minimal` template (3.13) also works,
   using `qubes/packaging/otrv4plus.spec`.
2. **Fetch** in a disposable qube with `fetch-sources.sh --tag <TAG>`:
   * the source at a tag you have checked;
   * wheels pinned by `lock-cp313.sha256`, which deliberately leaves out
     aiodns, pycares and cffi (no C resolver; the client never uses DNS);
   * every crate vendored, checked against `Cargo.lock`;
   * the Rust 1.91.0 tarball, checked against its signature from the Rust
     project (key `85AB96E6FA1BE5FE`);
   * maturin 1.13.3.

   `qvm-copy` then moves the bundle to `otr-build`, and the disposable qube
   is discarded.
3. **Build offline** with `build-core.sh`. It refuses to run if the qube
   has a network route, re-checks the Rust signature, and builds at the
   fixed path `/build/OTRv4Plus` with:

   ```
   RUSTFLAGS="--remap-path-prefix=… -C debuginfo=0 -C strip=symbols"
   ```

   Then `build-deb.sh`:
   * checks every input against the lock;
   * stages the client, its libraries and the relay;
   * **imports every module from the staged tree** (this catches a module
     the package forgot);
   * refuses a core built without MLS or with a test-only API;
   * compiles checked-hash bytecode, normalises mtimes and permissions,
     and builds with `dpkg-deb --root-owner-group`.

   It produces `otrv4plus_<v>_amd64.deb` (chat template) and
   `otrv4plus-i2p-relay_<v>_all.deb` (I2P template).
4. **Sign** with
   `QUBES_GPG_DOMAIN=otr-sign qubes-gpg-client-wrapper --detach-sign --armor`.
   The key never leaves `otr-sign`, and dom0 prompts for each signature.
5. **Install** with `qubesctl --skip-dom0 --targets=otr-chat-tpl state.sls
   otrv4plus.chat-tpl` (and the same for `otr-i2p-tpl`). Each run checks:
   * `gpgv` against the release key pinned in the formula;
   * `sha256sum --check`;

   then runs `apt-get install --no-install-recommends`. No repository is
   added and there is no automatic update. Updating means repeating steps
   2 to 5 for a new tag.

## 6. Hardening checklist

| Item | How | Status |
|---|---|---|
| No network in dom0 | Nothing is installed in dom0; the formula is copied in as reviewed text | design |
| No network in the qube that holds the keys | `otr-chat` netvm `""` | Salt |
| Only the SAM bridge reachable | Policy: ConnectTCP `+7656` to sys-i2p only; `otrv4plus.SamUdp` to sys-i2p only; everything else denied | Salt + policy |
| SAM never on a network interface | i2pd `[sam] address = 127.0.0.1`; web console, HTTP/SOCKS proxy, BOB, I2CP, I2PControl and UPnP all off | `files/i2pd.conf` |
| No DNS from the client | The router resolves `.i2p` names through SAM `NAMING LOOKUP`; no resolver library is shipped | **measured: 0 DNS queries** |
| No clipboard | `qubes.ClipboardPaste` denied in both directions | policy |
| No USB passthrough | Never attach USB to `otr-chat` or `sys-i2p`; neither needs it. The microphone comes through Qubes audio (`qvm-device mic`), attached only during a call | procedure |
| Files only with a prompt | `qubes.Filecopy` ask in both directions; `OpenInVM` only to `@dispvm`; `OpenURL` denied | policy |
| Minimal templates | `debian-13-minimal` clones, one per role, `--no-install-recommends`, `unattended-upgrades` removed | Salt |
| Router not running in templates | `ConditionPathExists=/run/qubes-service/i2pd` (and the same for sam-proxy) | Salt / package |
| Persistent router identity only where intended | bind-dirs for `/var/lib/i2pd` in sys-i2p only | Salt |
| Relay service hardened | systemd: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictAddressFamilies=AF_INET AF_UNIX`, empty capability set, non-root `User=user` | package |
| Relay cannot be used to forward off-qube | It relays only datagram sessions whose `HOST` is 127.0.0.1, and drops datagrams for sessions it did not open | **tested** |
| Signed, reproducible packages | split-GPG; byte-identical rebuilds | **measured** |
| No auto-update | No repository, no updater; installation is manual and signature-checked | design |
| Disposable qubes | The networked fetch runs in a disposable qube. `sys-i2p` *can* be a named disposable (fresh router identity each boot: better unlinkability, but minutes of integration at every start), so this is offered as an option, not the default | design |
| Python run isolated | Launcher: `python -s`, `PYTHONPATH` fixed to the package, no bytecode written at run time; the relay runs `-I` | package |

## 7. Test results

### Measured here (Ubuntu 24.04 container)

| Test | Result |
|---|---|
| Rust core reproducibility: two clean builds in different directories with the remap flags | `otrv4_core.abi3.so` byte-identical (sha256 `3375e1b8…603ef`), **0** build paths embedded. Without the flags: **117** build-machine paths. The wheels differed only in the SBOM's source directory, which the fixed build path `/build/OTRv4Plus` fixes. Build time 2 min 01 s. |
| `.deb` reproducibility: two builds, same inputs | Byte-identical. `otrv4plus_0.13.1_amd64.deb` sha256 `e2640aaf…25b45` (3.7 MB, 17 MB installed, 1 783 entries); `otrv4plus-i2p-relay_0.13.1_all.deb` sha256 `30da2d04…7b152` (15.7 KB). Built against cp312 here (the container's Python); the Qubes build uses `lock-cp313.sha256` and Python 3.13. |
| Package self-check | All 34 shipped modules import from the staged tree alone, and the core has `RustMlsClient`. **The gate on the raw-key test API was checked both ways:** the release core passes, and a core built with `raw-key-test-api` is refused, with all 18 entry points named. (The first draft checked three made-up names. `tests/test_qubes_packaging.py` now keeps the list equal to `tests/test_release_guard.py`.) |
| Signature gate | Throwaway ed25519 key: `gpgv` "Good signature", exit 0, on the genuine `.deb`; a copy with one changed byte gave "BAD signature", exit 1 |
| Salt states | All four states render (Jinja) and parse (YAML) into the expected state IDs. **Not applied**: no Salt minion or Qubes here. |
| Relay unit and integration tests (`tests/test_qubes_relay.py`, fake qrexec + fake SAM router) | 8 passed: datagrams both ways, two sessions kept apart, unknown or garbage datagrams dropped, the session ends with its control connection, stream bytes after `STREAM CONNECT` passed byte for byte (a command-looking line in user data is *not* acted on), loopback-only parsing, PORT rewrite |
| **End to end, no network:** the installed `.deb` client in `unshare -rn` (loopback only), with the packaged relay as SAM, under `strace -f` | The client's only IP connection was `127.0.0.1:7656`; **0** DNS. The router behind the relay received `HELLO VERSION` and `NAMING LOOKUP NAME=<b32>` (the client resolved its server through the router, not DNS). |
| Startup cost | Warm import 0.2–0.3 s, cold 5.3 s (bytecode check on first run), about 37 MiB RSS after import |

### To run on Qubes (commands and expected results)

```sh
# dom0
sudo qubesctl --show-output state.sls otrv4plus.dom0      # expect: all states Succeeded
qvm-prefs otr-chat netvm                                  # expect: (empty)
qvm-features otr-chat service.otrv4plus-sam-proxy         # expect: 1
qvm-run -p otr-chat 'qrexec-client-vm sys-firewall qubes.ConnectTCP+80 </dev/null; echo $?'
                                                          # expect: non-zero, "Request refused"
qvm-run -p otr-chat 'qrexec-client-vm sys-i2p qubes.ConnectTCP+7070 </dev/null; echo $?'
                                                          # expect: refused (only +7656 allowed)
# otr-chat
ip route; ip -6 route                                     # expect: no routes
getent hosts example.com; echo $?                         # expect: 2
systemctl is-active otrv4plus-sam-proxy                   # expect: active
ss -lntu                                                  # expect: only 127.0.0.1:7656/tcp, 127.0.0.1:7655/udp
otrv4plus --jid alice@<server>.i2p                        # expect: connected after tunnels build
# sys-i2p
ss -lntu | grep -E '7656|7655|7070|4444|4447'              # expect: 7656, 7655 on 127.0.0.1 only; no 7070/4444/4447
# leak test: in sys-firewall, while chatting and during a call
sudo tcpdump -ni any 'host <otr-chat IP>'                 # expect: nothing (otr-chat has no IP)
# calls
qvm-device mic attach otr-chat dom0:mic; otrv4plus → /audiotest   # expect: beep heard, mic level shown
# cross-platform: from otr-chat, call the Android app and a Termux client; send a file into a group; SMP verify.
# templates
sudo apt-get install --no-install-recommends lynis rkhunter && sudo lynis audit system && sudo rkhunter --check --sk
```

## 8. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Voice quality through the qrexec relay: two extra copies per frame | Medium | Low–medium | One 60 ms frame is about 200 bytes, and qrexec adds microseconds against I2P's 100s of ms. Frames are dropped, not queued, past 256 KiB of backlog. To be confirmed with `/audiotest` and a live call. |
| Qubes audio path (PipeWire/PulseAudio agent) differs from a laptop | Medium | Medium | parec/pacat are used as on Ubuntu; `/audiotest` diagnoses. The echo-cancel source is picked when present. |
| `debian-13-minimal` availability or package names (`pulseaudio-qubes` vs `pipewire-qubes`) | Low | Low | Noted in `chat-tpl.sls`; Fedora 42 with the RPM spec as an alternative. |
| A router compromise in sys-i2p | Low | Medium (availability and metadata, not content) | Keys and plaintext are never there. Optionally run it as a disposable qube for a fresh identity per boot. |
| The relay is new code in the trust path | Low | Medium | It is small, has no cryptography and no parsing beyond the SAM command line, is tested, and cannot forward off the qube. It runs as a hardened, non-root unit. |
| A build that is not reproducible on a second machine (toolchain or glibc drift) | Medium | Medium | Everything is pinned (Rust 1.91.0, maturin 1.13.3, wheel hashes). Compare hashes between two builders before signing. |
| Copying the formula into dom0 | Low | High | It is plain text and reviewed first; no binaries ever go to dom0 (the release *public* key is the only non-text file and is checked with `gpg --show-keys`). |
| opuslib 3.0.1 prints a `SyntaxWarning` at bytecode compile (upstream `is not 0`) | Certain | None | Cosmetic, upstream; noted so it is not mistaken for a build fault. |
| The terminal UI is less friendly than the app | Certain | Low | Candidate C (Compose Desktop on the same engine) is the planned GUI. |

## 9. Appendices

**A. Files.** `qubes/packaging/` contains:

* `fetch-sources.sh`, `build-core.sh` and `build-deb.sh`;
* `otrv4plus.spec`;
* `lock-cp313.sha256` and `lock-cp312.sha256`.

`qubes/relay/` contains:

* `otrv4plus-qubes-relay`;
* `otrv4plus-sam-proxy.service`;
* `otrv4plus.SamUdp`.

`qubes/salt/otrv4plus/` contains:

* `dom0.sls`, `build-tpl.sls`, `chat-tpl.sls` and `i2p-tpl.sls`;
* `install-signed.jinja`;
* `files/30-otrv4plus.policy` and `files/i2pd.conf`.

The tests are in `tests/test_qubes_relay.py`.

**B. Reproducibility recipe (core).**

```
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=<vendor>=/vendor \
           --remap-path-prefix=/build=/build -C debuginfo=0 -C strip=symbols"
cd /build/OTRv4Plus/Rust && maturin build --release --locked --features mls
```

**C. Python inputs (lock-cp313.sha256).** slixmpp 1.17.0 (cp313 wheel),
PySocks 1.7.1, pyasn1 0.6.4, pyasn1-modules 0.4.2, and opuslib 3.0.1 (sdist;
pure Python). Excluded on purpose: aiodns, pycares, cffi and pycparser.

**D. Why voice needed the relay.** SAM datagrams work like this. The client
sends `3.0 <session> <dest>\n<payload>` to the router's UDP 7655. The router
forwards inbound datagrams to the `HOST:PORT` the client named in
`SESSION CREATE`. Both legs are UDP, so `qubes.ConnectTCP` cannot carry
them. The relay proxy sits where the client already looks for SAM
(127.0.0.1:7656/7655). When it sees a datagram `SESSION CREATE`, it opens one
`otrv4plus.SamUdp` call to sys-i2p. The service there binds a loopback UDP
port and reports it, and the proxy rewrites `PORT=` to that port. From then
on, datagrams travel framed (a 2-byte length plus the bytes) over that call
in both directions. The call ends when the session's control connection
closes. The client is unchanged; the same client binary works on Ubuntu,
Termux and Qubes.
