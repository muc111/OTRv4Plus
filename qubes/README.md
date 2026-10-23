# OTRv4Plus on Qubes OS 4.2

This directory runs the OTRv4Plus terminal client in a qube that has **no
network**. All traffic goes through an I2P router in a second qube, and the
packages are built offline, reproducibly and with a signature. The client
speaks the same protocol as the Android app and as Termux or Ubuntu, so it
works with both for chat, files, groups and voice calls.

The reasoning and the measurements are in
[`../docs/FEASIBILITY_REPORT.md`](../docs/FEASIBILITY_REPORT.md). This README is the
operator's guide.

```
 ┌───────────── otr-chat (netvm: none) ─────────────┐        ┌──── sys-i2p (netvm: sys-firewall) ────┐
 │ otrv4plus (xterm)                                │        │ i2pd                                   │
 │   SAM 127.0.0.1:7656/tcp ─┐                      │ qrexec │   SAM 127.0.0.1:7656/tcp               │
 │   SAM 127.0.0.1:7655/udp ─┤ otrv4plus-sam-proxy ─┼────────┼─▶ qubes.ConnectTCP+7656                │
 │                           └ (systemd, user)      │        │   otrv4plus.SamUdp  ──▶ 127.0.0.1:7655 │
 │ keys: ~/.otrv4plus, ~/.config/otrv4plus          │        │ /var/lib/i2pd (bind-dirs, persistent)  │
 └──────────────────────────────────────────────────┘        └────────────────────────────────────────┘
          no DNS, no IP route, no clipboard                         the only networked qube here
```

| Path | What |
|---|---|
| `packaging/fetch-sources.sh` | Step 1. Runs in a **disposable** networked qube and collects the source, pinned wheels, vendored crates and the signed Rust toolchain into one bundle. |
| `packaging/build-core.sh` | Step 2. Runs **offline**. Builds the Rust core reproducibly at a fixed path. |
| `packaging/build-deb.sh` | Step 3. Runs **offline**. Builds `otrv4plus_*.deb` (for the chat template) and `otrv4plus-i2p-relay_*.deb` (for the I2P template). With `--stage`, it lays out the files for the RPM instead. |
| `packaging/build-desktop.sh` | Step 3b. Runs **offline**. Builds `otrv4plus-desktop_*.deb`, the Compose GUI, from a dependency cache the fetch step checked against `desktop/gradle/verification-metadata.xml`. |
| `packaging/otrv4plus.spec` | RPM for a Fedora template; ships the same files. Not yet built on Fedora. |
| `packaging/lock-cp313.sha256` | SHA-256 of every Python input. A file that is not in this list stops the build. |
| `relay/otrv4plus-qubes-relay` | Carries SAM over qrexec, both streams and the UDP datagrams calls use. Tests are in `tests/test_qubes_relay.py`. |
| `salt/otrv4plus/*.sls` | Salt states: the qubes, their settings and the policy (dom0), plus the three templates. |
| `salt/otrv4plus/files/30-otrv4plus.policy` | qrexec policy. |

## Install

Each step names the qube where you type it.

**1. Get the formula into dom0.** dom0 has no network, and copying into it
is a trust decision. The files are plain text, so read them first.

```sh
# in any qube where you cloned and checked the repository (git tag verified):
#   less qubes/salt/otrv4plus/*.sls qubes/salt/otrv4plus/files/*
# in dom0:
qvm-run --pass-io work 'tar -C ~/OTRv4Plus/qubes/salt -c otrv4plus' \
  | sudo tar -x -C /srv/salt --no-same-owner
sudo qubesctl --show-output state.sls otrv4plus.dom0
sudo qubesctl --skip-dom0 --targets=otr-build-tpl state.sls otrv4plus.build-tpl
```

**2. Fetch the sources in a disposable.**

```sh
# dom0:
qvm-run --dispvm otr-fetch-dvm xterm
# in that disposable:
git clone https://github.com/muc111/OTRv4Plus && cd OTRv4Plus
git tag -v <TAG> || git rev-parse <TAG>^{commit}    # compare with the release notes
qubes/packaging/fetch-sources.sh --tag <TAG>
qvm-copy bundle                                      # target: otr-build
```

**3. Build offline (otr-build).**

```sh
B=~/QubesIncoming/disp*/bundle
$B/OTRv4Plus/qubes/packaging/build-core.sh --bundle $B
cd /build/OTRv4Plus
qubes/packaging/build-deb.sh --wheels $B/wheels \
    --core-wheel /build/wheel/otrv4_core-*.whl --out /build/dist
qubes/packaging/build-desktop.sh --gradle-cache $B/gradle-cache --out /build/dist   # the GUI
```

Run the build twice, in two fresh `otr-build` qubes or once in each of two
people's qubes. The printed SHA-256 values must match.

**4. Sign with split-GPG.** The key lives in `otr-sign`, and dom0 asks you to
approve each signature.

```sh
# otr-build:
export QUBES_GPG_DOMAIN=otr-sign
for f in /build/dist/*.deb; do qubes-gpg-client-wrapper --detach-sign --armor < "$f" > "$f.asc"; done
qvm-copy /build/dist/otrv4plus_*.deb* /build/dist/otrv4plus-desktop_*.deb*   # target: otr-chat-tpl
qvm-copy /build/dist/otrv4plus-i2p-relay_*.deb*    # target: otr-i2p-tpl
```

Put the public key in dom0 as `/srv/salt/otrv4plus/files/otrv4plus-release.gpg`
(see `salt/otrv4plus/files/README.md`). Then, in dom0:

```sh
sudo qubesctl --skip-dom0 --targets=otr-i2p-tpl  state.sls otrv4plus.i2p-tpl
sudo qubesctl --skip-dom0 --targets=otr-chat-tpl state.sls otrv4plus.chat-tpl
qvm-shutdown --wait otr-chat-tpl otr-i2p-tpl
qvm-appmenus --update --force otr-chat
qvm-start sys-i2p
```

**5. Use it.** Start **OTRv4Plus** from the otr-chat menu. Two entries
are installed:

* the desktop app (`otrv4plus-desktop`), which looks like the Android app
  (see [`../desktop/README.md`](../desktop/README.md));
* the terminal client (`otrv4plus`), the same as on Termux and Ubuntu.

The desktop window holds no keys. It starts the engine as a separate
process, and the engine's Rust core keeps every key.

For the terminal client, if you prefer not
to type the arguments each time, put one per line in
`~/.config/otrv4plus/args` inside `otr-chat`:

```
--jid
alice@your-server.i2p
```

A new router needs a few minutes to integrate before the first tunnels are
built. For a call, attach the microphone only while the call is running, and
detach it afterwards:

```sh
qvm-device mic attach otr-chat dom0:mic
qvm-device mic detach otr-chat dom0:mic
```

## Checks on a real Qubes machine

These checks are listed with their expected results in
[`../docs/FEASIBILITY_REPORT.md`](../docs/FEASIBILITY_REPORT.md) §7. They could not be
run where this was written, because that machine is not running Qubes.

```sh
# otr-chat: no route, no DNS
ip route                                   # expect: nothing
getent hosts example.com; echo $?          # expect: 2
# otr-chat: SAM answers through the relay
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",7656),30); s.sendall(b"HELLO VERSION MIN=3.1 MAX=3.3\n"); print(s.recv(200))'
                                           # expect: b'HELLO REPLY RESULT=OK VERSION=3.3\n'
# dom0: the policy refuses anything else
qvm-run -p otr-chat 'qrexec-client-vm sys-firewall qubes.ConnectTCP+80 </dev/null'; echo $?  # expect: refused
```
