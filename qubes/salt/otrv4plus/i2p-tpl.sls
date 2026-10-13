# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Template of sys-i2p: i2pd with SAM on loopback, and the relay's service end.
# First: in otr-build, `qvm-copy` the signed otrv4plus-i2p-relay_*.deb (+ .asc,
# .sha256) to otr-i2p-tpl. Then, in dom0:
#
#   sudo qubesctl --skip-dom0 --targets=otr-i2p-tpl state.sls otrv4plus.i2p-tpl
{% from 'otrv4plus/install-signed.jinja' import install_signed %}

i2p-runtime:
  pkg.installed:
    - pkgs:
      - i2pd
      - python3.13
      - qubes-core-agent-networking
      - gpgv
    - install_recommends: false

/etc/i2pd/i2pd.conf:
  file.managed:
    - source: salt://otrv4plus/files/i2pd.conf
    - mode: '0644'
    - require:
      - pkg: i2p-runtime

/etc/i2pd/tunnels.conf:
  file.managed:
    - contents: "# OTRv4Plus sys-i2p: no client or server tunnels; SAM only.\n"
    - mode: '0644'
    - require:
      - pkg: i2p-runtime

# i2pd runs only where dom0 turned it on (qvm-service sys-i2p i2pd on), so
# the template itself never starts a router.
/etc/systemd/system/i2pd.service.d/30_qubes.conf:
  file.managed:
    - makedirs: true
    - contents: |
        [Unit]
        ConditionPathExists=/run/qubes-service/i2pd

# The router's identity, netDb and peer profiles survive a reboot of
# sys-i2p: a router that starts from nothing every time takes minutes to
# integrate and builds tunnels slowly.
/etc/qubes-bind-dirs.d/50_otrv4plus-i2pd.conf:
  file.managed:
    - makedirs: true
    - contents: |
        binds+=( '/var/lib/i2pd' )

{{ install_signed('otrv4plus-i2p-relay') }}

no-unattended-upgrades:
  pkg.removed:
    - pkgs:
      - unattended-upgrades
