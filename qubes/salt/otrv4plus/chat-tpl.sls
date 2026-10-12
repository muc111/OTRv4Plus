# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Template of otr-chat: the client and what it needs to run, nothing else.
# First: in otr-build, `qvm-copy` the signed otrv4plus_*.deb (+ .asc,
# .sha256) to otr-chat-tpl. Then, in dom0:
#
#   sudo qubesctl --skip-dom0 --targets=otr-chat-tpl state.sls otrv4plus.chat-tpl
{% from 'otrv4plus/install-signed.jinja' import install_signed %}

chat-runtime:
  pkg.installed:
    - pkgs:
      - python3.13
      - libopus0
      - pulseaudio-utils      # parec/pacat; PipeWire's pulse server answers them
      - pulseaudio-qubes      # VM audio; use pipewire-qubes on a PipeWire template
      - xterm
      - gpgv
    - install_recommends: false

{{ install_signed('otrv4plus') }}

otrv4plus-sam-proxy:
  service.enabled:
    - require:
      - cmd: otrv4plus-verified-install

# Nothing in this template listens on the network or updates itself.
no-unattended-upgrades:
  pkg.removed:
    - pkgs:
      - unattended-upgrades
