# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# OTRv4Plus on Qubes OS 4.2 -- dom0 state: the qubes, their settings, policy.
#
#   sudo qubesctl --show-output state.sls otrv4plus.dom0
#
# Creates nothing in dom0 but qubes and one policy file; installs nothing in
# dom0; dom0 stays without network. Layout (FEASIBILITY_REPORT.md §4-5):
#
#   otr-chat     the client and your keys       netvm none
#   sys-i2p      i2pd, SAM on its own loopback  netvm sys-firewall
#   otr-build    offline build of the packages  netvm none
#   otr-sign     release signing key (split-GPG) netvm none
#   otr-fetch-dvm  disposable template: fetches sources, then is discarded
#
# Templates: debian-13-minimal (Python 3.13; the client needs 3.12+ --
# debian-12-minimal has 3.11 and cannot run it), cloned once per role so a
# package installed for the build never reaches the chat qube.

{% set base = 'debian-13-minimal' %}

otr-base-template:
  qvm.template_installed:
    - name: {{ base }}

{% for tpl, label in [('otr-build-tpl', 'black'), ('otr-chat-tpl', 'black'), ('otr-i2p-tpl', 'black')] %}
{{ tpl }}:
  qvm.clone:
    - name: {{ tpl }}
    - source: {{ base }}
    - label: {{ label }}
    - require:
      - qvm: otr-base-template
{% endfor %}

# -- the chat qube: no network at all; I2P through qrexec only ---------------
otr-chat:
  qvm.vm:
    - name: otr-chat
    - present:
      - template: otr-chat-tpl
      - label: purple
    - prefs:
      - template: otr-chat-tpl
      - label: purple
      - netvm: ""
      - default_dispvm: ""
      - memory: 400
      - maxmem: 1200
      - vcpus: 2
      - include_in_backups: true
    - features:
      - enable:
        - service.otrv4plus-sam-proxy
      - set:
        - menu-items: otrv4plus.desktop
    - require:
      - qvm: otr-chat-tpl

# -- the I2P router: the only networked qube in this design ------------------
sys-i2p:
  qvm.vm:
    - name: sys-i2p
    - present:
      - template: otr-i2p-tpl
      - label: orange
    - prefs:
      - template: otr-i2p-tpl
      - label: orange
      - netvm: sys-firewall
      - provides_network: false
      - autostart: true
      - default_dispvm: ""
      - memory: 400
      - maxmem: 1000
      - vcpus: 2
    - features:
      - enable:
        - service.i2pd
    - require:
      - qvm: otr-i2p-tpl

# -- building and signing: both offline --------------------------------------
otr-build:
  qvm.vm:
    - name: otr-build
    - present:
      - template: otr-build-tpl
      - label: gray
    - prefs:
      - template: otr-build-tpl
      - netvm: ""
      - default_dispvm: ""
      - memory: 2000
      - maxmem: 8000
      - vcpus: 4
    - require:
      - qvm: otr-build-tpl

otr-sign:
  qvm.vm:
    - name: otr-sign
    - present:
      - template: otr-build-tpl
      - label: black
    - prefs:
      - template: otr-build-tpl
      - netvm: ""
      - default_dispvm: ""
      - memory: 300
      - maxmem: 600
    - require:
      - qvm: otr-build-tpl

# The one networked step of the build, in a qube that is thrown away after.
otr-fetch-dvm:
  qvm.vm:
    - name: otr-fetch-dvm
    - present:
      - template: otr-build-tpl
      - label: red
    - prefs:
      - template: otr-build-tpl
      - netvm: sys-firewall
      - template_for_dispvms: true
      - default_dispvm: ""
    - require:
      - qvm: otr-build-tpl

# -- policy -------------------------------------------------------------------
/etc/qubes/policy.d/30-otrv4plus.policy:
  file.managed:
    - source: salt://otrv4plus/files/30-otrv4plus.policy
    - user: root
    - group: qubes
    - mode: '0664'
