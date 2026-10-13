# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Template of otr-build, otr-sign and otr-fetch-dvm: compilers and tools,
# no OTRv4Plus package, no keys.
#
#   sudo qubesctl --skip-dom0 --targets=otr-build-tpl state.sls otrv4plus.build-tpl
build-tools:
  pkg.installed:
    - pkgs:
      - build-essential
      - python3.13
      - python3-venv
      - python3-pip
      - git
      - curl
      - ca-certificates
      - gnupg
      - xz-utils
      - unzip
      - openjdk-21-jdk-headless   # the desktop GUI's build (Gradle)
      - dpkg-dev
      - qubes-gpg-split
    - install_recommends: false
