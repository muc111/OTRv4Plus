#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Publish one file as annotations ("dump:<name>:<part>/<parts>", gzip +
# base64), for an environment that can read api.github.com but not artifact
# storage. GitHub keeps 4096 characters of an annotation and about ten of
# each level per step, so: 4000-character parts, notice then warning, and
# one file per step.
set -eu
f="$1"; name="$(basename "$f")"
[ -f "$f" ] || { echo "no $f"; exit 0; }
gzip -9c "$f" | base64 -w0 > /tmp/b64
parts=$(( ($(stat -c%s /tmp/b64) + 3999) / 4000 ))
[ "$parts" -le 20 ] || { echo "::error::$name needs $parts parts (max 20)"; exit 0; }
for i in $(seq 1 "$parts"); do
  level=notice; [ "$i" -gt 10 ] && level=warning
  echo "::$level title=dump:$name:$i/$parts::$(cut -c$(( (i-1)*4000+1 ))-$(( i*4000 )) /tmp/b64)"
done
