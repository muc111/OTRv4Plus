# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# RPM for a fedora-42-minimal template (Python 3.13). Not built in CI and not
# yet built on Fedora -- see FEASIBILITY_REPORT.md §7. The .deb is the tested
# path; this spec ships the SAME files: it installs a tree laid out by
# build-deb.sh --stage, so the two formats cannot drift apart.
#
#   qubes/packaging/build-deb.sh --wheels W --core-wheel C --stage /build/stage
#   rpmbuild -bb qubes/packaging/otrv4plus.spec \
#       --define "stage /build/stage" --define "repo $PWD" \
#       --define "_buildhost reproducible" \
#       --define "use_source_date_epoch_as_buildtime 1" \
#       --define "clamp_mtime_to_source_date_epoch 1"
#
# Signing: rpm --addsign through split-GPG (qubes-gpg-client-wrapper as
# %__gpg), so the key never enters the build qube.

%global debug_package %{nil}
%global _build_id_links none
# Already compiled with --invalidation-mode checked-hash; shebangs are ours.
%global __brp_python_bytecompile %{nil}
%global __brp_mangle_shebangs %{nil}
%global __brp_strip %{nil}

Name:           otrv4plus
Version:        0.13.1
Release:        1%{?dist}
Summary:        OTRv4+ post-quantum encrypted XMPP client (terminal)
License:        AGPL-3.0-only
URL:            https://github.com/muc111/OTRv4Plus
ExclusiveArch:  x86_64
Requires:       python3 >= 3.12
Requires:       opus
Recommends:     pulseaudio-utils
Recommends:     xterm
AutoReqProv:    no

%description
XMPP over I2P with OTRv4+: X448 + ML-KEM-1024 key exchange, ML-DSA-87
signatures, AES-256-GCM, SMP verification, file transfer, MLS groups.
Cryptography in the Rust core (otrv4_core). Interoperates with the
OTRv4Plus Android app and the Termux client.

%package i2p-relay
Summary:        OTRv4Plus: I2P SAM datagrams for a network-less Qubes qube
BuildArch:      noarch
Requires:       python3 >= 3.12
Requires:       i2pd

%description i2p-relay
The qrexec service otrv4plus.SamUdp, for the template of the qube that runs
i2pd (sys-i2p). It lets a chat qube with no network make OTRv4Plus voice
calls through this qube's I2P router. Loopback only.

%prep
test -d "%{stage}/opt/otrv4plus" || { echo "stage not found: run build-deb.sh --stage"; exit 1; }

%build

%install
cp -a %{stage}/. %{buildroot}/
install -D -m 0755 %{repo}/qubes/relay/otrv4plus.SamUdp \
    %{buildroot}%{_sysconfdir}/qubes-rpc/otrv4plus.SamUdp

%post
%systemd_post otrv4plus-sam-proxy.service

%preun
%systemd_preun otrv4plus-sam-proxy.service

%files
/opt/otrv4plus
%{_bindir}/otrv4plus
%dir /usr/lib/otrv4plus
/usr/lib/otrv4plus/otrv4plus-qubes-relay
%{_unitdir}/otrv4plus-sam-proxy.service
%{_datadir}/applications/otrv4plus.desktop
%{_datadir}/icons/hicolor/192x192/apps/otrv4plus.png
%doc %{_docdir}/otrv4plus

%files i2p-relay
/usr/lib/otrv4plus/otrv4plus-qubes-relay
%{_sysconfdir}/qubes-rpc/otrv4plus.SamUdp
