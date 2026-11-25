#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Builds QEMU 11.1.3, the version ADR 0036 rule 1 pins, for aarch64 guests,
# with the EDK2 firmware it bundles. The tarball's SHA-256 was checked
# against its signature by the QEMU release key, fingerprint
# CEAC C9E1 5534 EBAB B82D  3FA0 3353 C9CE F108 B584 (Michael Roth), as
# https://www.qemu.org/download/ publishes it.
#
# Usage: build-qemu.sh <prefix>

set -eu
VERSION=11.1.3
SHA256=5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22
prefix=$1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSL -o qemu.tar.xz "https://download.qemu.org/qemu-$VERSION.tar.xz"
echo "$SHA256  qemu.tar.xz" | sha256sum -c -
tar xf qemu.tar.xz
cd "qemu-$VERSION"
# The system's libfdt, so configure fetches no dtc source that the checked
# tarball doesn't hold.
./configure --prefix="$prefix" --target-list=aarch64-softmmu \
    --enable-slirp --enable-png --enable-fdt=system --disable-docs --disable-werror
make -j"$(nproc)"
make install
"$prefix/bin/qemu-system-aarch64" --version
ls "$prefix/share/qemu/edk2-aarch64-code.fd" "$prefix/share/qemu/edk2-arm-vars.fd"
