#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Builds aspis.efi and initfs.img twice, in different directories and as
# different users, and fails if the bytes differ (ADR 0038, rule 1).
#
# Run from the repository root, on a host with sudo (a CI runner).

set -eu
root=$(pwd)
other=/tmp/aspis-elsewhere
user=aspisrepro

cargo xtask build

sudo rm -rf "$other"
sudo mkdir -p "$other"
# The whole checkout, .git included, so the commit time is the same.
tar -C "$root" --exclude=./target --exclude=./build -cf - . | sudo tar -C "$other" -xf -
id "$user" >/dev/null 2>&1 || sudo useradd --create-home "$user"
sudo chown -R "$user" "$other"
sudo -u "$user" -H sh -c "
    set -eu
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
    . \"\$HOME/.cargo/env\"
    cd '$other'
    cargo xtask build
"

status=0
for f in aspis.efi initfs.img; do
    a=$(sha256sum "$root/build/production/$f" | cut -d' ' -f1)
    b=$(sudo sha256sum "$other/build/production/$f" | cut -d' ' -f1)
    echo "$f: $a"
    if [ "$a" != "$b" ]; then
        echo "$f differs between the two builds: $b"
        status=1
    fi
done
if [ "$status" -ne 0 ]; then
    # Report the difference with diffoscope (ADR 0038, rule 1).
    sudo apt-get install -y -qq diffoscope-minimal >/dev/null
    for f in aspis.efi initfs.img kernel.elf; do
        sudo diffoscope --max-report-size 200000 "$root/build/production/$f" "$other/build/production/$f" || true
    done
fi
[ "$status" -eq 0 ] && echo "both builds are identical"
exit "$status"
