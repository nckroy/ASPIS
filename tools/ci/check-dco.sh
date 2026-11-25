#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Every commit in a pull request carries a sign-off, which certifies the
# Developer Certificate of Origin 1.1 (ADR 0033, rule 1).
#
# Usage: check-dco.sh <base> <head>

set -eu
base=$1
head=$2
fail=0
for c in $(git rev-list --no-merges "$base..$head"); do
    if ! git log -1 --format=%B "$c" | grep -Eq '^Signed-off-by: [^<]+ <[^>]+@[^>]+>$'; then
        echo "no Signed-off-by line: $(git log -1 --format='%h %s' "$c")"
        fail=1
    fi
done
if [ "$fail" -ne 0 ]; then
    echo "Sign off each commit with 'git commit -s'. See https://developercertificate.org/."
    exit 1
fi
echo "every commit is signed off"
