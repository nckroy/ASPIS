#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Says what a change touches, for $GITHUB_OUTPUT:
#
# - "code=true" or "code=false": whether it touches anything other than
#   documents, so CI can skip the lint, test, fuzz and reproducibility jobs for
#   document-only changes (the project owner's rule; ADR 0036, rule 3).
#   Documents are Markdown files anywhere, and everything under docs/.
# - "specs=true" or "specs=false": whether it touches the TLA+ specs, the
#   code that TLC's trace validation runs (crates/ksched/ and crates/kipc/,
#   and the crates kipc builds on, crates/kcap/ and crates/kmem/), or what
#   defines
#   the tlc job: xtask/, the workflows and the shared setup action under
#   .github/, and the toolchain, the workspace manifest and the lock file,
#   which build the Rust that writes the traces. CI runs TLC only then (the
#   call-language specification's "Per change").
#
# Any other path, or a missing or unknown base, counts as both, so the
# checks run whenever this script can't be sure.
#
# Usage: code-changed.sh <base> <head>

set -eu
base=${1:-}
head=${2:-}

all() {
	echo "code=true"
	echo "specs=true"
	exit 0
}

case $base in
'' | 0000000000000000000000000000000000000000) all ;;
esac

if ! files=$(git diff --name-only "$base...$head" 2>/dev/null); then
	all
fi

# An empty diff isn't a document-only change: run the tests.
if [ -z "$files" ]; then
	all
fi

code=false
specs=false
for f in $files; do
	case $f in
	docs/* | *.md) ;;
	*) code=true ;;
	esac
	case $f in
	specs/* | crates/ksched/* | crates/kipc/* | crates/kcap/* | crates/kmem/* | \
		xtask/* | .github/workflows/* | .github/actions/* | \
		rust-toolchain.toml | Cargo.toml | Cargo.lock) specs=true ;;
	esac
done
echo "code=$code"
echo "specs=$specs"
