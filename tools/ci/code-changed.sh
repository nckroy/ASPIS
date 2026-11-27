#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Says whether a change touches anything other than documents, so CI can
# skip the lint, test, fuzz and reproducibility jobs for document-only changes
# (the project owner's rule; ADR 0036, rule 3). Documents are Markdown files anywhere, and everything under
# docs/. Any other path, or a missing or unknown base, counts as code, so
# the tests run whenever this script can't be sure.
#
# Usage: code-changed.sh <base> <head>
# Prints "code=true" or "code=false", for $GITHUB_OUTPUT.

set -eu
base=${1:-}
head=${2:-}

case $base in
'' | 0000000000000000000000000000000000000000)
	echo "code=true"
	exit 0
	;;
esac

if ! files=$(git diff --name-only "$base...$head" 2>/dev/null); then
	echo "code=true"
	exit 0
fi

# An empty diff isn't a document-only change: run the tests.
if [ -z "$files" ]; then
	echo "code=true"
	exit 0
fi

code=false
for f in $files; do
	case $f in
	docs/* | *.md) ;;
	*) code=true ;;
	esac
done
echo "code=$code"
