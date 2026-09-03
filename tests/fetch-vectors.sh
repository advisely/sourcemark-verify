#!/usr/bin/env bash
# Fetch the conformance vectors from the specification repository at a pinned
# ref. Pinned, not floating: a verifier that silently follows main can be made
# to pass by editing the tests, which is the opposite of the point.
set -euo pipefail
REF="${1:-main}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HERE/.vectors"
rm -rf "$DEST"
git clone --quiet --depth 1 --branch "$REF" https://github.com/advisely/sourcemark.git "$DEST"
echo "vectors at $REF: $(cd "$DEST" && git rev-parse --short HEAD)"
ls "$DEST/conformance/vectors"
