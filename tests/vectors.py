"""Locate the conformance vectors, which live in the specification repository.

They are deliberately not vendored here. A verifier that ships its own copy of
the tests it must pass can drift from the specification and keep reporting
green, which is the exact failure this repository exists to make impossible.

Search order:

    $SOURCEMARK_VECTORS            an explicit path
    ./.vectors/conformance         what tests/fetch-vectors.sh writes
    ../sourcemark/conformance      a sibling checkout, for local work

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

CANDIDATES = [
    os.environ.get("SOURCEMARK_VECTORS"),
    ROOT / ".vectors" / "conformance",
    ROOT.parent / "sourcemark" / "conformance",
]


def find() -> pathlib.Path | None:
    for candidate in CANDIDATES:
        if not candidate:
            continue
        path = pathlib.Path(candidate)
        if (path / "manifest.json").is_file():
            return path
    return None


def load() -> tuple[pathlib.Path, dict]:
    path = find()
    if path is None:
        raise FileNotFoundError(
            "conformance vectors not found. Run tests/fetch-vectors.sh, or set "
            "SOURCEMARK_VECTORS to a checkout's conformance/ directory."
        )
    return path, json.loads((path / "manifest.json").read_text())
