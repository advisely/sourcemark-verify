"""Run every suite.

    python3 -m tests

Both suites skip, with a printed reason, when the conformance vectors are not
present. Run tests/fetch-vectors.sh first, or point SOURCEMARK_VECTORS at a
checkout of the specification repository.

SPDX-License-Identifier: Apache-2.0
"""

import sys

from . import test_action, test_offline, test_vectors

if __name__ == "__main__":
    failures = 0
    for name, module in (("conformance vectors", test_vectors), ("offline", test_offline),
                         ("github action", test_action)):
        print(f"\n{'=' * 68}\n{name}\n{'=' * 68}")
        failures += module.main()
    print("\nall suites passed" if not failures else f"\n{failures} suite(s) failed")
    sys.exit(1 if failures else 0)
