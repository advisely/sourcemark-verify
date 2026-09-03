"""The verifier must not open a network socket. Ever.

`spec/verification.md` §1 says so, and says the reference implementation makes
it a test that fails if a socket opens. This is that test.

It matters more than it looks. A verifier that phones home -- to fetch a tree
head, resolve `salt_ref`, check a revocation list, report telemetry -- has
quietly reintroduced the dependency the format exists to remove: the auditor
is now trusting whoever answers that call, and the receipt stops working the
day that host goes away. Offline is not a performance property here, it is the
product.

Run:  python3 -m tests.test_offline

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import socket
import sys

sys.path.insert(0, str(__file__.rsplit("/tests/", 1)[0]))

from sourcemark_verify import verify           # noqa: E402
from tests import vectors                      # noqa: E402

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


class SocketOpened(AssertionError):
    pass


def main() -> int:
    try:
        root, manifest = vectors.load()
    except FileNotFoundError as exc:
        print(f"  SKIP  {exc}")
        return 0

    keys = {n: (root / n).read_bytes() for n in {
        v.get("log_public_key", manifest["log_public_key"]) for v in manifest["vectors"]}}

    def key_for(entry: dict) -> bytes:
        return keys[entry.get("log_public_key", manifest["log_public_key"])]

    log_key = keys[manifest["log_public_key"]]
    source = (root / manifest["source"]).read_bytes()

    real_socket = socket.socket
    real_create = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo

    def forbidden(*a, **kw):
        raise SocketOpened("the verifier opened a network socket")

    socket.socket = forbidden
    socket.create_connection = forbidden
    socket.getaddrinfo = forbidden
    try:
        outcomes = []
        for entry in manifest["vectors"]:
            receipt = (root / entry["receipt"]).read_bytes()
            text = (root / entry["text"]).read_text()
            outcomes.append((entry["name"],
                             verify(receipt, key_for(entry), cited_text=text).outcome,
                             entry["outcome"]))
        # The vector whose `url` field points at a live host is the one worth
        # naming: nothing in the procedure ever dereferences it.
        report = verify((root / "vectors" / "valid" / "receipt.cbor").read_bytes(),
                        log_key, source_bytes=source)
        outcomes.append(("valid --source", report.outcome, "VERIFIED"))
    except SocketOpened as exc:
        check("no socket is opened during verification", False, str(exc))
        return 1
    finally:
        socket.socket = real_socket
        socket.create_connection = real_create
        socket.getaddrinfo = real_getaddrinfo

    check("no socket is opened during verification", True,
          f"{len(outcomes)} verifications with networking disabled")
    check("and every outcome is still the one the spec requires",
          all(got == want for _, got, want in outcomes),
          "; ".join(f"{n}: {g} != {w}" for n, g, w in outcomes if g != w))

    # The receipt carries a URL that looks entirely dereferenceable. Nothing in
    # the procedure dereferences it, which is what the run above proves: DNS
    # itself was unavailable and every outcome was still reached.
    from sourcemark_verify.cbor import decode
    receipt = decode(decode(
        (root / "vectors" / "valid" / "receipt.cbor").read_bytes()).value[2])
    url = receipt["custody"]["proof"]["log"]["url"]
    check("the receipt does carry a fetchable-looking log URL",
          isinstance(url, str) and url.startswith("https://"), url)

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
