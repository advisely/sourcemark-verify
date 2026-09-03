"""Every conformance vector, against the decision procedure.

The claim being tested is not "the verifier works". It is that this verifier
reaches the outcome `spec/verification.md` §3 says it must, including on the
vectors designed to make a careless implementation say VERIFIED.

Run:  python3 -m tests.test_vectors

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, str(__file__.rsplit("/tests/", 1)[0]))

from sourcemark_verify import MissingInput, verify   # noqa: E402
from tests import vectors                            # noqa: E402

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def main() -> int:
    try:
        root, manifest = vectors.load()
    except FileNotFoundError as exc:
        print(f"  SKIP  {exc}")
        return 0

    log_key = (root / manifest["log_public_key"]).read_bytes()
    keys = {}

    def key_for(entry: dict) -> bytes:
        # Each vector names the log key it must be verified against. Reusing
        # one key for all of them would quietly skip the check that a receipt
        # naming a different log is refused.
        name = entry.get("log_public_key", manifest["log_public_key"])
        if name not in keys:
            keys[name] = (root / name).read_bytes()
        return keys[name]

    print(f"Vectors: {root}  ({len(manifest['vectors'])} of them)\n")

    for entry in manifest["vectors"]:
        name = entry["name"]
        receipt = (root / entry["receipt"]).read_bytes()
        text = (root / entry["text"]).read_text()
        expected = json.loads((root / "vectors" / name / "expected.json").read_text())
        report = verify(receipt, key_for(entry), cited_text=text)
        check(f"{name} → {expected['outcome']}",
              report.outcome == expected["outcome"],
              "" if report.outcome == expected["outcome"] else f"got {report.outcome}")
        if report.outcome == expected["outcome"]:
            check(f"{name} exit status {expected['exit_status']}",
                  report.exit_status == expected["exit_status"],
                  f"got {report.exit_status}")

    print("\nProperties the vectors alone do not test")

    valid = (root / "vectors" / "valid" / "receipt.cbor").read_bytes()
    valid_text = (root / "vectors" / "valid" / "text.txt").read_text()

    # §2: a verifier handed no text MUST refuse by name, never downgrade.
    try:
        verify(valid, log_key)
        check("refuses to run without the cited text", False, "it returned a verdict")
    except MissingInput:
        check("refuses to run without the cited text", True)

    # §4.4: no repairing the input. Each of these is a "harmless" fix-up that
    # changes what was committed to.
    for label, mutated in [
        ("trailing newline", valid_text + "\n"),
        ("collapsed double space", valid_text.replace("  ", " ")),
        ("CRLF line endings", valid_text.replace("\n", "\r\n") + "\r\n"),
        ("NFD-style decomposition", valid_text.replace("é", "é")),
        ("stripped", " " + valid_text + " "),
    ]:
        if mutated == valid_text:
            continue
        report = verify(valid, log_key, cited_text=mutated)
        check(f"does not repair the input: {label}", report.outcome == "TAMPERED",
              f"got {report.outcome}")

    # §4.7: the source path is the stronger claim and must be reported as such.
    source = (root / manifest["source"]).read_bytes()
    report = verify(valid, log_key, source_bytes=source)
    check("verifies against the document itself when given one",
          report.outcome == "VERIFIED" and report.binding == "source",
          f"{report.outcome} / {report.binding}")
    report_text = verify(valid, log_key, cited_text=valid_text)
    check("and reports a different binding than the text path",
          report_text.binding == "text" and report_text.binding != report.binding)

    # One byte of the source file altered inside the cited range: the demo.
    edited = bytearray(source)
    edited[98211 + 4] ^= 0x20
    check("one edited byte in the source is TAMPERED",
          verify(valid, log_key, source_bytes=bytes(edited)).outcome == "TAMPERED")
    check("and a byte edited OUTSIDE the cited range is not",
          verify(valid, log_key,
                 source_bytes=bytes(source[:10] + b"X" + source[11:])).outcome == "VERIFIED")

    # Every vector marked source_verifiable must re-derive from the shipped file.
    for entry in manifest["vectors"]:
        if not entry.get("source_verifiable"):
            continue
        r = verify((root / entry["receipt"]).read_bytes(), key_for(entry), source_bytes=source)
        check(f"{entry['name']} re-derives from source.bin", r.outcome == entry["outcome"],
              f"got {r.outcome}")

    # The issuer signature: checked only when asked, and never load-bearing.
    issuer_key = (root / manifest["issuer_public_key"]).read_bytes()
    check("the issuer signature verifies when a key is supplied",
          verify(valid, log_key, cited_text=valid_text,
                 issuer_key_bytes=issuer_key).outcome == "VERIFIED")
    check("a receipt still verifies with no issuer key at all",
          verify(valid, log_key, cited_text=valid_text).outcome == "VERIFIED")
    check("and the report says the issuer signature went unchecked",
          any("issuer signature was not checked" in n
              for n in verify(valid, log_key, cited_text=valid_text).notes))

    # §5: the report must not call the answer proven, correct, or accurate.
    from sourcemark_verify.cli import render
    text_out = render(verify(valid, log_key, cited_text=valid_text), receipt_path="x").lower()
    for word in ("proven", "correct", "accurate"):
        check(f"the report never calls the answer {word}", word not in text_out)

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
