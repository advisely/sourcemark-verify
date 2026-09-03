"""The command line.

`spec/verification.md` §5 constrains the output, not just the exit code:

  - it MUST name the outcome and list which checks ran
  - it MUST say which of §4.4 and §4.7 it performed, because "verified against
    text you supplied" and "verified against the document itself" are
    different claims and must not render identically
  - it MUST NOT call the answer proven, correct, or accurate. Custody is not
    support. A VERIFIED receipt whose support class is UNSUPPORTED is a
    correctly functioning receipt reporting a failed answer.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

from .verify import EXIT_STATUS, MissingInput, Report, verify

USAGE_EXIT = 64

BINDING_PHRASE = {
    "source": "against the document itself, re-derived at the recorded byte range",
    "text": "against the text you supplied",
    "erased": "not checked: the opening is a tombstone",
    "none": "not checked",
}

HEADLINE = {
    "VERIFIED": "CUSTODY VERIFIED",
    "ERASED": "ERASED — anchored and provable, no longer openable",
    "PENDING": "PENDING — anchored, not yet inside a signed tree",
    "TAMPERED": "TAMPERED — the cited text is not what was committed",
    "FORGED": "FORGED — the proof does not fold",
    "BACKDATED": "BACKDATED — the commitment does not precede the answer",
    "UNSIGNED": "UNSIGNED — the tree head does not verify against this key",
    "MALFORMED": "MALFORMED — this is not a readable receipt",
}


def render(report: Report, *, receipt_path: str) -> str:
    lines = [f"  {HEADLINE[report.outcome]}"]
    for i, check in enumerate(report.checks):
        last = i == len(report.checks) - 1
        mark = "ok  " if check.passed else "FAIL"
        lines.append(f"  {'└─' if last else '├─'} {check.name:<34} {mark} {check.detail}".rstrip())
    lines.append("")
    lines.append(f"  content binding    {BINDING_PHRASE[report.binding]}")
    for note in report.notes:
        lines.append(f"  note               {note}")
    if report.outcome == "VERIFIED":
        lines.append("  scope              custody only. This says nothing about whether the")
        lines.append("                     answer follows from the text — see support scoring.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sourcemark verify",
        description="Check a Sourcemark receipt offline. No network, no account, no trust.",
    )
    parser.add_argument("receipt", help="the receipt, as COSE_Sign1 CBOR")
    parser.add_argument("--log-key", required=True,
                        help="the log's public key, PEM or DER SubjectPublicKeyInfo")
    parser.add_argument("--text", help="file holding the cited text")
    parser.add_argument("--source", help="the original document; enables the strongest check")
    parser.add_argument("--issuer-key", help="optional: also check who assembled the receipt")
    parser.add_argument("--skew-ms", type=int, default=300_000,
                        help="clock-skew tolerance for the ordering check (default 300000)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    def read(path: str | None) -> bytes | None:
        if path is None:
            return None
        try:
            return pathlib.Path(path).read_bytes()
        except OSError as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            raise SystemExit(USAGE_EXIT) from exc

    receipt_bytes = read(args.receipt)
    log_key = read(args.log_key)
    text_bytes = read(args.text)
    source_bytes = read(args.source)
    issuer_key = read(args.issuer_key)

    cited_text = None
    if text_bytes is not None:
        try:
            cited_text = text_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            print(f"--text is not UTF-8: {exc}", file=sys.stderr)
            return USAGE_EXIT

    try:
        report = verify(
            receipt_bytes, log_key,
            cited_text=cited_text, source_bytes=source_bytes,
            issuer_key_bytes=issuer_key,
            skew_tolerance_ms=args.skew_ms, now_ms=int(time.time() * 1000),
        )
    except MissingInput as exc:
        # A missing input is a usage error, never a weaker verdict. A weaker
        # verdict rendered in a terminal is read as a pass.
        print(f"cannot verify: {exc}", file=sys.stderr)
        return USAGE_EXIT

    if args.json:
        print(json.dumps({
            "outcome": report.outcome,
            "exit_status": report.exit_status,
            "binding": report.binding,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail}
                       for c in report.checks],
            "notes": report.notes,
        }, indent=2))
    else:
        print(render(report, receipt_path=args.receipt))
    return EXIT_STATUS[report.outcome]


if __name__ == "__main__":
    sys.exit(main())
