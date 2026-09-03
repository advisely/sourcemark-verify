"""The GitHub Action runner.

Checks every receipt matching a glob and fails the job unless each outcome is
one the workflow said it would accept.

**`allow` is an input rather than a hard-coded rule** because the right answer
differs by deployment and the wrong default is dangerous in both directions.
A team with a retention policy legitimately sees `ERASED` and should not have
their pipeline go red over a document they deliberately destroyed. A team
anchoring in batches legitimately sees `PENDING` and wants a retry, not an
incident. Neither should be silently folded into "pass", so the workflow has
to say which it accepts, in writing, in the repository.

Everything else is deliberately not configurable. There is no `--lenient`, no
"warn only" mode for a `TAMPERED` receipt, and no way to ask for a boolean.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import glob
import json
import os
import pathlib
import sys

from sourcemark_verify import MissingInput, verify

ICON = {"VERIFIED": "✅", "ERASED": "🗝️", "PENDING": "⏳",
        "TAMPERED": "❌", "FORGED": "❌", "BACKDATED": "❌",
        "UNSIGNED": "❌", "MALFORMED": "⚠️"}

MEANING = {
    "VERIFIED": "cited text is what was committed, before the answer",
    "ERASED": "key destroyed, tree intact — not a failure",
    "PENDING": "not yet in a signed tree — retry shortly",
    "TAMPERED": "the source no longer matches what was committed",
    "FORGED": "the inclusion proof does not fold",
    "BACKDATED": "the commitment does not precede the answer",
    "UNSIGNED": "the tree head does not verify against this key",
    "MALFORMED": "not a readable receipt",
}


def output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        # Heredoc form, because a JSON value contains newlines and the plain
        # `name=value` form silently truncates at the first one.
        fh.write(f"{name}<<__SM__\n{value}\n__SM__\n")


def summary(rows: list[dict], allowed: set[str], failed: int) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["## Sourcemark receipts", "",
             "| Receipt | Outcome | |", "|---|---|---|"]
    for r in rows:
        mark = "" if r["outcome"] in allowed else " **not allowed**"
        lines.append(f"| `{r['receipt']}` | {ICON.get(r['outcome'],'')} "
                     f"{r['outcome']}{mark} | {MEANING.get(r['outcome'],'')} |")
    lines += ["", f"Accepting: `{'`, `'.join(sorted(allowed))}`",
              "", "A verified receipt establishes where text came from. Whether the "
                  "answer built on it holds up is a separate question."]
    if failed:
        lines.append(f"\n**{failed} receipt(s) did not reach an accepted outcome.**")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    pattern = os.environ["SM_RECEIPT"]
    receipts = sorted(glob.glob(pattern, recursive=True))
    if not receipts:
        print(f"::error::no receipt matched {pattern!r}. Refusing to pass a run that "
              f"checked nothing — an empty glob is the quietest way for this job to "
              f"stop protecting anything.")
        return 1

    log_key = pathlib.Path(os.environ["SM_LOG_KEY"]).read_bytes()
    source = os.environ.get("SM_SOURCE") or ""
    source_bytes = pathlib.Path(source).read_bytes() if source else None
    text_input = os.environ.get("SM_TEXT") or ""
    allowed = {o.strip().upper() for o in os.environ.get("SM_ALLOW", "VERIFIED").split(",")
               if o.strip()}

    rows, failed = [], 0
    for path in receipts:
        p = pathlib.Path(path)
        text = None
        if text_input:
            tp = pathlib.Path(text_input)
            if tp.is_dir() or len(receipts) > 1:
                candidate = (tp / f"{p.stem}.txt") if tp.is_dir() else p.with_suffix(".txt")
                text = candidate.read_text("utf-8") if candidate.is_file() else None
            else:
                text = tp.read_text("utf-8")
        elif source_bytes is None:
            candidate = p.with_suffix(".txt")
            text = candidate.read_text("utf-8") if candidate.is_file() else None

        try:
            report = verify(p.read_bytes(), log_key, cited_text=text,
                            source_bytes=source_bytes)
            outcome, status = report.outcome, report.exit_status
        except MissingInput as exc:
            # A usage error is not a verdict. Reporting it as one would let a
            # missing text file read as a clean pass.
            print(f"::error file={path}::cannot verify: {exc}")
            rows.append({"receipt": path, "outcome": "NOT_CHECKED", "exit_status": 64})
            failed += 1
            continue

        rows.append({"receipt": path, "outcome": outcome, "exit_status": status})
        if outcome in allowed:
            print(f"{ICON.get(outcome,'')} {path}: {outcome}")
        else:
            failed += 1
            print(f"::error file={path}::{outcome} — {MEANING.get(outcome,'')}")

    output("outcomes", json.dumps(rows))
    output("failed", str(failed))
    summary(rows, allowed, failed)
    print(f"\n{len(rows) - failed} of {len(rows)} receipt(s) reached an accepted outcome.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
