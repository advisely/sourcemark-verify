"""The GitHub Action runner, driven the way Actions drives it.

Everything crosses the boundary as environment variables and files, exactly as
in a workflow, so the test exercises the glue rather than importing past it.
The glue is where actions go wrong: an empty glob that passes, a JSON output
truncated at its first newline, a usage error reported as a clean run.

Run:  python3 -m tests.test_action

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(__file__.rsplit("/tests/", 1)[0]))

from tests import vectors  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def run(workdir: pathlib.Path, **env) -> tuple[int, str, dict, str]:
    out_file = workdir / "gh_output"
    sum_file = workdir / "gh_summary"
    out_file.write_text("")
    sum_file.write_text("")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "action" / "run.py")],
        capture_output=True, text=True, cwd=workdir,
        env={**os.environ, "PYTHONPATH": str(ROOT),
             "GITHUB_OUTPUT": str(out_file), "GITHUB_STEP_SUMMARY": str(sum_file),
             **env},
    )
    raw = out_file.read_text()
    outputs = {}
    for name in ("outcomes", "failed"):
        marker = f"{name}<<__SM__\n"
        if marker in raw:
            body = raw.split(marker, 1)[1].split("\n__SM__", 1)[0]
            outputs[name] = body
    return proc.returncode, proc.stdout + proc.stderr, outputs, sum_file.read_text()


def main() -> int:
    try:
        root, manifest = vectors.load()
    except FileNotFoundError as exc:
        print(f"  SKIP  {exc}")
        return 0

    work = pathlib.Path(tempfile.mkdtemp())
    receipts = work / "receipts"
    receipts.mkdir()
    # Each receipt beside its own text, which is the layout the action pairs
    # by stem when given a glob.
    wanted = {"valid": "VERIFIED", "erased": "ERASED", "tampered": "TAMPERED"}
    for name in wanted:
        shutil.copy(root / "vectors" / name / "receipt.cbor", receipts / f"{name}.cbor")
        shutil.copy(root / "vectors" / name / "text.txt", receipts / f"{name}.txt")
    key = str(root / manifest["log_public_key"])

    print("A single verified receipt")
    code, log, out, summary = run(
        work, SM_RECEIPT=str(receipts / "valid.cbor"), SM_LOG_KEY=key,
        SM_TEXT=str(receipts / "valid.txt"), SM_ALLOW="VERIFIED")
    check("exits 0", code == 0, log.strip().splitlines()[-1] if log.strip() else "")
    check("reports the outcome as JSON",
          json.loads(out["outcomes"])[0]["outcome"] == "VERIFIED")
    check("writes a job summary", "Sourcemark receipts" in summary)

    print("\nA glob, with texts paired by stem")
    code, log, out, summary = run(
        work, SM_RECEIPT=str(receipts / "*.cbor"), SM_LOG_KEY=key,
        SM_TEXT=str(receipts), SM_ALLOW="VERIFIED")
    rows = {r["receipt"].split("/")[-1]: r["outcome"] for r in json.loads(out["outcomes"])}
    check("every receipt is checked", len(rows) == 3, str(sorted(rows)))
    check("each reaches its own outcome",
          all(rows[f"{n}.cbor"] == o for n, o in wanted.items()), str(rows))
    check("the job fails because TAMPERED and ERASED were not allowed", code == 1)
    check("and it says how many", out["failed"] == "2", out.get("failed"))

    print("\n`allow` is the operator's call, in writing")
    code, log, out, _ = run(
        work, SM_RECEIPT=str(receipts / "*.cbor"), SM_LOG_KEY=key,
        SM_TEXT=str(receipts), SM_ALLOW="VERIFIED,ERASED")
    check("an erased document under a retention policy can pass", code == 1 and out["failed"] == "1",
          "only the tampered one is left")
    code, log, out, _ = run(
        work, SM_RECEIPT=str(receipts / "*.cbor"), SM_LOG_KEY=key,
        SM_TEXT=str(receipts), SM_ALLOW="VERIFIED,ERASED,TAMPERED")
    check("but nothing stops an operator writing TAMPERED down on purpose",
          code == 0, "it is in the workflow file, in the repository, in a diff")

    print("\nThe quiet failures")
    code, log, out, _ = run(work, SM_RECEIPT=str(work / "nothing" / "*.cbor"),
                            SM_LOG_KEY=key, SM_ALLOW="VERIFIED")
    check("an empty glob fails rather than passing having checked nothing", code == 1)
    check("and says so", "checked nothing" in log)

    lonely = work / "lonely"
    lonely.mkdir()
    shutil.copy(root / "vectors/valid/receipt.cbor", lonely / "valid.cbor")   # no .txt
    code, log, out, _ = run(work, SM_RECEIPT=str(lonely / "valid.cbor"), SM_LOG_KEY=key,
                            SM_ALLOW="VERIFIED")
    check("a receipt with no cited text is NOT_CHECKED, not a pass",
          code == 1 and json.loads(out["outcomes"])[0]["outcome"] == "NOT_CHECKED")

    print("\nThe strongest check, through the action")
    src = work / "source.bin"
    src.write_bytes((root / manifest["source"]).read_bytes())
    code, log, out, _ = run(work, SM_RECEIPT=str(receipts / "valid.cbor"), SM_LOG_KEY=key,
                            SM_SOURCE=str(src), SM_ALLOW="VERIFIED")
    check("--source verifies against the document itself", code == 0)
    edited = bytearray(src.read_bytes())
    edited[98211 + 4] ^= 0x20
    (work / "edited.bin").write_bytes(bytes(edited))
    code, log, out, _ = run(work, SM_RECEIPT=str(receipts / "valid.cbor"), SM_LOG_KEY=key,
                            SM_SOURCE=str(work / "edited.bin"), SM_ALLOW="VERIFIED")
    check("one edited byte in the source turns the job red",
          code == 1 and json.loads(out["outcomes"])[0]["outcome"] == "TAMPERED")

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
