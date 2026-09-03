# sourcemark-verify

**The verifier.** Checks a Sourcemark receipt offline, with no account, no network call, and no trust in the party that issued it.

**Licence:** Apache-2.0. Non-negotiable. The product claim is *"you do not have to trust us"*; a verifier under any restrictive licence refutes the claim it exists to support.

This is the trust asset. It must keep working if the company does not — which is why it lives in its own repository, with its own history, its own releases, and a dependency list short enough to read in one sitting.

---

## What it does

```
sourcemark verify receipt.cbor --log-key public.pem --source original.pdf
```

Folds three Merkle inclusion proofs, checks two signatures, re-derives the cited text from the original file at the recorded byte range, and confirms the commitment predates the answer. Every input comes from outside the system under audit.

## Seven outcomes, never a boolean

`VERIFIED` · `ERASED` · `PENDING` · `TAMPERED` · `FORGED` · `BACKDATED` · `UNSIGNED`

`TAMPERED`, `FORGED`, `BACKDATED` and `UNSIGNED` are distinct failures pointing at different culprits — the storage layer, the receipt issuer, the timeline, and the log operator respectively. A boolean would hide which one occurred.

`ERASED` is not `INVALID`: it is the correct outcome for a chunk whose key was destroyed, where the tree is unchanged and the proofs still fold. `PENDING` is not a failure either — it resolves on its own when the batch window closes.

Precedence between them is fixed by the specification, so two conforming verifiers handed the same broken receipt name the same failure rather than two defensible ones.

## Running it

```bash
pip install -e .
tests/fetch-vectors.sh main          # the vectors live in the spec repository
python3 -m tests                     # 71 checks

sourcemark-verify receipt.cbor --log-key log.pem --text chunk.txt
sourcemark-verify receipt.cbor --log-key log.pem --source original.pdf
```

Exit statuses: `0` verified, `1` a custody failure, `2` malformed, `3` pending, `4` erased, `64` a usage error such as a missing cited text. Distinct on purpose, so a CI job can treat `PENDING` as a retry and `ERASED` as a pass-with-note without parsing prose.

## Phase 0 deliverable — done

| Item | Status |
|---|---|
| Seven outcomes, plus `MALFORMED`, with fixed precedence | 16 of 16 conformance vectors |
| `--source` re-derivation from the original file | done, and reported as a distinct claim from `--text` |
| Offline | enforced by a test that disables `socket` and re-runs every vector |
| Both log profiles | our own COSE tree heads, and Rekor's leaf format with signed-note checkpoints |
| Small enough to audit by hand | four files, one dependency |

## Three things it refuses to do

**It will not verify without the cited text.** Without it, the content-binding check cannot run and everything else proves only that *some* leaf is in the tree — not that it is the leaf backing the sentence in front of you. Handed no text it exits `64` by name. It does not downgrade to a weaker verdict, because a weaker verdict rendered in a terminal is read as a pass.

**It will not repair its input.** No whitespace trimming, no Unicode normalization, no line-ending fixes. Every one of those changes what was committed to, and a verifier that quietly repairs has stopped checking anything. A trailing newline is `TAMPERED`, and that is correct.

**It will not accept an input it can recompute.** Under our own log profile the entry bytes are rebuilt from `corpus_root` and `committed_at`, and a receipt that supplies them is rejected outright rather than ignored — ignoring an unexpected field is how an input the issuer chose gets read by the next version.

## In CI, as a GitHub Action

```yaml
- uses: advisely/sourcemark-verify@v0
  with:
    receipt: receipts/*.cbor
    log-key: keys/log.pem
    source: docs/SOP-114.pdf
    allow: VERIFIED,ERASED     # what your deployment accepts, in writing
```

Fails the job unless every receipt reaches an outcome the workflow named, and writes a table into the run summary.

**`allow` is an input rather than a default** because the wrong default is dangerous in both directions. A team with a retention policy legitimately sees `ERASED` and should not go red over a document they deliberately destroyed; a team anchoring in batches legitimately sees `PENDING` and wants a retry rather than an incident. Neither gets folded silently into "pass" — the workflow has to say which it accepts, in the repository, in a diff.

Everything else is not configurable. There is no lenient mode, no warn-only for `TAMPERED`, and no way to ask for a boolean. And an **empty glob fails the job**: a run that checked nothing is the quietest way for this to stop protecting anything.

## Phase 1

WASM build behind `verify.sourcemark.dev` — drag and drop, nothing uploaded, an empty network tab in view-source. Strategically more important than the SDK, because it is the surface used by people who are not customers, and that is where the adoption loop closes.

Plus a GitHub Action, so a receipt can be checked in CI by someone who will never run `npm install`.

## Acceptance

> A person who has never had access to our code, our infrastructure, or our design partner's systems is handed three files: an answer, a receipt, and the original PDF. Using only this verifier and a public key, they determine — correctly, offline, in under a minute — that the cited text is genuinely at page 47 of that document and that the commitment predates the answer.

Binary, cheap to run, and not passable by a system that does not work.

## Design constraints

- **Small enough to audit by hand.** Every dependency added is trust the reader must extend.
- **Reproducible builds**, Sigstore-signed releases, published SBOM.
- **No telemetry, ever.** Not "opt-out" — absent.
- **No permissive parsing.** A verifier that tolerates structure it does not recognise is a place for a forged receipt to hide.

## The specification

This repository implements a format it does not define. The normative documents — the CDDL, the canonicalization rules, the verification procedure, and the conformance vectors — live in [`advisely/sourcemark`](https://github.com/advisely/sourcemark) under `spec/` and `conformance/`, licensed CC0.

That separation is deliberate and is the acceptance criterion for the spec itself:

> A second implementer writes a working verifier **from `spec/` alone**, without reading this repository.

Until that is true, the format is a product rather than a standard. This verifier is the first implementation, not the definition — and a change here that the spec does not require is a bug here.

## Conformance

This verifier passes every vector in `advisely/sourcemark`'s `conformance/` directory at a pinned spec tag. The vectors are **not vendored here** — `tests/fetch-vectors.sh` clones them, and the suite skips loudly without them. A verifier shipping its own copy of the tests it must pass can drift from the specification and keep reporting green, which is the exact failure this repository exists to make impossible. Pinned rather than floating, too: a verifier that silently follows `main` can be made to pass by editing the tests.

Four of the sixteen are the ones worth caring about. `unsigned-wrong-log`, `rekor-unpinned-body`, `rekor-checkpoint-mismatch` and `internal-with-entry-body` are each internally consistent and carry real signatures, and each reports `VERIFIED` under an implementation that folds proofs without asking what the proof was over.

## What the separate repository has already caught

The boundary is not ceremonial. Because this code shares nothing with the emitter — its CBOR, its Merkle folding and its decision procedure are separate implementations written from `spec/` — the first thing it produced was a defect in the vectors themselves: one carried a `byte_range` 433 bytes long around 156 bytes of text, so `--source` could never have passed. Every test inside the specification repository was green.
