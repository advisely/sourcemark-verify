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

## Phase 0 deliverable

| Item | Detail |
|---|---|
| `sourcemark verify` | Static CLI binary, no runtime dependency |
| Seven outcomes | Distinct exit statuses, so CI can treat `PENDING` as retry and `ERASED` as pass-with-note |
| `--source` | Re-derives the chunk from the original file at the recorded byte range |
| Offline | Zero network calls. Enforced by a test that fails if a socket opens. |

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

This verifier must pass every vector in `advisely/sourcemark`'s `conformance/` directory at a pinned spec tag. CI enforces it. An implementation returning `VERIFIED` for anything under `tampered/` is non-conforming, and that has to be checkable by someone who does not work here.
