"""The decision procedure of `spec/verification.md`.

Seven outcomes and an error, in a fixed order where the first failure is the
answer. The order is not a preference. A doubly-broken receipt has more than
one true verdict, and if two verifiers pick differently then the verdict
carries no information; §3 of the specification fixes the choice so that two
conforming implementations handed the same broken receipt name the same
culprit.

Three rules shape everything below.

**Nothing runs downstream of a tree head that has not been established as
trustworthy.** Check 1 compares the supplied key against `log_id` and stops on
mismatch, so a receipt naming a log the auditor never agreed to trust cannot
verify against whichever key happened to travel with it.

**The verifier never accepts an input it can recompute.** The log entry bytes
are rebuilt from `corpus_root` and `committed_at`; a receipt that supplies
them is supplying an input to the check meant to constrain it, and is refused.

**The verifier never repairs its input.** No whitespace trimming, no Unicode
normalization, no line-ending fixes before hashing. Each of those changes what
was committed to, and a verifier that quietly repairs has stopped checking.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils

from .cbor import CborError, Tagged, decode, encode

__all__ = ["Outcome", "Report", "Check", "verify", "load_log_key", "MissingInput"]

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
ALG_ES256, ALG_EDDSA = -7, -8
COSE_SIGN1_TAG = 18
CONTENT_TYPE = "application/vnd.sourcemark.receipt+cbor"
INTERNAL_PROFILE = "sourcemark.corpus.v1"
REKOR_PROFILE = "rekor.hashedrekord.v0.0.1"
PROFILES = (INTERNAL_PROFILE, REKOR_PROFILE)
HEAD_COSE, HEAD_NOTE = "cose.sth.v1", "note.checkpoint.v1"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# §7. Distinct statuses exist so a CI job can treat PENDING as a retry and
# ERASED as a pass-with-note without parsing human-readable output.
EXIT_STATUS = {
    "VERIFIED": 0,
    "TAMPERED": 1, "FORGED": 1, "BACKDATED": 1, "UNSIGNED": 1,
    "MALFORMED": 2,
    "PENDING": 3,
    "ERASED": 4,
}


class MissingInput(Exception):
    """A required input was not supplied. Exit 64, never a verdict."""


class Outcome(str):
    pass


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Report:
    outcome: str
    checks: list[Check] = field(default_factory=list)
    binding: str = "none"      # "text" | "source" | "erased" | "none"
    notes: list[str] = field(default_factory=list)

    @property
    def exit_status(self) -> int:
        return EXIT_STATUS[self.outcome]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------
# Merkle
# --------------------------------------------------------------------------


def fold(leaf: bytes, index: int, tree_size: int, path: list[bytes]) -> bytes:
    """RFC 6962 2.1.1, written the way the RFC writes it.

    A fold that terminates early accepts a truncated path, and a truncated
    path is a forgery -- so both the too-short and the too-long cases raise
    rather than returning whatever had accumulated.
    """
    if tree_size <= 0 or not 0 <= index < tree_size:
        raise ValueError(f"leaf index {index} outside a tree of size {tree_size}")
    fn, sn, r = index, tree_size - 1, leaf
    for sibling in path:
        if len(sibling) != 32:
            raise ValueError("path element is not a 32-byte digest")
        if sn == 0:
            raise ValueError("inclusion path is longer than the tree is deep")
        if fn & 1 or fn == sn:
            r = sha256(NODE_PREFIX + sibling + r)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = sha256(NODE_PREFIX + r + sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion path is shorter than the tree is deep")
    return r


# --------------------------------------------------------------------------
# Keys and signatures
# --------------------------------------------------------------------------


def load_log_key(data: bytes):
    """Accept PEM or DER SubjectPublicKeyInfo, and nothing else.

    Raw Ed25519 public keys are deliberately not accepted: `log_id` is
    SHA-256 over the SPKI DER, so a bare 32-byte key cannot be checked against
    the identity the receipt names.
    """
    try:
        return serialization.load_pem_public_key(data)
    except Exception:  # noqa: BLE001 - fall through to DER
        pass
    try:
        return serialization.load_der_public_key(data)
    except Exception as exc:  # noqa: BLE001
        raise MissingInput(f"could not read a public key from the supplied bytes: {exc}") from exc


def _spki_der(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4, with external_aad empty and staying empty: a receipt whose
    verification needs context the auditor was not handed is not offline."""
    return encode(["Signature1", protected, b"", payload])


def _verify_signature(key, alg: int, signature: bytes, message: bytes) -> None:
    """Raise InvalidSignature or ValueError. Never return a boolean."""
    if alg == ALG_EDDSA:
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("receipt claims EdDSA but the key is not Ed25519")
        key.verify(signature, message)
        return
    if alg == ALG_ES256:
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            raise ValueError("receipt claims ES256 but the key is not P-256")
        if len(signature) != 64:
            raise ValueError(f"ES256 signature must be 64 raw bytes, got {len(signature)}")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        # Low-s. Both s and n-s verify, so accepting high-s makes the
        # signature -- and therefore anything keyed on it -- malleable.
        if not 0 < s <= P256_ORDER // 2:
            raise ValueError("ES256 signature has a high s; canonicalization.md clause 5")
        if not 0 < r < P256_ORDER:
            raise ValueError("ES256 signature has an out-of-range r")
        key.verify(asym_utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return
    raise ValueError(f"alg {alg} is not permitted in v0.1")


def parse_note(checkpoint: bytes) -> tuple[bytes, str, int, bytes, list[tuple[str, bytes]]]:
    """Split a signed note into (signed body, origin, size, root, signatures).

    Format is the Go checksum-database note: an origin line, a decimal size, a
    base64 root, optional extension lines, a blank line, then one or more
    signature lines. The signature covers everything up to and including the
    newline that ends the last body line -- not the blank separator.
    """
    try:
        text = checkpoint.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CborError(f"a note checkpoint must be UTF-8: {exc}") from exc
    if "\n\n" not in text:
        raise CborError("the checkpoint has no blank line separating body from signatures")
    body, _, sig_block = text.partition("\n\n")
    body += "\n"
    lines = body.split("\n")
    if len(lines) < 4:
        raise CborError("a note checkpoint needs an origin, a size and a root hash")
    origin, size_line, root_line = lines[0], lines[1], lines[2]
    if not size_line.isdigit():
        raise CborError(f"the checkpoint's tree size {size_line!r} is not a decimal integer")
    try:
        root = base64.b64decode(root_line, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CborError(f"the checkpoint's root hash is not base64: {exc}") from exc
    if len(root) != 32:
        raise CborError(f"the checkpoint's root hash is {len(root)} bytes, expected 32")

    signatures: list[tuple[str, bytes]] = []
    for line in sig_block.split("\n"):
        if not line.strip():
            continue
        if not line.startswith("\u2014 "):
            raise CborError(f"malformed signature line: {line[:40]!r}")
        try:
            name, encoded = line[2:].split(" ", 1)
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise CborError(f"malformed signature line: {exc}") from exc
        if len(raw) < 5:
            raise CborError("a note signature needs a 4-byte key hint and a signature")
        signatures.append((name, raw[4:]))
    if not signatures:
        raise CborError("the checkpoint carries no signature")
    return body.encode("utf-8"), origin, int(size_line), root, signatures


def _verify_note(checkpoint: bytes, key) -> dict:
    """Verify a note under the SUPPLIED key, not under any key it names."""
    signed, origin, size, root, signatures = parse_note(checkpoint)
    for _, signature in signatures:
        try:
            if isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(signature, signed)
            else:
                key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
            return {"origin": origin, "tree_size": size, "root_hash": root,
                    "timestamp": None}
        except (InvalidSignature, ValueError):
            continue
    raise InvalidSignature("no signature on the checkpoint verifies under this key")


def _submitter_key(pem: bytes):
    """Rekor's `publicKey.content` is a bare public key OR an X.509 certificate.

    Almost every entry in the production log is the certificate form, because
    Fulcio issues a short-lived certificate for the signing identity. A
    verifier that only understands the bare form works against its own
    fixtures and fails against the real log, which is the worst possible place
    to find out -- so both are accepted here, and the difference is surfaced
    rather than smoothed over.

    The certificate's chain is deliberately NOT validated. It attests who
    submitted, and who submitted is reported and not required: anyone may
    submit a corpus root to a public log. Validating a chain would need a
    trust root the auditor has no reason to hold, to answer a question custody
    does not depend on.
    """
    try:
        return serialization.load_pem_public_key(pem)
    except Exception:  # noqa: BLE001 - fall through to the certificate form
        pass
    try:
        from cryptography import x509

        return x509.load_pem_x509_certificate(pem).public_key()
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"entry_body's publicKey is neither a PEM public key nor an X.509 "
            f"certificate: {exc}"
        ) from exc


def _rekor_leaf(entry_body: bytes, entry_data: bytes) -> tuple[bytes, str]:
    """Rekor's leaf, with entry_body pinned to our own entry_data.

    Step 3 of canonicalization.md 5.2 is the load-bearing line: without the
    digest comparison, entry_body is an arbitrary blob the issuer supplies to
    the check that is meant to constrain it, and the whole reason 5.1
    recomputes goes away.
    """
    try:
        parsed = json.loads(entry_body)
    except ValueError as exc:
        raise ValueError(f"entry_body is not JSON: {exc}") from exc
    if parsed.get("kind") != "hashedrekord" or parsed.get("apiVersion") != "0.0.1":
        raise ValueError(f"entry_body is {parsed.get('kind')!r}/{parsed.get('apiVersion')!r}, "
                         f"not hashedrekord/0.0.1")
    spec = parsed.get("spec", {})
    claimed = spec.get("data", {}).get("hash", {}).get("value")
    expected = sha256(entry_data).hex()
    if claimed != expected:
        raise ValueError(f"the logged artefact digest is {claimed}, but the corpus root and "
                         f"committed_at in this receipt hash to {expected}")
    signature_b64 = spec.get("signature", {}).get("content")
    key_b64 = spec.get("signature", {}).get("publicKey", {}).get("content")
    if not signature_b64 or not key_b64:
        raise ValueError("entry_body carries no submitter signature")
    submitter = _submitter_key(base64.b64decode(key_b64))
    signature = base64.b64decode(signature_b64)
    try:
        if isinstance(submitter, ed25519.Ed25519PublicKey):
            submitter.verify(signature, sha256(entry_data))
        else:
            submitter.verify(signature, sha256(entry_data),
                             ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    except InvalidSignature as exc:
        raise ValueError("the submitter signature inside entry_body does not verify") from exc
    fingerprint = sha256(submitter.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hex()
    return sha256(LEAF_PREFIX + entry_body), fingerprint


# --------------------------------------------------------------------------
# Check 0 -- parse and profile conformance
# --------------------------------------------------------------------------

_REQUIRED = {
    "receipt": {"receipt_version", "kind", "custody", "context"},
    "custody": {"source", "location", "derivation", "proof"},
    "source": {"document_id", "document_version_id", "source_uri",
               "content_hash", "committed_at"},
    "derivation": {"chunk_id", "parser", "salt_ref", "content_commitment", "opening"},
    "proof": {"leaf_hash", "document", "corpus", "log"},
    "log": {"url", "log_id", "entry_profile", "entry_id", "leaf_index",
            "tree_size", "path", "root_hash", "head_format", "signed_tree_head"},
    "context": {"query_id", "retriever", "retrieved_at"},
}
_OPTIONAL = {
    "receipt": {"support"},
    "custody": set(),
    "source": set(),
    "derivation": set(),
    "proof": set(),
    # entry_body is the ONLY optional member. Under the internal profile it is
    # forbidden outright, which is what stops a receipt handing the inclusion
    # check bytes the issuer chose.
    "log": {"entry_body"},
    "context": {"policy_ref"},
}


def _shape(name: str, node, problems: list[str]) -> None:
    if not isinstance(node, dict):
        problems.append(f"{name} is {type(node).__name__}, expected a map")
        return
    missing = _REQUIRED[name] - set(node)
    if missing:
        problems.append(f"{name} is missing {sorted(missing)}")
    extra = set(node) - _REQUIRED[name] - _OPTIONAL[name]
    if extra:
        problems.append(f"{name} carries {sorted(extra)}, which the CDDL does not declare")


def _digest(node, key: str, where: str, problems: list[str]) -> None:
    v = node.get(key) if isinstance(node, dict) else None
    if not isinstance(v, bytes) or len(v) != 32:
        problems.append(f"{where}.{key} is not a 32-byte digest")


def parse(receipt_bytes: bytes) -> tuple[dict, bytes, bytes, bytes]:
    """Return (receipt, protected, payload, signature) or raise CborError."""
    tagged = decode(receipt_bytes)
    if not isinstance(tagged, Tagged) or tagged.tag != COSE_SIGN1_TAG:
        raise CborError("not a tagged COSE_Sign1 (tag 18)")
    if not isinstance(tagged.value, list) or len(tagged.value) != 4:
        raise CborError("COSE_Sign1 must be a four-element array")
    protected, unprotected, payload, signature = tagged.value
    if unprotected != {}:
        raise CborError("the unprotected header must be empty")
    for label, v in (("protected", protected), ("payload", payload), ("signature", signature)):
        if not isinstance(v, bytes):
            raise CborError(f"{label} must be a byte string")
    header = decode(protected)
    if not isinstance(header, dict) or set(header) != {1, 3, 4}:
        raise CborError("the protected header must carry exactly alg, content type and kid")
    if header[1] not in (ALG_EDDSA, ALG_ES256):
        raise CborError(f"alg {header[1]!r} is not permitted in v0.1")
    if header[3] != CONTENT_TYPE:
        raise CborError(f"content type is {header[3]!r}, expected {CONTENT_TYPE!r}")
    if not isinstance(header[4], bytes):
        raise CborError("kid must be a byte string")

    receipt = decode(payload)
    problems: list[str] = []
    _shape("receipt", receipt, problems)
    if problems:
        raise CborError("; ".join(problems))
    if receipt["receipt_version"] != "0.1":
        raise CborError(f"receipt_version {receipt['receipt_version']!r} is not 0.1")
    if receipt["kind"] != "sourcemark.retrieval.receipt":
        raise CborError(f"kind {receipt['kind']!r} is not a retrieval receipt")

    custody = receipt["custody"]
    _shape("custody", custody, problems)
    if problems:
        raise CborError("; ".join(problems))
    for name, node in (("source", custody["source"]), ("derivation", custody["derivation"]),
                       ("proof", custody["proof"]), ("context", receipt["context"])):
        _shape(name, node, problems)
    _shape("log", custody["proof"].get("log"), problems)
    if problems:
        raise CborError("; ".join(problems))

    _digest(custody["source"], "content_hash", "source", problems)
    _digest(custody["derivation"], "content_commitment", "derivation", problems)
    _digest(custody["proof"], "leaf_hash", "proof", problems)
    _digest(custody["proof"]["log"], "log_id", "log", problems)
    _digest(custody["proof"]["log"], "root_hash", "log", problems)

    log_node = custody["proof"]["log"]
    if log_node.get("entry_profile") not in PROFILES:
        problems.append(f"log.entry_profile {log_node.get('entry_profile')!r} is not defined")
    if log_node.get("head_format") not in (HEAD_COSE, HEAD_NOTE):
        problems.append(f"log.head_format {log_node.get('head_format')!r} is not defined")
    if not isinstance(log_node.get("signed_tree_head"), bytes):
        problems.append("log.signed_tree_head must be a byte string")
    internal = log_node.get("entry_profile") == INTERNAL_PROFILE
    if internal and "entry_body" in log_node:
        problems.append(
            "log.entry_body is present under sourcemark.corpus.v1, whose leaf the "
            "verifier recomputes. Accepting it would hand the inclusion check an "
            "input the issuer chose (canonicalization.md 5.1)")
    if not internal and not isinstance(log_node.get("entry_body"), bytes):
        problems.append(f"{log_node.get('entry_profile')} requires entry_body")

    location = custody["location"]
    if not isinstance(location, dict) or "byte_range" not in location:
        problems.append("location.byte_range is mandatory")
    elif (not isinstance(location["byte_range"], list) or len(location["byte_range"]) != 2
          or not all(isinstance(v, int) and v >= 0 for v in location["byte_range"])):
        problems.append("location.byte_range must be two non-negative integers")

    opening = custody["derivation"]["opening"]
    if not isinstance(opening, dict):
        problems.append("derivation.opening must be a map")
    elif set(opening) == {"salt"}:
        if not isinstance(opening["salt"], bytes) or len(opening["salt"]) != 32:
            problems.append("opening.salt must be 32 bytes")
    elif set(opening) <= {"erased", "erased_at"} and opening.get("erased") is True:
        pass
    else:
        # Not an optional salt: "erased" and "the emitter forgot" must not be
        # the same bytes, so anything that is neither branch is malformed.
        problems.append(f"opening is neither a salt nor a stated tombstone: {sorted(opening)}")

    for key in ("committed_at",):
        if not isinstance(custody["source"][key], int) or custody["source"][key] < 0:
            problems.append(f"source.{key} must be integer milliseconds")
    if not isinstance(receipt["context"]["retrieved_at"], int):
        problems.append("context.retrieved_at must be integer milliseconds")

    support = receipt.get("support")
    if support is not None:
        if not isinstance(support, dict):
            problems.append("support must be a map")
        elif support.get("proven") is not False:
            # The CDDL types it as the literal false. A schema permitting true
            # permits a receipt asserting that a score is a proof.
            problems.append("support.proven must be the literal false")
        elif support.get("class") not in ("QUOTED", "SUPPORTED", "INFERRED", "UNSUPPORTED"):
            problems.append(f"support.class {support.get('class')!r} is not a defined class")

    for name, node in (("document", custody["proof"]["document"]),
                       ("corpus", custody["proof"]["corpus"]),
                       ("log", custody["proof"]["log"])):
        if not isinstance(node, dict):
            problems.append(f"proof.{name} must be a map")
            continue
        for key in ("leaf_index", "tree_size"):
            if not isinstance(node.get(key), int) or node[key] < 0:
                problems.append(f"proof.{name}.{key} must be a non-negative integer")
        if (not isinstance(node.get("path"), list)
                or not all(isinstance(h, bytes) and len(h) == 32 for h in node["path"])):
            problems.append(f"proof.{name}.path must be an array of 32-byte digests")

    if problems:
        raise CborError("; ".join(problems))
    return receipt, protected, payload, signature


# --------------------------------------------------------------------------
# The procedure
# --------------------------------------------------------------------------


def verify(
    receipt_bytes: bytes,
    log_key_bytes: bytes,
    *,
    cited_text: str | None = None,
    source_bytes: bytes | None = None,
    issuer_key_bytes: bytes | None = None,
    skew_tolerance_ms: int = 300_000,
    now_ms: int | None = None,
) -> Report:
    """Run the decision procedure. The first failure is the outcome."""
    report = Report(outcome="VERIFIED")

    def fail(outcome: str, name: str, detail: str) -> Report:
        report.checks.append(Check(name, False, detail))
        report.outcome = outcome
        return report

    def ok(name: str, detail: str = "") -> None:
        report.checks.append(Check(name, True, detail))

    # §2. The cited text is not optional.
    if cited_text is None and source_bytes is None:
        raise MissingInput(
            "no cited text. Without it, checks 4.4 and 4.7 cannot run and everything "
            "remaining proves only that SOME leaf is in the tree -- not that it is the "
            "leaf backing the sentence in front of you. Pass --text or --source."
        )

    # 0. Parse and profile conformance -> MALFORMED
    try:
        receipt, protected, payload, signature = parse(receipt_bytes)
    except CborError as exc:
        return fail("MALFORMED", "parse and profile conformance", str(exc))
    ok("parse and profile conformance", f"{len(receipt_bytes)} bytes, clause 2 profile")

    custody = receipt["custody"]
    proof, log = custody["proof"], custody["proof"]["log"]

    # 1. Log identity and tree-head signature -> UNSIGNED
    try:
        log_key = load_log_key(log_key_bytes)
    except MissingInput as exc:
        return fail("MALFORMED", "log identity", str(exc))
    supplied_id = sha256(_spki_der(log_key))
    if supplied_id != log["log_id"]:
        return fail("UNSIGNED", "log identity",
                    f"the receipt names log {log['log_id'].hex()[:16]}… but the key you "
                    f"supplied is {supplied_id.hex()[:16]}…. Without this check a receipt "
                    f"verifies against whichever key travels with it.")
    if log["head_format"] == HEAD_COSE:
        try:
            sth_tagged = decode(log["signed_tree_head"])
            if not isinstance(sth_tagged, Tagged) or sth_tagged.tag != COSE_SIGN1_TAG:
                raise CborError("the signed tree head is not a tagged COSE_Sign1")
            sth_protected, sth_unprotected, sth_payload, sth_signature = sth_tagged.value
            if sth_unprotected != {}:
                raise CborError("the tree head's unprotected header must be empty")
            sth_alg = decode(sth_protected).get(1)
            sth = decode(sth_payload)
            for key in ("log_id", "tree_size", "root_hash", "timestamp"):
                if key not in sth:
                    raise CborError(f"the signed tree head is missing {key}")
            if sth["log_id"] != log["log_id"]:
                raise CborError("the tree head signs a different log_id than the proof names")
        except CborError as exc:
            return fail("MALFORMED", "tree-head structure", str(exc))
        try:
            _verify_signature(log_key, sth_alg, sth_signature,
                              sig_structure(sth_protected, sth_payload))
        except (InvalidSignature, ValueError) as exc:
            return fail("UNSIGNED", "tree-head signature",
                        str(exc) or "the tree head's signature does not verify")
        head_detail = f"{log['url']} · tree_size {sth['tree_size']}"
    else:
        try:
            sth = _verify_note(log["signed_tree_head"], log_key)
        except CborError as exc:
            return fail("MALFORMED", "checkpoint structure", str(exc))
        except InvalidSignature as exc:
            return fail("UNSIGNED", "checkpoint signature", str(exc))
        # A checkpoint that signs a different tree than the proof claims is the
        # whole attack. Verifying the signature without checking what it signed
        # verifies nothing.
        if sth["tree_size"] != log["tree_size"] or sth["root_hash"] != log["root_hash"]:
            return fail("UNSIGNED", "checkpoint covers this proof",
                        f"the checkpoint signs tree_size {sth['tree_size']} root "
                        f"{sth['root_hash'].hex()[:16]}…, the proof claims "
                        f"{log['tree_size']} / {log['root_hash'].hex()[:16]}…")
        report.notes.append(f"Checkpoint origin: {sth['origin']}")
        head_detail = f"{sth['origin']} · tree_size {sth['tree_size']}"
    ok("log identity and tree-head signature", head_detail)

    # 2. Entry covered by this tree head -> PENDING
    if log["leaf_index"] >= sth["tree_size"]:
        return fail("PENDING", "entry covered by this tree head",
                    f"entry {log['leaf_index']} is not inside a tree of size "
                    f"{sth['tree_size']}. Not a failure: retry with a fresher tree head.")
    if log["tree_size"] > sth["tree_size"]:
        return fail("PENDING", "entry covered by this tree head",
                    f"the proof claims tree_size {log['tree_size']} but the head signs "
                    f"{sth['tree_size']}")
    ok("entry covered by this tree head", f"entry {log['leaf_index']} of {sth['tree_size']}")

    # 3. Leaf reconstruction and the three folds -> FORGED
    location = custody["location"]
    try:
        rebuilt = sha256(LEAF_PREFIX + encode([
            "sourcemark.leaf.v1",
            custody["source"]["document_version_id"],
            custody["derivation"]["chunk_id"],
            location.get("page"),
            location.get("bbox"),
            location["byte_range"],
            custody["derivation"]["content_commitment"],
        ]))
    except CborError as exc:
        return fail("MALFORMED", "leaf reconstruction", str(exc))
    if rebuilt != proof["leaf_hash"]:
        return fail("FORGED", "leaf reconstruction",
                    "the receipt misstates its own leaf: the coordinates and commitment "
                    "it carries do not hash to proof.leaf_hash")
    try:
        doc = proof["document"]
        if fold(proof["leaf_hash"], doc["leaf_index"], doc["tree_size"], doc["path"]) \
                != doc.get("doc_root"):
            return fail("FORGED", "chunk folds to doc_root",
                        "the document path does not reduce the leaf to doc_root")
        doc_leaf = sha256(LEAF_PREFIX + encode([
            "sourcemark.doc.v1",
            custody["source"]["document_version_id"],
            doc["doc_root"],
            doc["tree_size"],
        ]))
        corpus = proof["corpus"]
        if fold(doc_leaf, corpus["leaf_index"], corpus["tree_size"], corpus["path"]) \
                != corpus.get("corpus_root"):
            return fail("FORGED", "document folds to corpus_root",
                        "the corpus path does not reduce the document leaf to corpus_root")
        # The corpus entry construction does not change because the log did:
        # entry_data is recomputed with the sourcemark tag under every profile.
        entry_data = encode([INTERNAL_PROFILE, corpus["corpus_root"],
                             custody["source"]["committed_at"]])
        if log["entry_profile"] == INTERNAL_PROFILE:
            log_leaf = sha256(LEAF_PREFIX + entry_data)
        else:
            try:
                log_leaf, submitter = _rekor_leaf(log["entry_body"], entry_data)
            except ValueError as exc:
                return fail("FORGED", "external log entry", str(exc))
            report.notes.append(
                f"Submitted to {log['entry_profile']} by key {submitter[:16]}…. Who "
                f"submitted is reported, not required: anyone may submit a corpus root "
                f"to a public log, and it does not help them.")
        if fold(log_leaf, log["leaf_index"], log["tree_size"], log["path"]) != log["root_hash"]:
            return fail("FORGED", "log entry folds to the signed root",
                        "the recomputed log entry does not reduce to the root the tree "
                        "head signs")
        if log["root_hash"] != sth["root_hash"]:
            return fail("FORGED", "log root matches the tree head",
                        "the proof's root_hash is not the root the tree head signed")
    except (ValueError, CborError) as exc:
        return fail("FORGED", "inclusion proofs", str(exc))
    ok("leaf reconstruction and three folds",
       "chunk → doc_root → corpus_root → signed root")

    # 4. Content binding -> TAMPERED, or defer ERASED
    opening = custody["derivation"]["opening"]
    erased = opening.get("erased") is True
    if erased:
        report.binding = "erased"
        report.notes.append(
            "The version key was destroyed. The tree is unchanged, every proof folds, "
            "and no party -- including the issuer -- can produce a new opening. What "
            "the leaf committed to cannot be shown."
        )
        ok("content binding", "skipped: the opening is a stated tombstone")
    else:
        text = cited_text
        if source_bytes is not None:
            # Set before the checks, so a failure still says which path was
            # taken. "Failed against your text" and "failed against the
            # document" send an auditor to different places.
            report.binding = "source"
            start, end = location["byte_range"]
            if end > len(source_bytes):
                return fail("TAMPERED", "source re-derivation",
                            f"byte_range ends at {end} but the source file is "
                            f"{len(source_bytes)} bytes")
            derived = source_bytes[start:end]
            if cited_text is not None and derived != cited_text.encode("utf-8"):
                return fail("TAMPERED", "source re-derivation",
                            "the bytes at the recorded range in the source file are not "
                            "the text you supplied")
            try:
                text = derived.decode("utf-8")
            except UnicodeDecodeError as exc:
                return fail("TAMPERED", "source re-derivation",
                            f"the bytes at the recorded range are not UTF-8: {exc}")
        else:
            report.binding = "text"
        recomputed = hmac.new(opening["salt"], text.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(recomputed, custody["derivation"]["content_commitment"]):
            return fail("TAMPERED", "content binding",
                        f"HMAC over the cited text is {recomputed.hex()[:16]}… but the "
                        f"receipt commits to "
                        f"{custody['derivation']['content_commitment'].hex()[:16]}…")
        ok("content binding",
           "recomputed from the source file" if report.binding == "source"
           else "recomputed from the text you supplied")

    # 5. Ordering -> BACKDATED
    committed_at = custody["source"]["committed_at"]
    retrieved_at = receipt["context"]["retrieved_at"]
    if committed_at > retrieved_at:
        return fail("BACKDATED", "ordering",
                    f"the answer is dated {(committed_at - retrieved_at) / 1000:.0f}s "
                    f"BEFORE the commitment it cites")
    if sth.get("timestamp") is None:
        # A note checkpoint carries a tree size and a root and no clock. The
        # sub-check that the head does not predate the commitment therefore
        # cannot run, and saying nothing about that would be the quiet
        # downgrade this whole document exists to forbid. What survives is
        # committed_at <= retrieved_at above, plus the log's own append-only
        # history -- which is the stronger guarantee anyway, since a 2026
        # checkpoint cannot be manufactured in 2028.
        report.notes.append(
            "The tree head is a note checkpoint, which carries no timestamp, so the "
            "check that the head does not predate the commitment did not run. Ordering "
            "rests on the log's published history instead."
        )
    elif sth["timestamp"] < committed_at:
        return fail("BACKDATED", "ordering",
                    "the tree head predates the commitment it is supposed to cover")
    if now_ms is not None and retrieved_at > now_ms + skew_tolerance_ms:
        return fail("BACKDATED", "ordering",
                    f"the answer is dated {(retrieved_at - now_ms) / 1000:.0f}s in the "
                    f"future, beyond the {skew_tolerance_ms / 1000:.0f}s tolerance applied")
    ok("ordering", f"committed before the answer, tolerance {skew_tolerance_ms / 1000:.0f}s")

    # The issuer signature is checked last and on purpose. It is the weaker
    # claim: it says who assembled the receipt, not that anything in it is
    # true, and a receipt whose issuer key is unknown to the auditor is still
    # fully verifiable against the log.
    if issuer_key_bytes is not None:
        try:
            issuer_key = load_log_key(issuer_key_bytes)
            _verify_signature(issuer_key, decode(protected)[1], signature,
                              sig_structure(protected, payload))
            ok("issuer signature", "verifies against the key you supplied")
        except (InvalidSignature, ValueError, MissingInput) as exc:
            return fail("FORGED", "issuer signature", str(exc) or "does not verify")
    else:
        report.notes.append(
            "The issuer signature was not checked: no issuer key was supplied. It "
            "identifies who assembled this receipt and is not what makes it true."
        )

    report.outcome = "ERASED" if erased else "VERIFIED"
    return report
