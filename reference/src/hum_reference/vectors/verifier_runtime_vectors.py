"""Vectors for docs/specs/verifier-runtime.md that need no WebAssembly runtime: datasets and
their salted trees (rule 15), build recipes (rule 16), duplicate masking (rule 12) and the
reserved rejection codes. Module instantiation, host checks 7-11 and ``decide`` runs are
pending a component-model runtime and the profile binaries.
"""

from __future__ import annotations

from .. import cbor, fixtures
from .. import manifest as m
from ..bodies import verifier as vf
from ..bodies import verifier_runtime as vr
from ..cid import cid as compute_cid
from . import File, hexify, jsonable
from .verifier_vectors import TOOLCHAIN, World, district

SPEC = "verifier-runtime"

# A synthetic voter file: generated names and streets, no real person.
VOTERS = [
    (b"rec-0001", [("name", "Ada Lane"), ("street", "12 Mill St"), ("ward", "1")]),
    (b"rec-0002", [("name", "Ben Orchard"), ("street", "40 River Rd"), ("ward", "2")]),
    (b"rec-0003", [("name", "Cleo Marsh"), ("street", "7 Hill Ave"), ("ward", "3")]),
    (b"rec-0004", [("name", "Dev Field"), ("street", "88 Mill St"), ("ward", "1")]),
    (b"rec-0005", [("name", "Eli Grove"), ("street", "3 Pond Way"), ("ward", "2")]),
    (b"rec-0006", [("name", "Fay Brook"), ("street", "19 Hill Ave"), ("ward", "3")]),
]
SALT = fixtures.fixed_bytes("voters-salt")


def datasets_file() -> File:
    f = File(
        SPEC,
        "datasets",
        "Dataset records, the salted RFC 9162 tree, inclusion proofs valid and "
        "tampered, and a public dataset blob whose recomputed root must equal the manifest's commitment "
        "(rule 15). Records are synthetic.",
    )
    root = vr.dataset_root(SALT, VOTERS)
    recs = [vr.record_bytes(k, fl) for k, fl in VOTERS]
    f.add(
        "dataset-tree",
        "Six synthetic voter records: record bytes, salted leaf hashes, root",
        "Datasets",
        {"salt": hexify(SALT), "records": [{"key": hexify(k), "fields": fl} for k, fl in VOTERS]},
        {
            "record_bytes": [hexify(r) for r in recs],
            "root": hexify(root),
            "empty_root": hexify(vr.dataset_root(SALT, [])),
        },
    )
    for i in (0, 3, 5):
        proof = vr.inclusion_proof(SALT, VOTERS, i)
        k, fl = VOTERS[i]
        assert vr.verify_inclusion(SALT, k, fl, i, len(VOTERS), proof, root)
        f.add(
            "dataset-proof",
            f"Inclusion proof for record {i}",
            "Datasets",
            {
                "salt": hexify(SALT),
                "key": hexify(k),
                "fields": fl,
                "index": i,
                "size": len(VOTERS),
                "root": hexify(root),
            },
            {"proof": [hexify(h) for h in proof], "valid": True},
        )
    proof = vr.inclusion_proof(SALT, VOTERS, 2)
    k, fl = VOTERS[2]
    bad = [
        (
            "tampered-field",
            k,
            [("name", "Cleo Marsh"), ("street", "7 Hill Ave"), ("ward", "1")],
            2,
            proof,
        ),
        ("substituted-record", VOTERS[1][0], VOTERS[1][1], 2, proof),
        ("wrong-index", k, fl, 3, proof),
        ("wrong-salt-length-proof", k, fl, 2, proof[:-1]),
    ]
    for name, kk, ff, idx, pr in bad:
        assert not vr.verify_inclusion(SALT, kk, ff, idx, len(VOTERS), pr, root)
        f.add(
            "dataset-proof-bad",
            f"Dataset proof fails (rejection code 4): {name}",
            "Datasets",
            {
                "salt": hexify(SALT),
                "key": hexify(kk),
                "fields": ff,
                "index": idx,
                "size": len(VOTERS),
                "proof": [hexify(h) for h in pr],
                "root": hexify(root),
            },
            rejection={"step": None, "check": "dataset-lookup", "rule": "code-4", "reason": name},
        )
    blob = vr.dataset_blob(SALT, VOTERS)
    f.add(
        "dataset-public-blob",
        "Public dataset blob [salt, record...] and its recomputed root (rule 15)",
        "Datasets",
        {"blob": hexify(blob), "cid": hexify(compute_cid(blob))},
        {"root": hexify(vr.dataset_blob_root(blob)), "equals_commitment": True},
    )
    other = vr.dataset_blob(fixtures.fixed_bytes("other-salt"), VOTERS)
    f.add(
        "dataset-public-blob-mismatch",
        "A blob under another salt does not reproduce the commitment",
        "Datasets",
        {"blob": hexify(other), "commitment": hexify(root)},
        rejection={
            "step": None,
            "check": "dataset-blob",
            "rule": "15",
            "reason": "root differs from commitment",
        },
    )
    return f


def build_file() -> File:
    f = File(
        SPEC,
        "build",
        "Build recipes per profile and rule 16: source, toolchain and lang equal the "
        "manifest's. The module bytes here are placeholders; CI rebuilds real modules.",
    )
    w = World()
    for profile in vf.NAMED_PROFILES:
        recipe = w.w.blobs[w.blobs[f"build-{profile}"]]
        f.add(
            "build-recipe",
            f"Build recipe blob for the {profile} profile",
            "Reproducible builds",
            {"profile": profile, "code_cid": hexify(w.blobs[f"code-{profile}"])},
            {
                "recipe": hexify(recipe),
                "view": jsonable(cbor.decode(recipe)),
                "cid": hexify(w.blobs[f"build-{profile}"]),
            },
        )
    env = m.envelope("verifier", district(w, 1), authority=w.authority, issued=fixtures.ISSUED)
    recipe = w.w.blobs[w.blobs["build-district"]]
    assert vr.check_build_recipe(recipe, env) == []
    f.add(
        "build-check",
        "The district recipe matches its manifest (rule 16)",
        "Reproducible builds",
        {"recipe": hexify(recipe), "manifest_view": jsonable(env)},
        {"problems": []},
    )
    bad = vr.build_recipe(
        fixtures.fixed_bytes("source-district"),
        "x",
        "img",
        ["cargo"],
        "out",
        "rustc 1.98.0, target wasm32-wasip2",
        "en",
    )
    problems = vr.check_build_recipe(bad, env)
    assert problems
    f.add(
        "build-check-toolchain",
        "A recipe whose toolchain differs from code.toolchain fails rule 16",
        "Reproducible builds",
        {"recipe": hexify(bad), "expected_toolchain": TOOLCHAIN},
        rejection={"step": None, "check": "build-recipe", "rule": "16", "reason": problems[0]},
    )
    return f


def masking_file() -> File:
    f = File(
        SPEC,
        "masking",
        "Rule 12: the phone-visible code for a duplicate is 0 unless every required "
        "evidence item binds the submitter (document, selfie, credential, device). The logged code is "
        "always the true one. Also the reserved code table.",
    )
    f.add(
        "rejection-codes",
        "Reserved rejection codes 0-5",
        "Exports",
        {},
        {"codes": vr.RESERVED_CODES},
    )
    cases = [
        ("district-duplicate", 1, ["voter-file"], 0),
        ("uniqueness-document-selfie-device", 1, ["device", "document", "selfie"], 1),
        ("uniqueness-device-phone", 1, ["device", "phone"], 0),
        ("no-match-unmasked", 0, ["voter-file"], 0),
        ("missing-evidence-unmasked", 2, ["voter-file"], 2),
    ]
    for name, code, kinds, expected in cases:
        assert vr.mask_rejection(code, kinds) == expected
        f.add(
            "mask",
            f"Masking: {name}",
            "What the host does with a decision",
            {"true_code": code, "required_evidence_kinds": kinds},
            {"phone_code": expected, "logged_code": code},
        )
    return f


def generate() -> list[File]:
    return [datasets_file(), build_file(), masking_file()]
