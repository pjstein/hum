import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from hum_reference import cbor, fixtures, merkle
from hum_reference import manifest as m
from hum_reference.bodies import verifier_runtime as vr
from hum_reference.vectors import verifier_runtime_vectors as vrv
from hum_reference.vectors import verifier_vectors as vv


def test_salted_tree_matches_merkle_over_salted_leaves():
    salt = vrv.SALT
    root = vr.dataset_root(salt, vrv.VOTERS)
    recs = [vr.record_bytes(k, f) for k, f in sorted(vrv.VOTERS, key=lambda r: r[0])]
    assert root == merkle.root_hash([salt + r for r in recs])
    assert vr.dataset_root(salt, []) == hashlib.sha256(b"").digest()
    with pytest.raises(ValueError):
        vr.dataset_root(salt, [vrv.VOTERS[0], vrv.VOTERS[0]])


def test_record_bytes_are_canonical_cbor():
    r = vr.record_bytes(b"k", [("a", "1"), ("b", "2")])
    assert cbor.decode(r) == [b"k", [["a", "1"], ["b", "2"]]]


def test_proofs_verify_and_tampering_fails():
    salt, recs = vrv.SALT, vrv.VOTERS
    root = vr.dataset_root(salt, recs)
    for i, (k, f) in enumerate(recs):
        proof = vr.inclusion_proof(salt, recs, i)
        assert vr.verify_inclusion(salt, k, f, i, len(recs), proof, root)
        assert not vr.verify_inclusion(salt, k, f + [("x", "y")], i, len(recs), proof, root)
        assert not vr.verify_inclusion(bytes(32), k, f, i, len(recs), proof, root)


def test_public_blob_root_equals_commitment():
    blob = vr.dataset_blob(vrv.SALT, vrv.VOTERS)
    assert vr.dataset_blob_root(blob) == vr.dataset_root(vrv.SALT, vrv.VOTERS)
    assert cbor.decode(blob)[0] == vrv.SALT


def test_build_recipe_rule_16():
    w = vv.World()
    env = m.envelope("verifier", vv.district(w, 1), authority=w.authority, issued=fixtures.ISSUED)
    recipe = w.w.blobs[w.blobs["build-district"]]
    assert vr.check_build_recipe(recipe, env) == []
    bad = vr.build_recipe(b"\x00" * 32, "r", "i", ["c"], "o", vv.TOOLCHAIN, "fr", [(50, "x")])
    problems = vr.check_build_recipe(bad, env)
    assert any("source" in p for p in problems) and any("lang" in p for p in problems)
    assert any("outside 100..999" in p for p in problems)


def test_wall_clock_is_the_normative_limit():
    assert vr.DECIDE_WALL_CLOCK_SECONDS == 10
    assert "cargo-component" not in vv.TOOLCHAIN


def test_masking_rule_12():
    assert vr.mask_rejection(1, ["voter-file"]) == 0
    assert vr.mask_rejection(1, ["device", "document", "selfie"]) == 1
    assert vr.mask_rejection(1, ["device", "phone"]) == 0
    assert vr.mask_rejection(3, ["voter-file"]) == 3


def test_generator_deterministic():
    def tree():
        out = Path(tempfile.mkdtemp())
        for f in vrv.generate():
            f.write(out)
        return {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*.json")}

    a, b = tree(), tree()
    assert a == b and len(a) == 3
    for data in a.values():
        for case in json.loads(data)["cases"]:
            assert ("expected" in case) != ("rejection" in case)
