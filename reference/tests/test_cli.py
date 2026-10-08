import filecmp
import json
from pathlib import Path

import pytest

from hum_reference.cli import main

EXPECTED_DIRS = {
    "manifest",
    "log",
    "services",
    "storage",
    "release",
    "issue-map",
    "agent-sponsor",
    "verifier",
    "trust-list",
    "verifier-runtime",
    "chat",
}


def test_hum_vectors_writes_tree_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "vectors"
    assert main(["--out", str(out)]) == 0
    assert (out / "README.md").read_text().startswith("# vectors")
    assert {p.name for p in out.iterdir() if p.is_dir()} >= EXPECTED_DIRS


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_hum_vectors_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    main(["--out", str(a)])
    main(["--out", str(b)])
    assert _tree(a) == _tree(b)
    cmp = filecmp.dircmp(a, b)
    assert not cmp.diff_files and not cmp.left_only and not cmp.right_only


def test_every_case_is_well_formed(tmp_path: Path) -> None:
    out = tmp_path / "vectors"
    main(["--out", str(out)])
    ids: set[str] = set()
    steps_with_rejection: set[int] = set()
    for path in out.rglob("*.json"):
        doc = json.loads(path.read_text())
        assert doc["spec"] == path.parent.name and doc["file"] == path.stem
        for case in doc["cases"]:
            assert case["id"] not in ids, case["id"]
            ids.add(case["id"])
            assert case["id"].startswith(f"{doc['spec']}/{doc['file']}/")
            assert case["description"] and case["section"]
            assert ("expected" in case) != ("rejection" in case)
            if "rejection" in case and doc["spec"] == "manifest" and doc["file"] == "verification":
                steps_with_rejection.add(case["rejection"]["step"])
    assert steps_with_rejection == set(range(1, 12))


def test_regenerating_into_an_existing_tree_removes_stale_files(tmp_path: Path) -> None:
    out = tmp_path / "vectors"
    main(["--out", str(out)])
    stale = out / "manifest" / "stale.json"
    stale.write_text("{}")
    main(["--out", str(out)])
    assert not stale.exists()


def test_failed_generation_leaves_existing_vectors_intact(tmp_path, monkeypatch):
    from hum_reference import cli

    out = tmp_path / "vectors"
    (out / "release").mkdir(parents=True)
    (out / "release" / "sigmas.json").write_text("{}")
    (out / "README.md").write_text("old")

    def boom(_):
        raise TypeError("cannot render Fraction")

    monkeypatch.setattr(cli, "write_all", boom)
    with pytest.raises(TypeError):
        cli.write_vectors(out)
    assert (out / "release" / "sigmas.json").read_text() == "{}"
    assert (out / "README.md").read_text() == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["vectors"]
