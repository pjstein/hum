from pathlib import Path

from hum_reference.cli import main


def test_hum_vectors_writes_readme_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "vectors"
    assert main(["--out", str(out)]) == 0
    assert (out / "README.md").read_text().startswith("# vectors")


def test_hum_vectors_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    main(["--out", str(a)])
    main(["--out", str(b)])
    assert (a / "README.md").read_bytes() == (b / "README.md").read_bytes()
