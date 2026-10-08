"""Vector generation. One module per spec area; ``write_all`` writes the tree.

File shape (JSON, hex for bytes)::

    {
      "spec": "manifest",            # docs/specs/<spec>.md
      "file": "cbor",                 # this file's topic
      "cases": [
        {"id": "manifest/cbor/encode-001", "description": "...", "section": "...",
         "inputs": {...}, "expected": {...}}
        or
        {"id": ..., "description": ..., "section": ..., "inputs": {...},
         "rejection": {"step": 2, "reason": "..."}}
      ]
    }

Only the ``step`` of a rejection is normative; the reason text is advisory.
Values that are CBOR data use the JSON-with-tags form described in
``docs/specs/conformance.md`` (``{"hex": ...}`` for bytes, ``{"map": [[k, v]...]}``
for maps with non-text keys).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import cbor

__all__ = ["Case", "File", "hexify", "jsonable", "write_all"]


def hexify(b: bytes) -> str:
    return b.hex()


def jsonable(value: Any) -> Any:
    """Render a CBOR data item as JSON that round-trips the types."""
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, dict):
        return {"map": [[jsonable(k), jsonable(v)] for k, v in value.items()]}
    if isinstance(value, list | tuple):
        return [jsonable(v) for v in value]
    if isinstance(value, cbor.Tag):
        return {"tag": value.tag, "value": jsonable(value.value)}
    if isinstance(value, bool | int | str) or value is None:
        return value
    raise TypeError(f"cannot render {type(value).__name__}")


class Case(dict):
    """One vector case. Built with keyword arguments so the field order is fixed."""

    def __init__(
        self,
        id: str,
        description: str,
        section: str,
        inputs: dict[str, Any],
        expected: dict[str, Any] | None = None,
        rejection: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self["id"] = id
        self["description"] = description
        self["section"] = section
        self["inputs"] = inputs
        if expected is not None:
            self["expected"] = expected
        if rejection is not None:
            self["rejection"] = rejection
        if (expected is None) == (rejection is None):
            raise ValueError("a case has exactly one of expected or rejection")


class File:
    def __init__(self, spec: str, name: str, notes: str = "") -> None:
        self.spec = spec
        self.name = name
        self.notes = notes
        self.cases: list[Case] = []

    def add(
        self, suffix: str, description: str, section: str, inputs, expected=None, rejection=None
    ):
        n = len(self.cases) + 1
        case = Case(
            id=f"{self.spec}/{self.name}/{suffix}-{n:03d}",
            description=description,
            section=section,
            inputs=inputs,
            expected=expected,
            rejection=rejection,
        )
        self.cases.append(case)
        return case

    def write(self, out: Path) -> Path:
        d = out / self.spec
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{self.name}.json"
        doc = {"spec": self.spec, "file": self.name}
        if self.notes:
            doc["notes"] = self.notes
        doc["cases"] = self.cases
        path.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        return path


def write_all(out: Path) -> dict[str, dict[str, tuple[int, int]]]:
    """Write every vector file. Returns {spec: {file: (accepting cases, rejecting cases)}}."""
    from . import (
        agent_sponsor_vectors,
        ballot_vectors,
        chat_vectors,
        context_vectors,
        credentials_vectors,
        deck_vectors,
        issue_map_vectors,
        log_vectors,
        manifest_vectors,
        rating_vectors,
        release_body_vectors,
        release_vectors,
        services_vectors,
        shield_vectors,
        storage_more_vectors,
        storage_vectors,
        take_vectors,
        trust_list_vectors,
        verifier_runtime_vectors,
        verifier_vectors,
    )

    files: list[File] = []
    files += manifest_vectors.generate()
    files += log_vectors.generate()
    files += services_vectors.generate()
    files += storage_vectors.generate()
    files += storage_more_vectors.generate()
    files += release_vectors.generate()
    files += context_vectors.generate()
    files += deck_vectors.generate()
    files += release_body_vectors.generate()
    files += take_vectors.generate()
    files += rating_vectors.generate()
    files += issue_map_vectors.generate()
    files += agent_sponsor_vectors.generate()
    files += verifier_vectors.generate()
    files += trust_list_vectors.generate()
    files += verifier_runtime_vectors.generate()
    files += chat_vectors.generate()
    files += credentials_vectors.generate()
    files += ballot_vectors.generate()
    files += shield_vectors.generate()
    summary: dict[str, dict[str, tuple[int, int]]] = {}
    for f in files:
        f.write(out)
        ok = sum(1 for c in f.cases if "expected" in c)
        bad = len(f.cases) - ok
        summary.setdefault(f.spec, {})[f.name] = (ok, bad)
    return summary
