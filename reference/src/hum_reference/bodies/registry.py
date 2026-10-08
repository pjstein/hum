"""Import every body module so each registers its hooks with ``manifest``.

``manifest.verify_bundle`` imports this lazily, which keeps ``manifest`` free of a
circular import at module load.
"""

from __future__ import annotations

import importlib

MODULES = [
    "context",
    "deck",
    "release",
    "issue_map",
    "take",
    "agent_sponsor",
    "verifier",
    "trust_list",
    "service",
]

for _name in MODULES:
    try:
        importlib.import_module(f"hum_reference.bodies.{_name}")
    except ModuleNotFoundError as e:  # a body not written yet
        if e.name != f"hum_reference.bodies.{_name}":
            raise
