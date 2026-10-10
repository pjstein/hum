"""Sandbox component probes; these are not the five reference profile binaries."""

from .. import component_runtime as runtime
from ..cid import cid
from . import File


def generate():
    f = File(
        "verifier-runtime",
        "component-sandbox",
        "Executable small components, inline as hex. These are sandbox probes, not the five profile binaries. decide uses result<decision,rejection>. A fresh subprocess enforces at most ten seconds including native execution; host-selected fuel may stop earlier. No imports are currently linked: the spec's dotted import names and @0.1 world version need a pinned valid WIT ABI. The adapter permits one linear memory, capped at 64 MiB, to prevent per-memory cap multiplication. Multi-memory profile support, all host-world import calls and five profile builds remain gaps.",
    )
    for name, status in (
        ("empty-decision", "decision"),
        ("rejection", "rejected"),
        ("nan", "rejected"),
        ("memory-grow", "rejected"),
        ("loop", "module-limit"),
        ("stack", "module-limit"),
        ("memory-over", "module-limit"),
        ("wasi-import", "module-import"),
        ("wrong-abi", "module-abi"),
        ("shared-memory", "module-invalid"),
        ("relaxed-simd", "module-invalid"),
    ):
        module = runtime.probe(name)
        outcome = runtime.run(module, cid(module))
        assert outcome.status == status, (name, outcome)
        inputs = {
            "component": module.hex(),
            "code_cid": cid(module).hex(),
            "max_wall_seconds": runtime.WALL_SECONDS,
            "fuel": 1_000_000,
        }
        if outcome.value is not None:
            f.add(
                name,
                name.replace("-", " "),
                "The sandbox",
                inputs,
                expected={"status": status, "result": outcome.value},
            )
        else:
            f.add(
                name,
                name.replace("-", " "),
                "The sandbox",
                inputs,
                rejection={
                    "step": None,
                    "check": "component-sandbox",
                    "reason": status,
                    "retryable": outcome.retryable,
                    "issued": 0,
                    "dedup_writes": 0,
                },
            )
    module = runtime.probe("empty-decision")
    f.add(
        "wrong-cid",
        "Code CID mismatch is refused before instantiation",
        "Validation rule 1",
        {"component": module.hex(), "code_cid": cid(b"other module").hex()},
        rejection={"step": None, "check": "component-sandbox", "reason": "module-cid"},
    )
    f.add(
        "oversized",
        "A 16 MiB plus one byte input is refused before compilation",
        "Validation rule 3",
        {"repeat_byte": "00", "repeat_count": runtime.MODULE_BYTES + 1},
        rejection={
            "step": None,
            "check": "component-sandbox",
            "reason": "module-limit",
            "retryable": True,
        },
    )
    return [f]
