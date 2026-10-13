import multiprocessing
import os
import struct
import time

import pytest

from hum_reference import component_runtime as runtime
from hum_reference.cid import cid


@pytest.mark.parametrize(
    "name,status",
    [
        ("empty-decision", "decision"),
        ("rejection", "rejected"),
        ("loop", "module-limit"),
        ("stack", "module-limit"),
        ("memory-over", "module-limit"),
        ("wasi-import", "module-import"),
        ("wrong-abi", "module-abi"),
        ("shared-memory", "module-invalid"),
        ("relaxed-simd", "module-invalid"),
    ],
)
def test_components(name, status):
    module = runtime.probe(name)
    outcome = runtime.run(module, cid(module))
    assert outcome.status == status
    assert outcome.issued == outcome.dedup_writes == 0


def test_nan_and_memory_growth():
    for name in ("nan", "memory-grow"):
        module = runtime.probe(name)
        assert runtime.run(module, cid(module)).value == {"code": 0, "retry": False}


def test_hash_size_deadline():
    module = runtime.probe("empty-decision")
    assert runtime.run(module, bytes(33)).status == "module-cid"
    assert runtime.run(bytes(runtime.MODULE_BYTES + 1), bytes(33)).status == "module-limit"
    module = runtime.probe("loop")
    start = time.monotonic()
    result = runtime.run(module, cid(module), timeout=0.5, fuel=None)
    assert result.status == "module-limit" and result.retryable
    assert time.monotonic() - start < 2


def _partial_result(connection):
    # Announce a payload but never finish it: poll is readable, recv blocks.
    os.write(connection.fileno(), struct.pack("!i", 1000) + b"partial")
    time.sleep(30)


def test_deadline_covers_partial_ipc_result():
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_partial_result, args=(send,), daemon=True)
    process.start()
    send.close()
    start = time.monotonic()
    outcome = runtime._collect(process, receive, 0.25)
    assert outcome.status == "module-limit"
    assert time.monotonic() - start < 1
    assert not process.is_alive()


def test_host_validates_module_decision_in_order():
    from hum_reference.bodies import verifier as vf

    body = {
        vf.PROFILE: "invite",
        vf.ATTRIBUTES: [vf.attribute("invite", "bool", "gate")],
        vf.DEDUP: [{vf.DD_METHOD: "evidence"}],
    }
    assert (
        runtime.validate_decision({"attributes": [("invite", 1)], "dedup_keys": [b"key"]}, body)
        is None
    )
    assert (
        runtime.validate_decision({"attributes": [("undeclared", 1)], "dedup_keys": []}, body)
        == "host-invalid-attribute"
    )
    assert (
        runtime.validate_decision({"attributes": [("invite", 0)], "dedup_keys": []}, body)
        == "host-invalid-value"
    )
    assert (
        runtime.validate_decision({"attributes": [], "dedup_keys": []}, body)
        == "host-missing-attribute"
    )
    assert (
        runtime.validate_decision({"attributes": [("invite", 1)], "dedup_keys": []}, body)
        == "host-invalid-dedup"
    )


def test_probe_result_payload_layout_and_failure_controls():
    module = runtime.probe("rejection")
    assert runtime.run(module, cid(module)).value == {"code": 2, "retry": False}
    # A deliberately wrong NaN expectation must be observable as code 1.
    for name, original, wrong in (
        ("nan", "2143289344", "2143289345"),
        ("memory-grow", "i32.const -1 i32.ne", "i32.const -2 i32.ne"),
    ):
        text = (runtime.PROBES / f"{name}.wat").read_text().replace(original, wrong)
        import wasmtime

        module = wasmtime.wat2wasm(text)
        assert runtime.run(module, cid(module)).value == {"code": 1, "retry": False}


def test_aggregate_linear_memory_cannot_multiply_per_memory_cap():
    import wasmtime

    text = """(component
      (core module $memory (memory 600))
      (core instance $a (instantiate $memory))
      (core instance $b (instantiate $memory)))"""
    module = wasmtime.wat2wasm(text)
    assert runtime.run(module, cid(module)).status == "module-limit"
